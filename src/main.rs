//! virtsec: runtime security CLI for Proxmox VE nodes. Runs as root on the node.

mod audit;
mod cache;
mod guest;
mod inventory;
mod lang;
mod mlab;
mod model;
mod os;
mod pkgdb;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod probe;
mod procfs;
mod protocol;
mod purl;
mod qga;
mod reach;
mod render;
mod rootfs;
mod sbom;
mod serve;
mod stream;
mod vuln;
mod watch;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

use cache::Cache;
use guest::GuestKind;
use mlab::MlabClient;
use model::Inventory;
use render::Filter;
use vuln::VulnSeverity;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Packages of every guest and of the node, tagged loaded / dormant.
    Inventory {
        #[command(flatten)]
        scope: Scope,
        /// Write one CycloneDX JSON SBOM per guest into this directory.
        #[arg(long, value_name = "DIR")]
        sbom: Option<PathBuf>,
    },
    /// Vulnerabilities of every guest and of the node (vuln.mlab.sh).
    Vulns(VulnsArgs),
    /// Security posture: node config (firewall, 2FA, SSH, repos), guest risks, restart / reboot needed.
    Audit {
        #[command(flatten)]
        scope: Scope,
        /// Exit with status 3 when a check at or above this severity fails.
        #[arg(long, value_enum, value_name = "SEVERITY")]
        fail_on: Option<MinSeverity>,
    },
    /// Run as an mlab-agent tool on stdin/stdout (the agent starts it).
    Serve,
    /// Live stream: guest execs (and with eBPF connects, file writes), PVE logins and tasks, guest config changes.
    Watch(WatchArgs),
}

#[derive(Args)]
struct WatchArgs {
    /// No kernel events (eBPF exec / connect / file writes, or proc connector exec).
    #[arg(long)]
    no_exec: bool,
    /// No pvedaemon / pveproxy / sshd journal events.
    #[arg(long)]
    no_journal: bool,
    /// Hide events below this severity.
    #[arg(long, value_enum, default_value_t = MinSeverity::Info)]
    min_severity: MinSeverity,
    /// Seconds between two reads of the guest configs and cgroups.
    #[arg(long, value_name = "SECS", default_value_t = 2)]
    poll: u64,
    #[arg(long, default_value = "/etc/pve", hide = true)]
    pve: PathBuf,
    #[arg(short = 'o', long, value_enum, default_value_t = Output::Pretty)]
    output: Output,
    /// Hide events matching a rule of this file (one per line: `key=value ...`, `message~=text`).
    #[arg(long, value_name = "FILE")]
    ignore: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, ValueEnum)]
enum MinSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Pretty,
    Json,
}

#[derive(Args)]
struct Scope {
    /// Only these guests (repeatable).
    #[arg(long = "vmid", value_name = "ID")]
    vmids: Vec<u32>,
    /// Only containers or only VMs.
    #[arg(long, value_enum)]
    kind: Option<Kind>,
    /// Skip the node's own packages.
    #[arg(long)]
    no_host: bool,
    /// Inspect VMs from the inside: read-only commands (`cat /proc/*/maps`,
    /// `tar` of the package databases) run through qemu-guest-agent.
    #[arg(long)]
    guest_exec: bool,
    /// Also match the node kernel by CPE against NVD (ignores PVE backports: noisy).
    #[arg(long)]
    match_kernel: bool,
    /// Proxmox config directory.
    #[arg(long, default_value = "/etc/pve", hide = true)]
    pve: PathBuf,
    #[arg(short = 'o', long, value_enum, default_value_t = Output::Pretty)]
    output: Output,
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Lxc,
    Vm,
}

#[derive(Args)]
struct VulnsArgs {
    #[command(flatten)]
    scope: Scope,
    /// vuln.mlab.sh base URL (or an on-prem mlab). API key: $MLAB_API_KEY.
    #[arg(long, value_name = "URL", default_value = MlabClient::DEFAULT_URL)]
    mlab_url: String,
    /// Ignore cached results.
    #[arg(long)]
    no_cache: bool,
    /// Hide findings below this severity.
    #[arg(long, value_enum, value_name = "SEVERITY")]
    min_severity: Option<VulnSeverity>,
    /// Only vulns in code that is loaded in memory.
    #[arg(long)]
    only_loaded: bool,
    /// Only vulns in CISA / EU KEV (known exploited).
    #[arg(long)]
    kev_only: bool,
    /// Only vulns the previous run did not report (each run saves the baseline).
    #[arg(long)]
    new: bool,
    /// Exit with status 3 when a shown vuln is at or above this severity.
    #[arg(long, value_enum, value_name = "SEVERITY")]
    fail_on: Option<VulnSeverity>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Command::Inventory { scope, sbom } => {
            let invs =
                tokio::task::spawn_blocking(move || collect(&scope).map(|i| (i, scope))).await??;
            let (invs, scope) = invs;
            if let Some(dir) = &sbom {
                for inv in &invs {
                    sbom::write(dir, inv)?;
                }
            }
            print(&match scope.output {
                Output::Pretty => render::inventory_pretty(&invs, color()),
                Output::Json => {
                    serde_json::to_string_pretty(&render::inventory_json(&invs))? + "\n"
                }
            })
        }
        Command::Audit { scope, fail_on } => {
            let (invs, scope) =
                tokio::task::spawn_blocking(move || collect(&scope).map(|i| (i, scope))).await??;
            let checks = audit::audit(
                &audit::Paths {
                    pve: &scope.pve,
                    root: std::path::Path::new("/"),
                },
                &invs,
            );
            print(&match scope.output {
                Output::Pretty => audit::pretty(&checks, color()),
                Output::Json => {
                    serde_json::to_string_pretty(&serde_json::json!({ "checks": checks }))? + "\n"
                }
            })?;
            if let Some(min) = fail_on.map(severity) {
                if checks.iter().any(|c| c.severity >= min) {
                    std::process::exit(3);
                }
            }
            Ok(())
        }
        Command::Serve => tokio::task::spawn_blocking(serve::serve).await?,
        Command::Watch(args) => tokio::task::spawn_blocking(move || run_watch(args)).await?,
        Command::Vulns(args) => {
            let client = MlabClient::new(&args.mlab_url, std::env::var("MLAB_API_KEY").ok())?;
            let cache = Cache::new(Cache::default_dir(), Cache::DEFAULT_TTL, !args.no_cache);
            let (invs, args) =
                tokio::task::spawn_blocking(move || collect(&args.scope).map(|i| (i, args)))
                    .await??;
            let mut vulns = vuln::match_images(&client, &cache, &invs).await;
            let baseline = cache.last_seen();
            let seen = vuln::seen(&invs, &vulns, baseline.as_ref());
            if args.new {
                if baseline.is_none() {
                    eprintln!("virtsec: no previous run on this node: every vuln is new");
                }
                vuln::keep_new(&invs, &mut vulns, baseline.as_ref());
            }
            // Only a complete run replaces the baseline (by guest: a failed
            // one keeps its previous findings).
            cache.save_seen(&seen);
            let results: Vec<_> = invs.iter().zip(vulns.iter()).collect();
            let filter = Filter {
                min_severity: args.min_severity,
                only_loaded: args.only_loaded,
                kev_only: args.kev_only,
            };
            print(&match args.scope.output {
                Output::Pretty => render::vulns_pretty(&results, &filter, color()),
                Output::Json => {
                    serde_json::to_string_pretty(&render::vulns_json(&results, &filter))? + "\n"
                }
            })?;
            if let Some(min) = args.fail_on {
                let hit = results
                    .iter()
                    .flat_map(|(_, v)| &v.findings)
                    .any(|f| filter.keeps(f) && f.severity >= min);
                if hit {
                    std::process::exit(3);
                }
            }
            Ok(())
        }
    }
}

fn collect(scope: &Scope) -> Result<Vec<Inventory>> {
    let kind = scope.kind.map(|k| match k {
        Kind::Lxc => GuestKind::Lxc,
        Kind::Vm => GuestKind::Qemu,
    });
    inventory::scan_node(&inventory::Scan {
        pve: &scope.pve,
        vmids: &scope.vmids,
        kind,
        guest_exec: scope.guest_exec,
        host: !scope.no_host && scope.vmids.is_empty() && kind.is_none(),
        match_kernel: scope.match_kernel,
    })
}

fn run_watch(args: WatchArgs) -> Result<()> {
    procfs::check_root_access()?;
    let rules = match &args.ignore {
        Some(f) => watch::Rules::parse(&std::fs::read_to_string(f)?)
            .map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?,
        None => watch::Rules::default(),
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let names = watch::Names::default();
    {
        let (pve, names, tx) = (args.pve.clone(), names.clone(), tx.clone());
        let every = std::time::Duration::from_secs(args.poll.max(1));
        std::thread::spawn(move || watch::poll_config(pve, names, every, tx));
    }
    // A source that can't start (no journalctl, not Linux) is reported, the others go on.
    let spawn =
        |name: &'static str,
         f: fn(watch::Names, std::sync::mpsc::Sender<watch::Event>) -> Result<()>| {
            let (names, tx) = (names.clone(), tx.clone());
            std::thread::spawn(move || {
                if let Err(e) = f(names, tx) {
                    tracing::error!("{name} events stopped: {e:#}");
                }
            });
        };
    if !args.no_exec {
        #[cfg(all(feature = "ebpf", target_os = "linux"))]
        spawn("ebpf", probe::follow);
        #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
        spawn("exec", watch::follow_exec);
    }
    if !args.no_journal {
        spawn("journal", watch::follow_journal);
    }
    drop(tx);
    let min = severity(args.min_severity);
    let color = color();
    for ev in rx {
        if ev.severity < min || rules.ignores(&ev) {
            continue;
        }
        let line = match args.output {
            Output::Pretty => ev.pretty(color),
            Output::Json => serde_json::to_string(&ev)?,
        };
        print(&(line + "\n"))?;
    }
    Ok(())
}

fn severity(s: MinSeverity) -> watch::Severity {
    match s {
        MinSeverity::Info => watch::Severity::Info,
        MinSeverity::Warning => watch::Severity::Warning,
        MinSeverity::Critical => watch::Severity::Critical,
    }
}

fn color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn print(s: &str) -> Result<()> {
    match std::io::stdout().lock().write_all(s.as_bytes()) {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(e.into()),
        _ => Ok(()),
    }
}
