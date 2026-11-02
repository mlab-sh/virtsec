//! `virtsec serve`: virtsec as an mlab-agent tool, on stdin/stdout.
//!
//! ```text
//! sources (watch threads: config poll, journal, exec/eBPF) ──▶ collector
//!   collector: filter on the config in force → v1 SecEvent → Stream (batches, backlog) ──▶ writer
//! inventory thread: at start, hourly, on a guest start and on `configure` ──▶ inventory_ready
//! agent ──frames──▶ protocol loop (this thread): init, calls (ops), shutdown
//!                     └── writer (one thread owns stdout: answers + events, whole frames)
//! ```
//!
//! Capture never waits on the agent: the agent reads tool events only while
//! it serves a call, so a batch the writer can't take now stays in the
//! backlog for `events_since`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use virtsec_api::{self as api, op, Config, Settings};

use crate::inventory::{self, Scan};
use crate::model::{self, Inventory};
use crate::os::OsRelease;
use crate::protocol::{self, ErrorBody, ErrorCode, HostMsg, ToolMsg, TOOL_PROTOCOL_VERSION};
use crate::rootfs::Rootfs;
use crate::stream::Stream;
use crate::watch::{self, Names};

/// Batches are cut at least this often.
const BATCH_INTERVAL: Duration = Duration::from_secs(2);
const HEARTBEAT: Duration = Duration::from_secs(60);
/// Guests are re-inventoried at least this often.
const INVENTORY_EVERY: Duration = Duration::from_secs(3600);
const CONFIG_POLL: Duration = Duration::from_secs(2);
/// Frames waiting for stdout; events past this wait in the backlog.
const WRITER_QUEUE: usize = 256;
const SAVED_CONFIG: &str = "config.cbor";

/// Run the tool protocol on stdin/stdout until the agent says stop.
pub fn serve() -> Result<()> {
    let (mut stdin, stdout) = (std::io::stdin().lock(), std::io::stdout());
    serve_on(&mut stdin, Box::new(stdout), Path::new("/etc/pve"))
}

struct State {
    settings: Settings,
    work_dir: PathBuf,
    pve: PathBuf,
    config: Config,
    stream: Stream,
    /// By vmid; `None` = the node.
    inventories: BTreeMap<Option<u32>, Inventory>,
    node: String,
    cluster_id: Option<String>,
    node_info: Option<api::NodeInfo>,
    started_at: i64,
    /// Capture sources started (they keep running, filtered, once started).
    started: BTreeSet<&'static str>,
    failed: BTreeMap<&'static str, String>,
}

type Shared = Arc<Mutex<State>>;

/// Frames to stdout, from any thread.
#[derive(Clone)]
struct Writer(SyncSender<Vec<u8>>);

impl Writer {
    fn spawn(mut out: Box<dyn Write + Send>) -> Self {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(WRITER_QUEUE);
        std::thread::spawn(move || {
            for frame in rx {
                if out.write_all(&frame).and_then(|()| out.flush()).is_err() {
                    break; // agent gone
                }
            }
        });
        Self(tx)
    }

    /// Answers wait for room: the agent is reading, it asked.
    fn answer(&self, msg: &ToolMsg) {
        if let Ok(frame) = protocol::encode(msg) {
            let _ = self.0.send(frame);
        }
    }

    /// Events never wait; `false` when not queued.
    fn event<T: serde::Serialize>(&self, name: &str, body: &T) -> bool {
        let Ok(body) = api::to_cbor(body) else {
            return false;
        };
        protocol::encode(&ToolMsg::Event {
            name: name.into(),
            body,
        })
        .is_ok_and(|frame| self.0.try_send(frame).is_ok())
    }
}

/// What the running process shares with its threads.
#[derive(Clone)]
struct Ctx {
    shared: Shared,
    writer: Writer,
    names: Names,
    events: Sender<watch::Event>,
    inventory: SyncSender<()>,
}

/// The protocol loop over any pipe pair (tests use in-memory ones).
pub fn serve_on(input: &mut dyn Read, output: Box<dyn Write + Send>, pve: &Path) -> Result<()> {
    let writer = Writer::spawn(output);
    let Some(HostMsg::Init {
        protocol,
        settings,
        work_dir,
    }) = protocol::read(input)?
    else {
        anyhow::bail!("expected init from the agent");
    };
    if protocol != TOOL_PROTOCOL_VERSION {
        writer.answer(&ToolMsg::InitFailed {
            message: format!(
                "agent speaks tool protocol {protocol}, virtsec {TOOL_PROTOCOL_VERSION}"
            ),
        });
        return Ok(());
    }
    let ctx = match init(settings, PathBuf::from(work_dir), pve, writer.clone()) {
        Ok(c) => c,
        Err(e) => {
            writer.answer(&ToolMsg::InitFailed {
                message: format!("{e:#}"),
            });
            return Ok(());
        }
    };
    writer.answer(&ToolMsg::Ready {
        name: api::TOOL.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        ops: op::ALL.iter().map(|s| (*s).to_string()).collect(),
    });

    while let Some(msg) = protocol::read::<HostMsg>(input)? {
        match msg {
            HostMsg::Call {
                id,
                op,
                args,
                blob_ok,
            } => {
                let msg = match call(&ctx, &op, &args, blob_ok) {
                    Ok((body, blob_path)) => ToolMsg::Result {
                        id,
                        body,
                        blob_path: blob_path.map(|p| p.to_string_lossy().into_owned()),
                    },
                    Err(error) => ToolMsg::Failure { id, error },
                };
                writer.answer(&msg);
            }
            HostMsg::Shutdown => break,
            HostMsg::Init { .. } => anyhow::bail!("init sent twice"),
        }
    }
    Ok(())
}

fn parse_settings(v: ciborium::Value) -> Result<Settings> {
    if v.is_null() {
        return Ok(Settings::default());
    }
    v.deserialized::<Settings>()
        .map_err(|e| anyhow::anyhow!("invalid [tools.virtsec.settings]: {e}"))
}

fn init(settings: ciborium::Value, work_dir: PathBuf, pve: &Path, writer: Writer) -> Result<Ctx> {
    let settings = parse_settings(settings)?;
    crate::procfs::check_root_access()?;
    if !pve.join("qemu-server").exists() && !pve.join("lxc").exists() {
        anyhow::bail!(
            "{} has no guest configs: is this a Proxmox VE node?",
            pve.display()
        );
    }
    std::fs::create_dir_all(&work_dir).context("work dir not writable")?;
    let saved = load_config(&work_dir).unwrap_or_default();
    let (config, cut) = clamp(&settings, &saved);
    for reason in &cut {
        tracing::info!("config clamped: {reason}");
    }

    let node = std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "pve".into());
    let shared: Shared = Arc::new(Mutex::new(State {
        stream: Stream::new(
            format!("b-{:016x}", rand_u64()),
            node.clone(),
            settings.backlog_events as usize,
        ),
        settings,
        work_dir,
        pve: pve.to_path_buf(),
        config,
        inventories: BTreeMap::new(),
        cluster_id: Some(cluster_id(pve).unwrap_or_else(|| node.clone())),
        node_info: Some(node_info()),
        node,
        started_at: chrono::Utc::now().timestamp_millis(),
        started: BTreeSet::new(),
        failed: BTreeMap::new(),
    }));

    let (events, rx) = mpsc::channel::<watch::Event>();
    let (inventory, inv_rx) = mpsc::sync_channel::<()>(1);
    let ctx = Ctx {
        shared,
        writer,
        names: Names::default(),
        events,
        inventory,
    };
    {
        // Always: guest names for the other sources and the guest-start trigger.
        let (pve, names, tx) = (pve.to_path_buf(), ctx.names.clone(), ctx.events.clone());
        std::thread::spawn(move || watch::poll_config(pve, names, CONFIG_POLL, tx));
    }
    let c = ctx.clone();
    std::thread::spawn(move || collector(rx, c));
    let c = ctx.clone();
    std::thread::spawn(move || inventories(inv_rx, c));
    let c = ctx.clone();
    std::thread::spawn(move || heartbeat(c));
    start_sources(&ctx);
    let _ = ctx.inventory.try_send(());
    Ok(ctx)
}

/// Start the capture sources the config turns on and that aren't running yet.
// ponytail: a source turned off later keeps running, its events filtered;
// it stops with the process. Stop it for real if its cost ever matters.
fn start_sources(ctx: &Ctx) {
    let Ok(mut s) = ctx.shared.lock() else { return };
    let on = s.config.sources;
    let mut start = |name: &'static str, f: fn(Names, Sender<watch::Event>) -> Result<()>| {
        if !s.started.insert(name) {
            return;
        }
        let (names, tx, shared) = (ctx.names.clone(), ctx.events.clone(), ctx.shared.clone());
        std::thread::spawn(move || {
            if let Err(e) = f(names, tx) {
                tracing::error!("{name} events stopped: {e:#}");
                if let Ok(mut s) = shared.lock() {
                    s.failed.insert(name, format!("{e:#}"));
                }
            }
        });
    };
    if on.journal {
        start("journal", watch::follow_journal);
    }
    if on.ebpf {
        #[cfg(all(feature = "ebpf", target_os = "linux"))]
        start("ebpf", crate::probe::follow);
        #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
        start("ebpf", watch::follow_exec);
    }
}

/// Events → filter → batches, cut at least every [`BATCH_INTERVAL`].
fn collector(rx: Receiver<watch::Event>, ctx: Ctx) {
    let mut next_cut = Instant::now() + BATCH_INTERVAL;
    loop {
        let wait = next_cut.saturating_duration_since(Instant::now());
        let batches = match rx.recv_timeout(wait) {
            Ok(ev) => {
                if ev.kind == "started" {
                    let _ = ctx.inventory.try_send(());
                }
                let Ok(mut s) = ctx.shared.lock() else { return };
                if !keeps(&s.settings, &s.config, &ev) {
                    continue;
                }
                s.stream.push(sec_event(&ev))
            }
            Err(RecvTimeoutError::Timeout) => {
                next_cut = Instant::now() + BATCH_INTERVAL;
                let Ok(mut s) = ctx.shared.lock() else { return };
                s.stream.flush().into_iter().collect()
            }
            Err(RecvTimeoutError::Disconnected) => return,
        };
        for b in batches {
            if !ctx.writer.event(api::event::BATCH, &b) {
                tracing::debug!(seq = b.seq, "writer busy; batch kept for events_since");
            }
        }
    }
}

/// The guests the config and the policy let mlab see; empty = all.
fn vmids(settings: &Settings, config: &Config) -> Vec<u32> {
    if config.vmids.is_empty() {
        settings.vmids.clone()
    } else {
        config.vmids.clone()
    }
}

/// Whether `ev` passes the config in force (sources, kinds, guests, severity).
fn keeps(settings: &Settings, config: &Config, ev: &watch::Event) -> bool {
    let on = config.sources;
    let source_on = match ev.source {
        "exec" | "ebpf" => on.ebpf,
        "pve" => on.journal,
        "config" => on.config,
        _ => false,
    };
    if !source_on || severity(ev.severity) < config.min_severity {
        return false;
    }
    if matches!(ev.source, "exec" | "ebpf") && !config.kinds.is_empty() {
        let base = match ev.kind.as_str() {
            "exec" | "vm_cgroup_exec" | "boot_execs" => "exec",
            "connect" | "vm_cgroup_connect" => "connect",
            _ => "file_write",
        };
        if !config.kinds.iter().any(|k| k == base) {
            return false;
        }
    }
    let wanted = vmids(settings, config);
    match &ev.guest {
        Some(g) => wanted.is_empty() || wanted.contains(&g.vmid),
        None => true,
    }
}

fn severity(s: watch::Severity) -> api::Severity {
    match s {
        watch::Severity::Info => api::Severity::Info,
        watch::Severity::Warning => api::Severity::Warning,
        watch::Severity::Critical => api::Severity::Critical,
    }
}

fn guest_kind(k: crate::guest::GuestKind) -> api::GuestKind {
    match k {
        crate::guest::GuestKind::Lxc => api::GuestKind::Lxc,
        crate::guest::GuestKind::Qemu => api::GuestKind::Qemu,
    }
}

fn sec_event(ev: &watch::Event) -> api::SecEvent {
    api::SecEvent {
        source: match ev.source {
            "ebpf" => api::Source::Ebpf,
            "pve" => api::Source::Pve,
            "config" => api::Source::Config,
            _ => api::Source::Exec,
        },
        timestamp: ev.time.timestamp_millis(),
        kind: ev.kind.clone(),
        severity: severity(ev.severity),
        guest: ev.guest.as_ref().map(|g| api::GuestRef {
            kind: guest_kind(g.kind),
            vmid: g.vmid,
            name: g.name.clone(),
        }),
        message: ev.message.clone(),
        metadata: ev.fields.clone(),
        payload: ev.fields.get("dest").map_or(
            serde_json::Value::Null,
            |d| serde_json::json!({ "dest": d }),
        ),
    }
}

/// Re-inventory on demand (coalesced) and at least every [`INVENTORY_EVERY`].
fn inventories(rx: Receiver<()>, ctx: Ctx) {
    loop {
        match rx.recv_timeout(INVENTORY_EVERY) {
            Ok(()) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let Some((pve, wanted, guest_exec, on)) = ctx.shared.lock().ok().map(|s| {
            (
                s.pve.clone(),
                vmids(&s.settings, &s.config),
                s.config.guest_exec,
                s.config.sources.inventory,
            )
        }) else {
            return;
        };
        if !on {
            continue;
        }
        let scanned = inventory::scan_node(&Scan {
            pve: &pve,
            vmids: &wanted,
            kind: None,
            guest_exec,
            host: true,
            match_kernel: false,
        });
        let invs = match scanned {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!("inventory failed: {e:#}");
                if let Ok(mut s) = ctx.shared.lock() {
                    s.failed.insert("inventory", format!("{e:#}"));
                }
                continue;
            }
        };
        let Ok(mut s) = ctx.shared.lock() else { return };
        // Only what changed: a rescan of an unchanged node says nothing.
        let readies: Vec<api::InventoryReady> = invs
            .iter()
            .map(ready)
            .filter(|r| s.inventories.get(&r.vmid).map(ready).as_ref() != Some(r))
            .collect();
        s.failed.remove("inventory");
        s.inventories = invs
            .into_iter()
            .map(|i| (i.guest.as_ref().map(|g| g.vmid), i))
            .collect();
        drop(s);
        for r in readies {
            ctx.writer.event(api::event::INVENTORY_READY, &r);
        }
    }
}

fn ready(inv: &Inventory) -> api::InventoryReady {
    api::InventoryReady {
        vmid: inv.guest.as_ref().map(|g| g.vmid),
        name: inv.name.clone(),
        packages: inv.packages.len() as u32,
        loaded: inv.count(model::Reachability::Loaded) as u32,
    }
}

fn heartbeat(ctx: Ctx) {
    std::thread::sleep(Duration::from_secs(10));
    loop {
        let Some(st) = ctx.shared.lock().ok().map(|s| status(&s)) else {
            return;
        };
        ctx.writer.event(api::event::STATUS, &st);
        std::thread::sleep(HEARTBEAT);
    }
}

fn status(s: &State) -> api::Status {
    let allow = s.settings.allow();
    let on = s.config.sources;
    let state = |name: &'static str, allowed: bool, wanted: bool| {
        let (state, error) = if !allowed {
            ("off", Some("not allowed by policy".to_string()))
        } else if !wanted {
            ("off", None)
        } else if let Some(e) = s.failed.get(name) {
            ("failed", Some(e.clone()))
        } else {
            ("running", None)
        };
        api::SourceState {
            name: name.into(),
            state: state.into(),
            error,
        }
    };
    api::Status {
        api_version: api::API_VERSION,
        virtsec_version: env!("CARGO_PKG_VERSION").into(),
        boot_id: s.stream.boot_id().to_string(),
        started_at: s.started_at,
        node: s.node.clone(),
        cluster_id: s.cluster_id.clone(),
        node_info: s.node_info.clone(),
        config: s.config.clone(),
        allow,
        allow_guest_exec: s.settings.allow_guest_exec,
        allowed_vmids: s.settings.vmids.clone(),
        sources: vec![
            state("ebpf", allow.ebpf, on.ebpf),
            state("journal", allow.journal, on.journal),
            state("config", allow.config, on.config),
            state("inventory", allow.inventory, on.inventory),
        ],
        counters: s.stream.counters(),
        guests: s.inventories.keys().filter(|k| k.is_some()).count() as u32,
    }
}

/// Intersect `wanted` with what `settings` allows; the reasons in words.
pub fn clamp(settings: &Settings, wanted: &Config) -> (Config, Vec<String>) {
    let mut c = wanted.clone();
    let mut cut = Vec::new();
    let a = settings.allow();
    let mut off = |on: &mut bool, allowed: bool, name: &str| {
        if *on && !allowed {
            *on = false;
            cut.push(format!("{name} not allowed by policy"));
        }
    };
    off(&mut c.sources.ebpf, a.ebpf, "ebpf");
    off(&mut c.sources.journal, a.journal, "journal");
    off(&mut c.sources.config, a.config, "config");
    off(&mut c.sources.inventory, a.inventory, "inventory");
    off(&mut c.guest_exec, settings.allow_guest_exec, "guest_exec");
    if !settings.vmids.is_empty() {
        let (kept, refused): (Vec<u32>, Vec<u32>) =
            c.vmids.iter().partition(|v| settings.vmids.contains(v));
        for v in refused {
            cut.push(format!("guest {v} not allowed by policy"));
        }
        c.vmids = kept;
    }
    c.kinds.retain(|k| {
        let ok = ["exec", "connect", "file_write"].contains(&k.as_str());
        if !ok {
            cut.push(format!("unknown kernel event kind {k}"));
        }
        ok
    });
    (c, cut)
}

fn load_config(work_dir: &Path) -> Option<Config> {
    api::from_cbor(&std::fs::read(work_dir.join(SAVED_CONFIG)).ok()?).ok()
}

fn save_config(work_dir: &Path, c: &Config) -> std::io::Result<()> {
    let tmp = work_dir.join(format!("{SAVED_CONFIG}.tmp"));
    std::fs::write(&tmp, api::to_cbor(c).map_err(std::io::Error::other)?)?;
    std::fs::rename(tmp, work_dir.join(SAVED_CONFIG))
}

/// `cluster_name` in `corosync.conf`; `None` on a standalone node.
fn cluster_id(pve: &Path) -> Option<String> {
    std::fs::read_to_string(pve.join("corosync.conf"))
        .ok()?
        .lines()
        .find_map(|l| l.trim().strip_prefix("cluster_name:"))
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
}

fn node_info() -> api::NodeInfo {
    let dpkg = std::fs::read_to_string("/var/lib/dpkg/status").unwrap_or_default();
    let pve_version = dpkg
        .split("\n\n")
        .find(|p| p.lines().any(|l| l == "Package: pve-manager"))
        .and_then(|p| p.lines().find_map(|l| l.strip_prefix("Version: ")))
        .unwrap_or("")
        .to_string();
    api::NodeInfo {
        pve_version,
        kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|k| k.trim().to_string())
            .unwrap_or_default(),
        os: OsRelease::read(&Rootfs::new("/"))
            .map(|o| o.pretty_name)
            .unwrap_or_default(),
    }
}

fn package(p: &model::Package) -> api::Package {
    api::Package {
        name: p.name.clone(),
        version: p.version.clone(),
        kind: match p.kind {
            model::PackageKind::Os => "os",
            model::PackageKind::Lang => "lang",
            model::PackageKind::Node => "node",
        }
        .into(),
        purl: p.purl.clone(),
        source: p.source.clone(),
        location: p.location.clone(),
        reachability: p.reachability.as_str().into(),
        coordinate: p.coordinate.as_ref().map(|c| match c {
            model::Coordinate::Eco {
                ecosystem,
                name,
                version,
            } => api::Coordinate {
                ecosystem: Some(ecosystem.clone()),
                name: Some(name.clone()),
                version: Some(version.clone()),
                purl: None,
                cpe: None,
            },
            model::Coordinate::Purl { purl } => api::Coordinate {
                ecosystem: None,
                name: None,
                version: None,
                purl: Some(purl.clone()),
                cpe: None,
            },
            model::Coordinate::Cpe { cpe } => api::Coordinate {
                ecosystem: None,
                name: None,
                version: None,
                purl: None,
                cpe: Some(cpe.clone()),
            },
        }),
    }
}

fn guest_inventory(inv: &Inventory) -> api::GuestInventory {
    api::GuestInventory {
        guest: inv.guest.as_ref().map(|g| api::GuestInfo {
            kind: guest_kind(g.kind),
            vmid: g.vmid,
            name: g.name.clone(),
            status: g.status.into(),
            risks: g.risks.clone(),
        }),
        name: inv.name.clone(),
        os: inv.os.as_ref().map(|o| api::Os {
            id: o.id.clone(),
            version_id: o.version_id.clone(),
            pretty_name: o.pretty_name.clone(),
        }),
        packages: inv.packages.iter().map(package).collect(),
        mapped_files: inv.mapped_files as u32,
        warnings: inv.warnings.clone(),
    }
}

fn args<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ErrorBody> {
    if bytes.is_empty() {
        // No-argument ops: mlab may send nothing or CBOR null.
        return api::from_cbor(&[0xf6])
            .map_err(|_| ErrorBody::new(ErrorCode::BadRequest, "arguments required"));
    }
    api::from_cbor(bytes)
        .map_err(|e| ErrorBody::new(ErrorCode::BadRequest, format!("invalid arguments: {e}")))
}

fn reply<T: serde::Serialize>(v: &T) -> Result<(Vec<u8>, Option<PathBuf>), ErrorBody> {
    api::to_cbor(v)
        .map(|b| (b, None))
        .map_err(|_| ErrorBody::new(ErrorCode::Internal, "answer could not be encoded"))
}

fn internal(e: impl std::fmt::Display) -> ErrorBody {
    ErrorBody::new(ErrorCode::Internal, e.to_string())
}

fn needs_upload(blob_ok: bool, what: &str) -> Result<(), ErrorBody> {
    if blob_ok {
        Ok(())
    } else {
        Err(ErrorBody::new(
            ErrorCode::BadRequest,
            format!("{what} needs an upload target"),
        ))
    }
}

fn call(
    ctx: &Ctx,
    op_name: &str,
    raw: &[u8],
    blob_ok: bool,
) -> Result<(Vec<u8>, Option<PathBuf>), ErrorBody> {
    let lock = || ctx.shared.lock().map_err(|_| internal("state poisoned"));
    match op_name {
        op::STATUS => reply(&status(&*lock()?)),
        op::EVENTS_SINCE => {
            let a: api::EventsSince = args(raw)?;
            reply(&lock()?.stream.since(&a.boot_id, a.after_seq))
        }
        op::CONFIGURE => {
            let wanted: Config = args(raw)?;
            let (clamped, cut) = {
                let mut s = lock()?;
                let (clamped, cut) = clamp(&s.settings, &wanted);
                save_config(&s.work_dir, &clamped).map_err(internal)?;
                s.config = clamped.clone();
                (clamped, cut)
            };
            start_sources(ctx);
            let _ = ctx.inventory.try_send(());
            ctx.writer.event(api::event::STATUS, &status(&*lock()?));
            reply(&api::Configured {
                config: clamped,
                clamped: cut,
            })
        }
        op::INVENTORY => {
            let a: api::InventoryRequest = args(raw)?;
            needs_upload(blob_ok, "inventory")?;
            let s = lock()?;
            let guests: Vec<api::GuestInventory> = s
                .inventories
                .iter()
                .filter(|(k, _)| a.vmid.is_none() || **k == a.vmid)
                .map(|(_, inv)| guest_inventory(inv))
                .collect();
            if a.vmid.is_some() && guests.is_empty() {
                return Err(ErrorBody::new(
                    ErrorCode::NotFound,
                    "no such guest inventoried on this node",
                ));
            }
            let info = api::InventoryInfo {
                guests: guests.len() as u32,
                packages: guests.iter().map(|g| g.packages.len() as u32).sum(),
            };
            let doc = api::Inventory {
                format: api::inventory::INVENTORY_FORMAT.into(),
                api_version: api::API_VERSION,
                generated_at: chrono::Utc::now().timestamp_millis(),
                node: s.node.clone(),
                cluster_id: s.cluster_id.clone(),
                node_info: s.node_info.clone(),
                guests,
            };
            let path = s.work_dir.join("inventory.cbor");
            std::fs::write(&path, doc.encode().map_err(internal)?).map_err(internal)?;
            let (body, _) = reply(&info)?;
            Ok((body, Some(path)))
        }
        op::SBOM => {
            let a: api::SbomRequest = args(raw)?;
            needs_upload(blob_ok, "sbom")?;
            let s = lock()?;
            let inv = s.inventories.get(&a.vmid).ok_or_else(|| {
                ErrorBody::new(
                    ErrorCode::NotFound,
                    "no such guest inventoried on this node",
                )
            })?;
            let bom = crate::sbom::cyclonedx(inv);
            let path = s.work_dir.join("sbom.cdx.json");
            std::fs::write(&path, serde_json::to_vec(&bom).map_err(internal)?).map_err(internal)?;
            let (body, _) = reply(&api::SbomInfo {
                vmid: a.vmid,
                components: inv.packages.len() as u32,
            })?;
            Ok((body, Some(path)))
        }
        _ => Err(ErrorBody::new(
            ErrorCode::UnknownOp,
            "virtsec has no such op",
        )),
    }
}

/// A random id per process, without a dependency: the kernel's uuid source.
fn rand_u64() -> u64 {
    std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .ok()
        .and_then(|u| u64::from_str_radix(&u.replace('-', "")[..16], 16).ok())
        .unwrap_or_else(|| chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::GuestKind;
    use crate::watch::{Event, GuestRef, Severity};

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn frames(sink: &Sink) -> Vec<ToolMsg> {
        std::thread::sleep(Duration::from_millis(100));
        let bytes = sink.0.lock().unwrap().clone();
        let mut r = bytes.as_slice();
        std::iter::from_fn(|| protocol::read::<ToolMsg>(&mut r).ok().flatten()).collect()
    }

    fn init_frame(protocol: u16, settings: ciborium::Value) -> Vec<u8> {
        protocol::encode(&HostMsg::Init {
            protocol,
            settings,
            work_dir: std::env::temp_dir().to_string_lossy().into_owned(),
        })
        .unwrap()
    }

    #[test]
    fn refuses_another_protocol_and_bad_settings() {
        let sink = Sink::default();
        let input = init_frame(2, ciborium::Value::Null);
        serve_on(
            &mut input.as_slice(),
            Box::new(sink.clone()),
            Path::new("/nonexistent"),
        )
        .unwrap();
        assert!(
            matches!(&frames(&sink)[..], [ToolMsg::InitFailed { message }] if message.contains("protocol 2"))
        );

        let sink = Sink::default();
        let bad = ciborium::Value::Map(vec![("surprise".into(), true.into())]);
        let input = init_frame(1, bad);
        serve_on(
            &mut input.as_slice(),
            Box::new(sink.clone()),
            Path::new("/nonexistent"),
        )
        .unwrap();
        assert!(
            matches!(&frames(&sink)[..], [ToolMsg::InitFailed { message }] if message.contains("invalid [tools.virtsec.settings]"))
        );
    }

    #[test]
    fn clamps_to_the_policy() {
        let settings = Settings {
            allow_journal: false,
            vmids: vec![4001, 4002],
            ..Settings::default()
        };
        let wanted = Config {
            guest_exec: true,
            vmids: vec![4001, 9999],
            kinds: vec!["exec".into(), "dns".into()],
            ..Config::default()
        };
        let (c, cut) = clamp(&settings, &wanted);
        assert!(!c.sources.journal && c.sources.ebpf);
        assert!(
            !c.guest_exec,
            "guest exec is off unless the policy allows it"
        );
        assert_eq!(c.vmids, [4001]);
        assert_eq!(c.kinds, ["exec"]);
        assert_eq!(
            cut,
            [
                "journal not allowed by policy",
                "guest_exec not allowed by policy",
                "guest 9999 not allowed by policy",
                "unknown kernel event kind dns",
            ]
        );
        let open = Settings {
            allow_guest_exec: true,
            ..Settings::default()
        };
        assert!(clamp(&open, &wanted).0.guest_exec);
    }

    #[test]
    fn filters_on_sources_kinds_guests_and_severity() {
        let ev = |source, kind: &str, vmid: Option<u32>, sev| {
            let mut e = Event::new(sev, source, kind, "m".into());
            e.guest = vmid.map(|vmid| GuestRef {
                kind: GuestKind::Lxc,
                vmid,
                name: "g".into(),
            });
            e
        };
        let settings = Settings {
            vmids: vec![4001],
            ..Settings::default()
        };
        let mut config = Config {
            kinds: vec!["connect".into()],
            min_severity: api::Severity::Warning,
            ..Config::default()
        };
        assert!(keeps(
            &settings,
            &config,
            &ev("ebpf", "vm_cgroup_connect", Some(4001), Severity::Warning)
        ));
        assert!(
            !keeps(
                &settings,
                &config,
                &ev("exec", "exec", Some(4001), Severity::Warning)
            ),
            "kind"
        );
        assert!(
            !keeps(
                &settings,
                &config,
                &ev("ebpf", "connect", Some(4002), Severity::Warning)
            ),
            "guest"
        );
        assert!(
            !keeps(
                &settings,
                &config,
                &ev("ebpf", "connect", Some(4001), Severity::Info)
            ),
            "severity"
        );
        assert!(
            keeps(
                &settings,
                &config,
                &ev("pve", "auth_failure", None, Severity::Warning)
            ),
            "node-level"
        );
        config.sources.journal = false;
        assert!(
            !keeps(
                &settings,
                &config,
                &ev("pve", "auth_failure", None, Severity::Warning)
            ),
            "source off"
        );
    }

    #[test]
    fn connect_events_carry_dest_in_the_payload() {
        let mut e = Event::new(
            Severity::Info,
            "ebpf",
            "connect",
            "connect 1.1.1.1:80 (curl)".into(),
        );
        e.fields.insert("dest".into(), "1.1.1.1:80".into());
        let s = sec_event(&e);
        assert_eq!(s.source, api::Source::Ebpf);
        assert_eq!(s.payload["dest"], "1.1.1.1:80");
        assert!(
            sec_event(&Event::new(Severity::Info, "pve", "login", "x".into()))
                .payload
                .is_null()
        );
    }

    #[test]
    fn corosync_cluster_name() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(cluster_id(dir.path()), None);
        std::fs::write(
            dir.path().join("corosync.conf"),
            "totem {\n  cluster_name: lab-eu\n  version: 2\n}\n",
        )
        .unwrap();
        assert_eq!(cluster_id(dir.path()).as_deref(), Some("lab-eu"));
    }
}
