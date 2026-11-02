//! `virtsec audit`: the security posture of the node and its guests, read from
//! their configuration. No CVE here (that is `vulns`): what an admin set, or
//! forgot to set.
//!
//! - **node**: PVE firewall, second factors, API tokens, SSH, the web UI's
//!   listen policy, APT repositories and how fresh their lists are, corosync.
//! - **guests**: isolation risks from their config, guest firewall coverage.
//! - **both**: restart and reboot needed (from the inventory).
//!
//! Secrets are never read into a check: `tfa.cfg` is only asked which users
//! have a factor, `user.cfg` gives token flags, not `priv/token.cfg`.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, SystemTime};

use owo_colors::OwoColorize;
use serde::Serialize;

use crate::guest::{Guest, GuestKind};
use crate::model::Inventory;
use crate::watch::{GuestRef, Severity};

/// One finding of the audit.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Stable id (`firewall.datacenter`, `ssh.root_password`, `guest.risk`, ...).
    pub id: &'static str,
    pub severity: Severity,
    /// The guest it is about; `None` for the node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest: Option<GuestRef>,
    pub message: String,
    /// What to change, in words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Check {
    fn node(id: &'static str, severity: Severity, message: String, fix: Option<&str>) -> Self {
        Self {
            id,
            severity,
            guest: None,
            message,
            fix: fix.map(str::to_string),
        }
    }

    fn guest(g: &Guest, id: &'static str, severity: Severity, message: String) -> Self {
        Self {
            id,
            severity,
            guest: Some(GuestRef {
                kind: g.kind,
                vmid: g.vmid,
                name: g.name.clone(),
            }),
            message,
            fix: None,
        }
    }
}

/// Lists older than this mean the node stopped fetching updates.
const APT_STALE: Duration = Duration::from_secs(7 * 24 * 3600);

/// Where the node's files are: `/etc/pve` and `/` on a node, dirs in tests.
pub struct Paths<'a> {
    pub pve: &'a Path,
    pub root: &'a Path,
}

/// Every check, node first. `invs`: the inventories of the same run (guests'
/// risks, restart and reboot notices).
pub fn audit(p: &Paths, invs: &[Inventory]) -> Vec<Check> {
    let node = std::fs::read_to_string(p.root.join("etc/hostname")).unwrap_or_default();
    let mut out = Vec::new();
    let guests: Vec<&Guest> = invs.iter().filter_map(|i| i.guest.as_ref()).collect();
    out.extend(firewall(p.pve, node.trim(), &guests));
    out.extend(users(p.pve));
    out.extend(ssh(p.root));
    out.extend(web_ui(p.root));
    out.extend(repositories(p.root, SystemTime::now()));
    out.extend(corosync(p.pve));
    for inv in invs {
        out.extend(notices(inv));
    }
    for g in &guests {
        out.extend(guest_risks(g));
    }
    out.sort_by_key(|c| {
        (
            c.guest.as_ref().map(|g| g.vmid),
            std::cmp::Reverse(c.severity),
        )
    });
    out
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

// ---------------------------------------------------------------- firewall

/// `enable:` in the `[OPTIONS]` section of a `.fw` file.
fn fw_enabled(content: &str) -> Option<bool> {
    let mut in_options = false;
    for line in content.lines().map(str::trim) {
        if line.starts_with('[') {
            in_options = line.eq_ignore_ascii_case("[options]");
        } else if in_options {
            if let Some(v) = line.strip_prefix("enable:") {
                return Some(v.trim() == "1");
            }
        }
    }
    None
}

fn firewall(pve: &Path, node: &str, guests: &[&Guest]) -> Vec<Check> {
    let mut out = Vec::new();
    let dc = read(&pve.join("firewall/cluster.fw"))
        .and_then(|c| fw_enabled(&c))
        .unwrap_or(false);
    if !dc {
        out.push(Check::node(
            "firewall.datacenter",
            Severity::Warning,
            "datacenter firewall is off: neither the node nor any guest is filtered by PVE".into(),
            Some("Datacenter → Firewall → Options → Firewall: Yes (allow 8006 and 22 from the admin network first)"),
        ));
        return out;
    }
    if read(&pve.join(format!("nodes/{node}/host.fw"))).and_then(|c| fw_enabled(&c)) == Some(false)
    {
        out.push(Check::node(
            "firewall.node",
            Severity::Warning,
            format!("firewall disabled on node {node}"),
            Some("Node → Firewall → Options → Firewall: Yes"),
        ));
    }
    for g in guests.iter().filter(|g| g.status != "template") {
        let nics: Vec<&str> = g
            .config
            .iter()
            .filter(|(k, _)| {
                k.strip_prefix("net")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            })
            .map(|(k, _)| k.as_str())
            .collect();
        let unfiltered: Vec<&str> = nics
            .iter()
            .copied()
            .filter(|k| {
                !g.get(k)
                    .is_some_and(|v| v.split(',').any(|o| o == "firewall=1"))
            })
            .collect();
        let enabled = read(&pve.join(format!("firewall/{}.fw", g.vmid)))
            .and_then(|c| fw_enabled(&c))
            .unwrap_or(false);
        if nics.is_empty() {
            continue;
        }
        let msg = if !enabled {
            "guest firewall off: no rule applies to its traffic".to_string()
        } else if !unfiltered.is_empty() {
            format!(
                "{} without firewall=1: its traffic bypasses the guest's rules",
                unfiltered.join(", ")
            )
        } else {
            continue;
        };
        out.push(Check::guest(g, "firewall.guest", Severity::Warning, msg));
    }
    out
}

// ---------------------------------------------------------------- users

/// `user:<id>:<enable>:<expire>:<first>:<last>:<email>:<comment>:<keys>:`
/// and `token:<user>!<name>:<expire>:<privsep>:<comment>:` lines.
struct UserCfg {
    /// Enabled, unexpired users, with their legacy `keys` (`x!oath`, `x!yubico`).
    users: Vec<(String, String)>,
    /// Tokens sharing their user's privileges (`privsep` 0).
    shared_tokens: Vec<String>,
}

fn parse_user_cfg(content: &str, now: i64) -> UserCfg {
    let mut cfg = UserCfg {
        users: Vec::new(),
        shared_tokens: Vec::new(),
    };
    for line in content.lines() {
        let f: Vec<&str> = line.split(':').collect();
        let live = |expire: Option<&&str>| {
            expire
                .and_then(|e| e.parse::<i64>().ok())
                .is_none_or(|e| e == 0 || e > now)
        };
        match f.as_slice() {
            ["user", id, enable, rest @ ..] if *enable == "1" && live(rest.first()) => cfg
                .users
                .push((id.to_string(), rest.get(5).unwrap_or(&"").to_string())),
            ["token", id, expire, privsep, ..] if *privsep == "0" && live(Some(expire)) => {
                cfg.shared_tokens.push(id.to_string())
            }
            _ => {}
        }
    }
    cfg
}

/// Users with a TOTP, WebAuthn, U2F or Yubico factor in `tfa.cfg` (JSON).
fn tfa_users(content: &str) -> BTreeSet<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(content) else {
        return BTreeSet::new();
    };
    let Some(users) = v.get("users").and_then(|u| u.as_object()) else {
        return BTreeSet::new();
    };
    users
        .iter()
        .filter(|(_, f)| {
            ["totp", "webauthn", "u2f", "yubico"].iter().any(|k| {
                f.get(k)
                    .and_then(|a| a.as_array())
                    .is_some_and(|a| !a.is_empty())
            })
        })
        .map(|(u, _)| u.clone())
        .collect()
}

/// Realms that enforce a second factor for everyone (`tfa type=...` in `domains.cfg`).
fn tfa_realms(content: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut realm = None;
    for line in content.lines() {
        if !line.starts_with([' ', '\t']) {
            realm = line.split_once(':').map(|(_, r)| r.trim().to_string());
        } else if line.trim().starts_with("tfa ") {
            out.extend(realm.clone());
        }
    }
    out
}

fn users(pve: &Path) -> Vec<Check> {
    let now = chrono::Utc::now().timestamp();
    let Some(cfg) = read(&pve.join("user.cfg")).map(|c| parse_user_cfg(&c, now)) else {
        return Vec::new();
    };
    let with_factor = read(&pve.join("priv/tfa.cfg"))
        .map(|c| tfa_users(&c))
        .unwrap_or_default();
    let realms = read(&pve.join("domains.cfg"))
        .map(|c| tfa_realms(&c))
        .unwrap_or_default();
    let mut out = Vec::new();
    let without: Vec<&str> = cfg
        .users
        .iter()
        .filter(|(id, keys)| {
            let realm = id.rsplit_once('@').map_or("", |(_, r)| r);
            !with_factor.contains(id) && !realms.contains(realm) && !keys.starts_with("x!")
        })
        .map(|(id, _)| id.as_str())
        .collect();
    if !without.is_empty() {
        let root = without.contains(&"root@pam");
        out.push(Check::node(
            "users.no_second_factor",
            if root {
                Severity::Critical
            } else {
                Severity::Warning
            },
            format!("no second factor: {}", without.join(", ")),
            Some("Datacenter → Permissions → Two Factor: add TOTP or WebAuthn (root@pam first)"),
        ));
    }
    for t in &cfg.shared_tokens {
        out.push(Check::node(
            "users.token_privsep",
            Severity::Warning,
            format!("API token {t} has every privilege of its user (privilege separation off)"),
            Some("recreate the token with Privilege Separation, then grant it only what it needs"),
        ));
    }
    out
}

// ---------------------------------------------------------------- ssh, web UI

/// `sshd -T`'s effective config, else the main file (lower-cased keys).
fn sshd_config(root: &Path) -> Option<HashMap<String, String>> {
    let text = if root == Path::new("/") {
        std::process::Command::new("sshd")
            .arg("-T")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        None
    }
    .or_else(|| read(&root.join("etc/ssh/sshd_config")))?;
    let mut m = HashMap::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') || line.to_ascii_lowercase().starts_with("match ") {
            continue;
        }
        if let Some((k, v)) = line.split_once(char::is_whitespace) {
            // First one wins, as for sshd.
            m.entry(k.to_ascii_lowercase())
                .or_insert_with(|| v.trim().to_ascii_lowercase());
        }
    }
    Some(m)
}

fn ssh(root: &Path) -> Vec<Check> {
    let Some(c) = sshd_config(root) else {
        return Vec::new();
    };
    let password = c.get("passwordauthentication").is_none_or(|v| v == "yes");
    let root_login = c
        .get("permitrootlogin")
        .map_or("prohibit-password", String::as_str);
    if password && root_login == "yes" {
        vec![Check::node(
            "ssh.root_password",
            Severity::Warning,
            "SSH accepts root logins with a password".into(),
            Some("PermitRootLogin prohibit-password in sshd_config (a PVE cluster only needs root's key)"),
        )]
    } else if password {
        vec![Check::node(
            "ssh.password",
            Severity::Info,
            "SSH accepts password logins".into(),
            Some("PasswordAuthentication no, once every admin has a key"),
        )]
    } else {
        Vec::new()
    }
}

fn web_ui(root: &Path) -> Vec<Check> {
    let conf = read(&root.join("etc/default/pveproxy")).unwrap_or_default();
    let set = |k: &str| {
        conf.lines().any(|l| {
            l.trim_start()
                .strip_prefix(k)
                .is_some_and(|r| r.trim_start().starts_with('='))
        })
    };
    if set("ALLOW_FROM") || set("LISTEN_IP") {
        return Vec::new();
    }
    vec![Check::node(
        "webui.open",
        Severity::Info,
        "web UI and API (8006) accept connections from every address".into(),
        Some("ALLOW_FROM=\"<admin network>\" and DENY_FROM=\"all\" in /etc/default/pveproxy, or a firewall rule"),
    )]
}

// ---------------------------------------------------------------- repositories

#[derive(Debug, PartialEq)]
struct Repo {
    uri: String,
    components: Vec<String>,
}

/// Enabled repositories of one-line (`.list`) and deb822 (`.sources`) files.
fn parse_sources(content: &str, deb822: bool) -> Vec<Repo> {
    let mut out = Vec::new();
    if !deb822 {
        for line in content.lines().map(str::trim) {
            let mut w = line.split_whitespace();
            if w.next() != Some("deb") {
                continue;
            }
            let mut rest: Vec<&str> = w.collect();
            if rest.first().is_some_and(|o| o.starts_with('[')) {
                let end = rest.iter().position(|o| o.ends_with(']')).unwrap_or(0);
                rest.drain(..=end);
            }
            if let Some((uri, comps)) = rest.split_first() {
                out.push(Repo {
                    uri: uri.to_string(),
                    components: comps.iter().skip(1).map(|c| c.to_string()).collect(),
                });
            }
        }
        return out;
    }
    for stanza in content.split("\n\n") {
        let field = |k: &str| {
            stanza.lines().find_map(|l| {
                let (key, v) = l.split_once(':')?;
                key.trim()
                    .eq_ignore_ascii_case(k)
                    .then(|| v.trim().to_string())
            })
        };
        if field("Enabled").is_some_and(|e| e.eq_ignore_ascii_case("no"))
            || !field("Types").is_some_and(|t| t.split_whitespace().any(|t| t == "deb"))
        {
            continue;
        }
        let comps: Vec<String> = field("Components")
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        for uri in field("URIs").unwrap_or_default().split_whitespace() {
            out.push(Repo {
                uri: uri.to_string(),
                components: comps.clone(),
            });
        }
    }
    out
}

fn repositories(root: &Path, now: SystemTime) -> Vec<Check> {
    let mut repos = Vec::new();
    if let Some(c) = read(&root.join("etc/apt/sources.list")) {
        repos.extend(parse_sources(&c, false));
    }
    if let Ok(dir) = std::fs::read_dir(root.join("etc/apt/sources.list.d")) {
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let deb822 = name.ends_with(".sources");
            if deb822 || name.ends_with(".list") {
                repos.extend(
                    read(&e.path())
                        .map(|c| parse_sources(&c, deb822))
                        .unwrap_or_default(),
                );
            }
        }
    }
    let lists: Vec<(String, SystemTime)> = std::fs::read_dir(root.join("var/lib/apt/lists"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let t = e.metadata().ok()?.modified().ok()?;
            Some((name, t))
        })
        .collect();

    let mut out = Vec::new();
    let has = |c: &str| repos.iter().any(|r| r.components.iter().any(|x| x == c));
    if has("pvetest") || has("pve-test") {
        out.push(Check::node(
            "apt.test_repo",
            Severity::Warning,
            "the PVE test repository is enabled: unreleased packages".into(),
            Some("disable pve-test in Node → Updates → Repositories"),
        ));
    }
    if has("pve-no-subscription") {
        out.push(Check::node(
            "apt.no_subscription",
            Severity::Info,
            "the pve-no-subscription repository is enabled: less tested than enterprise".into(),
            None,
        ));
    }
    // An enterprise repo without a subscription: `apt update` fails on it (401)
    // and never writes its index, so PVE (or Ceph) updates silently stop.
    let enterprise: BTreeSet<&str> = repos
        .iter()
        .filter(|r| r.uri.contains("://enterprise.proxmox.com/"))
        .map(|r| r.uri.as_str())
        .collect();
    for uri in enterprise {
        let prefix = uri
            .split_once("://")
            .map_or(uri, |(_, r)| r)
            .trim_end_matches('/')
            .replace('/', "_");
        if !lists.iter().any(|(n, _)| n.starts_with(&prefix)) {
            out.push(Check::node(
                "apt.enterprise_unreachable",
                Severity::Warning,
                format!(
                    "{uri} is enabled but never fetched (no subscription?): no updates from it"
                ),
                Some("add a subscription key, or replace it with the no-subscription repository"),
            ));
        }
    }
    let newest = lists
        .iter()
        .filter(|(n, _)| n.ends_with("Release"))
        .map(|(_, t)| *t)
        .max();
    if let Some(age) = newest.and_then(|t| now.duration_since(t).ok()) {
        if age > APT_STALE {
            out.push(Check::node(
                "apt.stale",
                Severity::Warning,
                format!(
                    "package lists last refreshed {} days ago: updates are not seen",
                    age.as_secs() / 86400
                ),
                Some("apt update (or check why the daily pve-daily-update timer fails)"),
            ));
        }
    }
    out
}

fn corosync(pve: &Path) -> Vec<Check> {
    let Some(c) = read(&pve.join("corosync.conf")) else {
        return Vec::new();
    };
    let off = c.lines().map(str::trim).any(|l| {
        let l = l.replace(' ', "");
        l == "crypto_cipher:none" || l == "secauth:off"
    });
    if !off {
        return Vec::new();
    }
    vec![Check::node(
        "corosync.unencrypted",
        Severity::Warning,
        "corosync traffic is not encrypted (crypto_cipher none / secauth off)".into(),
        Some("crypto_cipher aes256 and crypto_hash sha256 in /etc/pve/corosync.conf"),
    )]
}

// ---------------------------------------------------------------- guests

fn notices(inv: &Inventory) -> Vec<Check> {
    let mut out = Vec::new();
    let mk = |id, sev, msg: String| match &inv.guest {
        Some(g) => Check::guest(g, id, sev, msg),
        None => Check::node(id, sev, msg, None),
    };
    if !inv.restart.is_empty() {
        let pkgs: Vec<&str> = inv.restart.iter().map(|r| r.package.as_str()).collect();
        let mut c = mk(
            "restart_needed",
            Severity::Warning,
            format!(
                "old code still running after an upgrade: {}",
                pkgs.join(", ")
            ),
        );
        c.fix = Some("restart the processes holding them (needrestart, or the guest)".into());
        out.push(c);
    }
    if let Some(r) = &inv.reboot {
        let mut c = mk(
            "reboot_needed",
            Severity::Warning,
            format!("reboot needed: {r}"),
        );
        c.fix = Some("reboot (migrate the guests away first on a cluster)".into());
        out.push(c);
    }
    out
}

/// How much a config risk weakens isolation. Privileged plus a way out
/// (nesting, AppArmor off, a writable host mount) is close to host root.
pub fn risk_severity(kind: GuestKind, risk: &str, all: &[String]) -> Severity {
    let risk = risk.trim_end_matches(" (pending restart)");
    let privileged = kind == GuestKind::Lxc && all.iter().any(|r| r.starts_with("privileged"));
    let way_out = risk == "nesting"
        || risk == "apparmor unconfined"
        || risk == "no capabilities dropped"
        || (risk.contains("host bind mount") && !risk.ends_with("(ro)"));
    if privileged && way_out {
        Severity::Critical
    } else if risk == "privileged"
        || way_out
        || risk.starts_with("raw ")
        || risk.starts_with("hookscript")
        || risk.contains("host device")
        || risk.contains("passthrough")
    {
        Severity::Warning
    } else {
        Severity::Info
    }
}

fn guest_risks(g: &Guest) -> Vec<Check> {
    g.risks
        .iter()
        .map(|r| {
            Check::guest(
                g,
                "guest.risk",
                risk_severity(g.kind, r, &g.risks),
                format!("isolation risk: {r}"),
            )
        })
        .collect()
}

// ---------------------------------------------------------------- output

pub fn pretty(checks: &[Check], color: bool) -> String {
    let count = |s| checks.iter().filter(|c| c.severity == s).count();
    let mut out = format!(
        "{} checks failed: {} critical, {} warning, {} info\n",
        checks.len(),
        count(Severity::Critical),
        count(Severity::Warning),
        count(Severity::Info)
    );
    let mut last: Option<Option<u32>> = None;
    for c in checks {
        let target = c.guest.as_ref().map(|g| g.vmid);
        if last != Some(target) {
            let title = match &c.guest {
                Some(g) => format!("{} ({} {})", g.name, g.kind.as_str(), g.vmid),
                None => "node".to_string(),
            };
            let title = if color {
                title.bold().to_string()
            } else {
                title
            };
            let _ = write!(out, "\n{title}\n");
            last = Some(target);
        }
        let sev = match c.severity {
            Severity::Info => "info",
            Severity::Warning => "WARN",
            Severity::Critical => "CRIT",
        };
        let sev = match (color, c.severity) {
            (false, _) | (_, Severity::Info) => sev.to_string(),
            (_, Severity::Warning) => sev.yellow().to_string(),
            (_, Severity::Critical) => sev.red().bold().to_string(),
        };
        let _ = writeln!(out, "  {sev}  {}", c.message);
        if let Some(f) = &c.fix {
            let fix = format!("fix: {f}");
            let fix = if color { fix.dimmed().to_string() } else { fix };
            let _ = writeln!(out, "        {fix}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guest(vmid: u32, cfg: &str) -> Guest {
        use crate::guest;
        let config = guest::parse_config(cfg);
        Guest {
            kind: GuestKind::Lxc,
            vmid,
            name: format!("g{vmid}"),
            status: "running",
            risks: guest::risks(GuestKind::Lxc, &config),
            config,
        }
    }

    #[test]
    fn firewall_options() {
        assert_eq!(
            fw_enabled("[OPTIONS]\nenable: 1\n[RULES]\nIN ACCEPT\n"),
            Some(true)
        );
        assert_eq!(
            fw_enabled("[options]\n\npolicy_in: DROP\nenable: 0\n"),
            Some(false)
        );
        assert_eq!(fw_enabled("[RULES]\nenable: 1\n"), None);

        let dir = tempfile::tempdir().unwrap();
        let pve = dir.path();
        let g1 = guest(
            1,
            "unprivileged: 1\nnet0: name=eth0,bridge=vmbr0,firewall=1\n",
        );
        let g2 = guest(2, "unprivileged: 1\nnet0: name=eth0,bridge=vmbr0,firewall=1\nnet1: name=eth1,bridge=vmbr1\n");
        let g3 = guest(3, "unprivileged: 1\nnet0: name=eth0,bridge=vmbr0\n");
        let ids = |c: Vec<Check>| -> Vec<(&'static str, Option<u32>)> {
            c.iter()
                .map(|c| (c.id, c.guest.as_ref().map(|g| g.vmid)))
                .collect()
        };
        assert_eq!(
            ids(firewall(pve, "pve", &[&g1])),
            [("firewall.datacenter", None)]
        );

        std::fs::create_dir_all(pve.join("firewall")).unwrap();
        std::fs::write(pve.join("firewall/cluster.fw"), "[OPTIONS]\nenable: 1\n").unwrap();
        for v in [1, 2] {
            std::fs::write(
                pve.join(format!("firewall/{v}.fw")),
                "[OPTIONS]\nenable: 1\n",
            )
            .unwrap();
        }
        let got = firewall(pve, "pve", &[&g1, &g2, &g3]);
        assert_eq!(
            ids(got.clone()),
            [("firewall.guest", Some(2)), ("firewall.guest", Some(3))]
        );
        assert!(
            got[0].message.starts_with("net1 without firewall=1"),
            "{}",
            got[0].message
        );
        assert!(got[1].message.starts_with("guest firewall off"));
    }

    #[test]
    fn users_factors_and_tokens() {
        let cfg = parse_user_cfg(
            "user:root@pam:1:0:::root@example.com:::\nuser:old@pve:1:100::::::\n\
             user:off@pve:0:0::::::\nuser:yk@pve:1:0:::::x!yubico:\n\
             token:root@pam!ci:0:0::\ntoken:mcp@pve!claude:0:1::\n",
            1_000,
        );
        let ids: Vec<&str> = cfg.users.iter().map(|(u, _)| u.as_str()).collect();
        assert_eq!(ids, ["root@pam", "yk@pve"]);
        assert_eq!(cfg.shared_tokens, ["root@pam!ci"]);

        let tfa = tfa_users(
            r#"{"users":{"root@pam":{"totp":[{"id":"a","value":"secret"}]},"bob@pve":{"recovery":["x"]}},"webauthn":{}}"#,
        );
        assert_eq!(tfa.into_iter().collect::<Vec<_>>(), ["root@pam"]);
        let realms = tfa_realms(
            "pam: pam\n\tcomment Linux PAM\n\nldap: corp\n\tserver1 ldap\n\ttfa type=oath\n",
        );
        assert_eq!(realms.into_iter().collect::<Vec<_>>(), ["corp"]);
    }

    #[test]
    fn ssh_and_sources() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        std::fs::create_dir_all(r.join("etc/ssh")).unwrap();
        std::fs::write(
            r.join("etc/ssh/sshd_config"),
            "# x\nPermitRootLogin yes\nMatch User bob\n",
        )
        .unwrap();
        assert_eq!(ssh(r)[0].id, "ssh.root_password");
        std::fs::write(r.join("etc/ssh/sshd_config"), "PasswordAuthentication no\n").unwrap();
        assert!(ssh(r).is_empty());

        let one = parse_sources(
            "# c\ndeb http://deb.debian.org/debian trixie main contrib\n\
             deb [arch=amd64 signed-by=/k.gpg] http://download.proxmox.com/debian/pve trixie pve-no-subscription\n",
            false,
        );
        assert_eq!(one[1].uri, "http://download.proxmox.com/debian/pve");
        assert_eq!(one[1].components, ["pve-no-subscription"]);
        let d = parse_sources(
            "Types: deb\nURIs: https://enterprise.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-enterprise\n\n\
             Types: deb\nURIs: http://download.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-test\nEnabled: no\n",
            true,
        );
        assert_eq!(d.len(), 1);

        std::fs::create_dir_all(r.join("etc/apt/sources.list.d")).unwrap();
        std::fs::create_dir_all(r.join("var/lib/apt/lists")).unwrap();
        std::fs::write(
            r.join("etc/apt/sources.list.d/pve-enterprise.sources"),
            "Types: deb\nURIs: https://enterprise.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-enterprise\n",
        )
        .unwrap();
        std::fs::write(
            r.join("var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease"),
            "",
        )
        .unwrap();
        let ids = |now| {
            repositories(r, now)
                .iter()
                .map(|c| c.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(SystemTime::now()), ["apt.enterprise_unreachable"]);
        let later = SystemTime::now() + Duration::from_secs(30 * 86400);
        assert_eq!(ids(later), ["apt.enterprise_unreachable", "apt.stale"]);
        std::fs::write(
            r.join("var/lib/apt/lists/enterprise.proxmox.com_debian_pve_dists_trixie_InRelease"),
            "",
        )
        .unwrap();
        assert!(ids(SystemTime::now()).is_empty());
    }

    #[test]
    fn risk_levels() {
        let sev = |risks: &[&str], r: &str| {
            let all: Vec<String> = risks.iter().map(|s| s.to_string()).collect();
            risk_severity(GuestKind::Lxc, r, &all)
        };
        let priv_nest = ["privileged", "nesting", "mp0 host bind mount /var/log (ro)"];
        assert_eq!(sev(&priv_nest, "nesting"), Severity::Critical);
        assert_eq!(sev(&priv_nest, "privileged"), Severity::Warning);
        assert_eq!(
            sev(&priv_nest, "mp0 host bind mount /var/log (ro)"),
            Severity::Info
        );
        assert_eq!(sev(&["nesting"], "nesting"), Severity::Warning);
        assert_eq!(sev(&["keyctl"], "keyctl"), Severity::Info);
        assert_eq!(
            sev(
                &["privileged", "mp0 host bind mount /srv"],
                "mp0 host bind mount /srv"
            ),
            Severity::Critical
        );
    }
}
