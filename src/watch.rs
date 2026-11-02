//! `virtsec watch`: one live stream of what happens on the node.
//!
//! - **exec**: every program started in a guest, from the kernel's proc
//!   connector (netlink), attributed by cgroup. In an LXC, each exec is
//!   reported. In a VM's cgroup only QEMU (and PVE's tap scripts) should ever
//!   run: anything else there is a possible VM escape.
//! - **pve**: logins, authentication failures and tasks, from the journal of
//!   pvedaemon / pveproxy / sshd.
//! - **config**: guests created, removed, started, stopped, and isolation risks
//!   added to or removed from their config (polled, pmxcfs has no inotify).

// The exec source is Linux-only; its helpers are still unit-tested elsewhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Local, Utc};
use owo_colors::OwoColorize;
use serde::Serialize;

use crate::guest::{self, GuestKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestRef {
    pub kind: GuestKind,
    pub vmid: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub time: DateTime<Utc>,
    pub severity: Severity,
    /// `exec`, `ebpf`, `pve` or `config`.
    pub source: &'static str,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest: Option<GuestRef>,
    pub message: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

impl Event {
    pub fn new(severity: Severity, source: &'static str, kind: &str, message: String) -> Self {
        Self {
            time: Utc::now(),
            severity,
            source,
            kind: kind.to_string(),
            guest: None,
            message,
            fields: BTreeMap::new(),
        }
    }

    pub fn pretty(&self, color: bool) -> String {
        let sev = match self.severity {
            Severity::Info => "info",
            Severity::Warning => "WARN",
            Severity::Critical => "CRIT",
        };
        let sev = match (color, self.severity) {
            (false, _) | (_, Severity::Info) => sev.to_string(),
            (_, Severity::Warning) => sev.yellow().to_string(),
            (_, Severity::Critical) => sev.red().bold().to_string(),
        };
        let guest = self
            .guest
            .as_ref()
            .map(|g| format!("{}/{} {}  ", g.kind.as_str(), g.vmid, g.name))
            .unwrap_or_default();
        format!(
            "{}  {sev}  {:<6}  {guest}{}",
            self.time.with_timezone(&Local).format("%H:%M:%S"),
            self.source,
            self.message
        )
    }
}

/// Guest names by id, kept current by the config poller for the other sources.
pub type Names = Arc<Mutex<HashMap<(GuestKind, u32), String>>>;

pub fn guest_ref(names: &Names, kind: GuestKind, vmid: u32) -> GuestRef {
    let name = names
        .lock()
        .ok()
        .and_then(|n| n.get(&(kind, vmid)).cloned())
        .unwrap_or_else(|| "?".into());
    GuestRef { kind, vmid, name }
}

// ---------------------------------------------------------------- config

#[derive(Clone, PartialEq)]
struct State {
    name: String,
    status: &'static str,
    risks: Vec<String>,
}

/// Poll `/etc/pve` and the guest cgroups every `every`, reporting what changed.
pub fn poll_config(pve: PathBuf, names: Names, every: Duration, tx: Sender<Event>) {
    let mut prev: Option<HashMap<(GuestKind, u32), State>> = None;
    loop {
        let by_guest: HashMap<_, _> = guest::pids_by_guest()
            .into_iter()
            .filter_map(|(g, p)| Some((g?, p)))
            .collect();
        let now: HashMap<_, _> = guest::discover(&pve, &by_guest)
            .into_iter()
            .map(|g| {
                (
                    (g.kind, g.vmid),
                    State {
                        name: g.name,
                        status: g.status,
                        risks: g.risks,
                    },
                )
            })
            .collect();
        if let Ok(mut n) = names.lock() {
            *n = now.iter().map(|(k, s)| (*k, s.name.clone())).collect();
        }
        if let Some(prev) = &prev {
            for ev in config_diff(prev, &now) {
                if tx.send(ev).is_err() {
                    return;
                }
            }
        }
        prev = Some(now);
        std::thread::sleep(every);
    }
}

fn config_diff(
    prev: &HashMap<(GuestKind, u32), State>,
    now: &HashMap<(GuestKind, u32), State>,
) -> Vec<Event> {
    let mut out = Vec::new();
    let mut keys: Vec<_> = prev.keys().chain(now.keys()).copied().collect();
    keys.sort();
    keys.dedup();
    for key @ (kind, vmid) in keys {
        let ev = |sev, k: &str, msg: String, name: &str| {
            let mut e = Event::new(sev, "config", k, msg);
            e.guest = Some(GuestRef {
                kind,
                vmid,
                name: name.to_string(),
            });
            e
        };
        match (prev.get(&key), now.get(&key)) {
            (None, Some(s)) => {
                let (sev, msg) = if s.risks.is_empty() {
                    (Severity::Info, "guest created".to_string())
                } else {
                    (
                        Severity::Warning,
                        format!("guest created, risks: {}", s.risks.join(", ")),
                    )
                };
                out.push(ev(sev, "guest_created", msg, &s.name));
            }
            (Some(s), None) => out.push(ev(
                Severity::Info,
                "guest_removed",
                "guest removed".into(),
                &s.name,
            )),
            (Some(a), Some(b)) => {
                if a.status != b.status {
                    let k = if b.status == "running" {
                        "started"
                    } else {
                        "stopped"
                    };
                    out.push(ev(Severity::Info, k, k.to_string(), &b.name));
                }
                for r in b.risks.iter().filter(|r| !a.risks.contains(r)) {
                    out.push(ev(
                        Severity::Warning,
                        "risk_added",
                        format!("risk added: {r}"),
                        &b.name,
                    ));
                }
                for r in a.risks.iter().filter(|r| !b.risks.contains(r)) {
                    out.push(ev(
                        Severity::Info,
                        "risk_removed",
                        format!("risk removed: {r}"),
                        &b.name,
                    ));
                }
            }
            (None, None) => {}
        }
    }
    out
}

// ---------------------------------------------------------------- journal

/// Follow the journal of PVE's API daemons and sshd.
pub fn follow_journal(names: Names, tx: Sender<Event>) -> anyhow::Result<()> {
    let mut child = Command::new("journalctl")
        .args(["-f", "-n", "0", "-o", "json"])
        .args([
            "-u",
            "pvedaemon",
            "-u",
            "pveproxy",
            "-u",
            "ssh",
            "-u",
            "sshd",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().expect("piped");
    for line in BufReader::new(stdout).lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line?) else {
            continue;
        };
        let ident = v["SYSLOG_IDENTIFIER"].as_str().unwrap_or("");
        // MESSAGE is a byte array when not valid UTF-8.
        let msg = match &v["MESSAGE"] {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(b) => String::from_utf8_lossy(
                &b.iter()
                    .filter_map(|x| x.as_u64().map(|x| x as u8))
                    .collect::<Vec<_>>(),
            )
            .into_owned(),
            _ => continue,
        };
        if let Some(mut ev) = classify(ident, &msg) {
            if let Some(vmid) = ev.fields.get("vmid").and_then(|v| v.parse().ok()) {
                let kind = match ev.fields.get("task").map(String::as_str) {
                    Some(t) if t.starts_with("vz") => GuestKind::Lxc,
                    _ => GuestKind::Qemu,
                };
                ev.guest = Some(guest_ref(&names, kind, vmid));
            }
            if tx.send(ev).is_err() {
                break;
            }
        }
    }
    let _ = child.kill();
    Ok(())
}

/// `key=value` out of a log line (`rhost=::ffff:10.0.0.5 user=root@pam`).
fn kv<'a>(msg: &'a str, key: &str) -> Option<&'a str> {
    msg.split_whitespace()
        .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim_end_matches([';', ',']))
}

/// The security-relevant lines of pvedaemon / pveproxy / sshd.
pub fn classify(ident: &str, msg: &str) -> Option<Event> {
    let mut fields = BTreeMap::new();
    let (sev, kind, text) = if ident.starts_with("sshd") {
        if msg.starts_with("Accepted ") {
            (Severity::Info, "ssh_login", msg.to_string())
        } else if msg.starts_with("Failed ") || msg.starts_with("Invalid user") {
            (Severity::Warning, "ssh_failure", msg.to_string())
        } else {
            return None;
        }
    } else if msg.contains("authentication failure;") {
        let user = kv(msg, "user").unwrap_or("?");
        let rhost = kv(msg, "rhost").unwrap_or("?");
        fields.insert("user".into(), user.to_string());
        fields.insert("rhost".into(), rhost.to_string());
        (
            Severity::Warning,
            "auth_failure",
            format!("API authentication failure for {user} from {rhost}"),
        )
    } else if let Some(user) = msg
        .split_once("successful auth for user '")
        .and_then(|(_, r)| r.split_once('\''))
        .map(|(u, _)| u)
    {
        fields.insert("user".into(), user.to_string());
        (Severity::Info, "login", format!("API login {user}"))
    } else {
        let upid = msg.split_once("starting task UPID:").map(|(_, u)| u)?;
        // node:pid:pstart:starttime:type:id:user:
        let parts: Vec<&str> = upid.split(':').collect();
        let (task, id, user) = (
            parts.get(4)?,
            parts.get(5).unwrap_or(&""),
            parts.get(6).unwrap_or(&"?"),
        );
        fields.insert("task".into(), task.to_string());
        fields.insert("user".into(), user.to_string());
        if !id.is_empty() {
            fields.insert("vmid".into(), id.to_string());
        }
        (
            Severity::Info,
            "task",
            format!("task {task} {id} by {user}"),
        )
    };
    let mut ev = Event::new(sev, "pve", kind, text);
    ev.fields = fields;
    Some(ev)
}

// ---------------------------------------------------------------- exec

/// Command line, ppid and uid of a freshly exec'd process (racy: it may be gone).
fn describe(pid: u32) -> (String, BTreeMap<String, String>) {
    let mut cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            String::from_utf8_lossy(&b)
                .trim_end_matches('\0')
                .replace('\0', " ")
        })
        .unwrap_or_default();
    if cmdline.chars().count() > 200 {
        cmdline = cmdline.chars().take(200).collect::<String>() + "…";
    }
    let mut fields = BTreeMap::new();
    fields.insert("pid".into(), pid.to_string());
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
        for (key, name) in [("PPid:", "ppid"), ("Uid:", "uid")] {
            if let Some(v) = status
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .and_then(|v| v.split_whitespace().next())
            {
                fields.insert(name.into(), v.to_string());
            }
        }
    }
    (cmdline, fields)
}

/// Programs QEMU legitimately runs in its own cgroup: itself, PVE's tap scripts.
fn expected_in_vm(exe: &str) -> bool {
    exe.ends_with("/qemu-system-x86_64")
        || exe.ends_with("/qemu-system-aarch64")
        || exe.ends_with("/kvm")
        || exe.contains("/qemu-server/pve-bridge")
}

/// `(dev, ino)` of `pid`'s root directory.
fn root_id(pid: u32) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/proc/{pid}/root/"))
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Whether an exec in LXC `vmid` is one of LXC's own hooks (lxcfs mounts,
/// autodev, ...): those run in the container's cgroup, but on the host's root,
/// before `pivot_root`. A process already gone is judged by its container: no
/// process there on its own root yet (or any more) means it is starting or stopping.
pub fn is_lxc_hook(vmid: u32, pid: u32) -> bool {
    let host = root_id(1);
    if let Some(root) = root_id(pid) {
        return Some(root) == host;
    }
    let mut dirs = vec![PathBuf::from(format!("/sys/fs/cgroup/lxc/{vmid}"))];
    while let Some(dir) = dirs.pop() {
        if let Ok(procs) = std::fs::read_to_string(dir.join("cgroup.procs")) {
            let own_root = procs
                .lines()
                .filter_map(|l| l.parse().ok())
                .any(|p| root_id(p).is_some_and(|r| Some(r) != host));
            if own_root {
                return false;
            }
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            dirs.extend(
                entries
                    .flatten()
                    .filter(|e| e.path().is_dir())
                    .map(|e| e.path()),
            );
        }
    }
    true
}

/// The guest of a live process, from its cgroup.
pub fn guest_of_pid(pid: u32) -> Option<(GuestKind, u32)> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .and_then(guest::guest_of_cgroup)
}

/// The exec event for `pid`, or `None` for the host's own processes.
pub fn exec_event(pid: u32, names: &Names) -> Option<Event> {
    let (kind, vmid) = guest_of_pid(pid)?;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "?".into());
    exec_in_guest(kind, vmid, pid, &exe, names)
}

/// An exec of `exe` by `pid` in a guest; `None` when expected (QEMU, LXC hooks).
pub fn exec_in_guest(
    kind: GuestKind,
    vmid: u32,
    pid: u32,
    exe: &str,
    names: &Names,
) -> Option<Event> {
    if kind == GuestKind::Lxc && is_lxc_hook(vmid, pid) {
        return None;
    }
    let (cmdline, fields) = describe(pid);
    let (sev, k, msg) = match kind {
        GuestKind::Qemu if expected_in_vm(exe) => return None,
        GuestKind::Qemu => (
            Severity::Critical,
            "vm_cgroup_exec",
            format!("program run in the VM's QEMU cgroup (possible VM escape): {exe}  {cmdline}"),
        ),
        GuestKind::Lxc => {
            let suspicious = ["/tmp/", "/dev/shm/", "/var/tmp/"]
                .iter()
                .any(|d| exe.starts_with(d))
                || exe.ends_with(" (deleted)");
            (
                if suspicious {
                    Severity::Warning
                } else {
                    Severity::Info
                },
                "exec",
                format!("{exe}  {cmdline}"),
            )
        }
    };
    let mut ev = Event::new(sev, "exec", k, msg);
    ev.guest = Some(guest_ref(names, kind, vmid));
    ev.fields = fields;
    Some(ev)
}

/// `PROC_EVENT_EXEC`'s tgid out of one proc connector datagram.
///
/// Layout: `nlmsghdr` (16) · `cn_msg` (20: idx, val, seq, ack, len, flags) ·
/// `proc_event` (what, cpu, timestamp_ns, then `exec { pid, tgid }`).
pub fn parse_exec(buf: &[u8]) -> Option<u32> {
    let u32_at = |o: usize| {
        buf.get(o..o + 4)
            .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
    };
    const CN_IDX_PROC: u32 = 1;
    const PROC_EVENT_EXEC: u32 = 2;
    (u32_at(16)? == CN_IDX_PROC && u32_at(36)? == PROC_EVENT_EXEC).then_some(())?;
    u32_at(56)
}

#[cfg(target_os = "linux")]
pub fn follow_exec(names: Names, tx: Sender<Event>) -> anyhow::Result<()> {
    use std::mem::{size_of, zeroed};
    // SAFETY: plain netlink socket calls on buffers we own.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_CONNECTOR,
        );
        if fd < 0 {
            anyhow::bail!("proc connector: {}", std::io::Error::last_os_error());
        }
        let mut sa: libc::sockaddr_nl = zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        sa.nl_groups = 1; // CN_IDX_PROC
        if libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_nl>() as u32,
        ) < 0
        {
            anyhow::bail!("proc connector bind: {}", std::io::Error::last_os_error());
        }
        // nlmsghdr + cn_msg { idx 1, val 1, len 4 } + PROC_CN_MCAST_LISTEN
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(&40u32.to_ne_bytes());
        msg.extend_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes());
        msg.extend_from_slice(&[0u8; 10]); // flags, seq, pid
        for v in [1u32, 1, 0, 0] {
            msg.extend_from_slice(&v.to_ne_bytes());
        }
        msg.extend_from_slice(&4u16.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        if libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) < 0 {
            anyhow::bail!("proc connector listen: {}", std::io::Error::last_os_error());
        }
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0);
            if n < 0 {
                let e = std::io::Error::last_os_error();
                // ENOBUFS: events dropped under load; keep going.
                if e.raw_os_error() == Some(libc::ENOBUFS) {
                    continue;
                }
                anyhow::bail!("proc connector: {e}");
            }
            if let Some(ev) = parse_exec(&buf[..n as usize]).and_then(|pid| exec_event(pid, &names))
            {
                if tx.send(ev).is_err() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn follow_exec(_names: Names, _tx: Sender<Event>) -> anyhow::Result<()> {
    anyhow::bail!("exec events need Linux (proc connector)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_connector_exec() {
        let mut b = vec![0u8; 64];
        b[16..20].copy_from_slice(&1u32.to_ne_bytes());
        b[36..40].copy_from_slice(&2u32.to_ne_bytes());
        b[52..56].copy_from_slice(&4242u32.to_ne_bytes());
        b[56..60].copy_from_slice(&4241u32.to_ne_bytes());
        assert_eq!(parse_exec(&b), Some(4241));
        b[36..40].copy_from_slice(&1u32.to_ne_bytes()); // PROC_EVENT_FORK
        assert_eq!(parse_exec(&b), None);
        assert_eq!(parse_exec(&b[..40]), None);
    }

    #[test]
    fn journal_lines() {
        let e = classify(
            "pvedaemon",
            "authentication failure; rhost=::ffff:192.168.16.10 user=root@pam msg=Authentication failure",
        )
        .unwrap();
        assert_eq!(
            (e.severity, e.kind.as_str()),
            (Severity::Warning, "auth_failure")
        );
        assert_eq!(e.fields["rhost"], "::ffff:192.168.16.10");

        let e = classify(
            "pvedaemon",
            "<root@pam> successful auth for user 'root@pam'",
        )
        .unwrap();
        assert_eq!(e.message, "API login root@pam");

        let e = classify(
            "pvedaemon",
            "<root@pam> starting task UPID:pve:0003A1B2:01C2D3E4:6720F1A2:vzstart:4001:root@pam:",
        )
        .unwrap();
        assert_eq!(e.message, "task vzstart 4001 by root@pam");
        assert_eq!(e.fields["vmid"], "4001");

        assert_eq!(
            classify(
                "sshd",
                "Failed password for root from 10.0.0.9 port 4242 ssh2"
            )
            .unwrap()
            .kind,
            "ssh_failure"
        );
        assert!(classify("sshd", "pam_unix(sshd:session): session closed").is_none());
        assert!(classify("pveproxy", "worker 1234 finished").is_none());
    }

    #[test]
    fn config_changes() {
        let s = |status, risks: &[&str]| State {
            name: "web".into(),
            status,
            risks: risks.iter().map(|r| r.to_string()).collect(),
        };
        let prev = HashMap::from([
            ((GuestKind::Lxc, 1), s("running", &["nesting"])),
            ((GuestKind::Qemu, 2), s("running", &[])),
        ]);
        let now = HashMap::from([
            ((GuestKind::Lxc, 1), s("stopped", &["privileged"])),
            ((GuestKind::Qemu, 3), s("stopped", &["raw QEMU args"])),
        ]);
        let got: Vec<(String, String)> = config_diff(&prev, &now)
            .into_iter()
            .map(|e| (e.kind, e.message))
            .collect();
        assert_eq!(
            got,
            vec![
                ("stopped".into(), "stopped".into()),
                ("risk_added".into(), "risk added: privileged".into()),
                ("risk_removed".into(), "risk removed: nesting".into()),
                ("guest_removed".into(), "guest removed".into()),
                (
                    "guest_created".into(),
                    "guest created, risks: raw QEMU args".into()
                ),
            ]
        );
    }

    #[test]
    fn vm_cgroup_allowlist() {
        assert!(expected_in_vm("/usr/bin/qemu-system-x86_64"));
        assert!(expected_in_vm("/usr/libexec/qemu-server/pve-bridge"));
        assert!(!expected_in_vm("/usr/bin/bash"));
    }
}
