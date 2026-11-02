//! Proxmox guests on this node: configs from `/etc/pve`, processes from cgroups.
//!
//! PVE puts every container under `/lxc/<vmid>/` (the monitor lives apart, in
//! `/lxc.monitor/<vmid>`) and every VM's QEMU process in
//! `/qemu.slice/<vmid>.scope`, so `/proc/<pid>/cgroup` names the guest of any PID.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestKind {
    Lxc,
    Qemu,
}

impl GuestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GuestKind::Lxc => "lxc",
            GuestKind::Qemu => "qemu",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Guest {
    pub kind: GuestKind,
    pub vmid: u32,
    pub name: String,
    /// `running` (has processes on this host), `stopped` or `template`.
    pub status: &'static str,
    /// Isolation weakened by the config (privileged, host bind mounts, passthrough, ...).
    pub risks: Vec<String>,
    /// The current config, `key: value` lines in file order (snapshots excluded).
    #[serde(skip)]
    pub config: Vec<(String, String)>,
}

impl Guest {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.config
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Every guest configured on this node (`<pve>/lxc`, `<pve>/qemu-server`), by vmid.
pub fn discover(pve: &Path, pids: &HashMap<(GuestKind, u32), Vec<u32>>) -> Vec<Guest> {
    let mut guests = Vec::new();
    for (kind, dir) in [(GuestKind::Lxc, "lxc"), (GuestKind::Qemu, "qemu-server")] {
        let Ok(entries) = fs::read_dir(pve.join(dir)) else {
            continue;
        };
        for e in entries.flatten() {
            let file = e.file_name();
            let Some(vmid) = file
                .to_str()
                .and_then(|n| n.strip_suffix(".conf"))
                .and_then(|n| n.parse().ok())
            else {
                continue;
            };
            let Ok(content) = fs::read_to_string(e.path()) else {
                continue;
            };
            let config = parse_config(&content);
            let name_key = if kind == GuestKind::Lxc {
                "hostname"
            } else {
                "name"
            };
            let name = config
                .iter()
                .find(|(k, _)| k == name_key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| format!("{}-{vmid}", kind.as_str()));
            let mut risks = risks(kind, &config);
            // Changes made while the guest runs wait in `[pve:pending]` until its next start.
            let pending = with_pending(&config, &content);
            for r in self::risks(kind, &pending) {
                if !risks.contains(&r) {
                    risks.push(format!("{r} (pending restart)"));
                }
            }
            guests.push(Guest {
                kind,
                vmid,
                name,
                status: if pids.contains_key(&(kind, vmid)) {
                    "running"
                } else if config.iter().any(|(k, v)| k == "template" && v == "1") {
                    "template"
                } else {
                    "stopped"
                },
                risks,
                config,
            });
        }
    }
    guests.sort_by_key(|g| g.vmid);
    guests
}

/// `key: value` lines up to the first `[snapshot]` section; `#` lines are the description.
pub fn parse_config(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .take_while(|l| !l.starts_with('['))
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// `config` with the `[pve:pending]` section applied (`delete: a,b` removes keys).
pub fn with_pending(config: &[(String, String)], content: &str) -> Vec<(String, String)> {
    let Some((_, rest)) = content.split_once("\n[pve:pending]\n") else {
        return config.to_vec();
    };
    let pending = parse_config(rest);
    let deleted: Vec<&str> = pending
        .iter()
        .filter(|(k, _)| k == "delete")
        .flat_map(|(_, v)| v.split(','))
        .collect();
    let mut out: Vec<(String, String)> = config
        .iter()
        .filter(|(k, _)| !deleted.contains(&k.as_str()) && !pending.iter().any(|(p, _)| p == k))
        .cloned()
        .collect();
    out.extend(pending.into_iter().filter(|(k, _)| k != "delete"));
    out
}

/// What in a guest's config weakens its isolation from the host.
pub fn risks(kind: GuestKind, config: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    let get = |key: &str| {
        config
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let numbered = |prefix: &'static str| {
        config.iter().filter(move |(k, _)| {
            k.strip_prefix(prefix)
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
    };
    match kind {
        GuestKind::Lxc => {
            if get("unprivileged") != Some("1") {
                out.push("privileged".to_string());
            }
            for f in get("features").into_iter().flat_map(|f| f.split(',')) {
                match f.split_once('=') {
                    Some((name @ ("nesting" | "keyctl" | "fuse" | "mknod"), "1")) => {
                        out.push(name.to_string())
                    }
                    Some(("mount", fs)) => out.push(format!("mount={fs}")),
                    _ => {}
                }
            }
            for (k, v) in numbered("mp") {
                // A volume is `storage:volume`; a bare absolute path is a host bind mount.
                let src = v.split(',').next().unwrap_or("");
                if src.starts_with('/') {
                    let ro = v.split(',').any(|o| o == "ro=1");
                    out.push(format!(
                        "{k} host bind mount {src}{}",
                        if ro { " (ro)" } else { "" }
                    ));
                }
            }
            for (k, v) in numbered("dev") {
                out.push(format!(
                    "{k} host device {}",
                    v.split(',').next().unwrap_or("")
                ));
            }
            for (k, v) in config.iter().filter(|(k, _)| k.starts_with("lxc.")) {
                out.push(match (k.as_str(), v.as_str()) {
                    ("lxc.apparmor.profile", "unconfined") => "apparmor unconfined".to_string(),
                    ("lxc.cap.drop", "") => "no capabilities dropped".to_string(),
                    _ => format!("raw {k}"),
                });
            }
        }
        GuestKind::Qemu => {
            if get("args").is_some() {
                out.push("raw QEMU args".to_string());
            }
            for (k, _) in numbered("hostpci") {
                out.push(format!("{k} PCI passthrough"));
            }
            for (k, v) in numbered("usb") {
                if !v.starts_with("spice") {
                    out.push(format!("{k} USB passthrough"));
                }
            }
            for (k, v) in numbered("virtiofs") {
                let dir = v
                    .split(',')
                    .find_map(|o| o.strip_prefix("dirid="))
                    .unwrap_or(v.split(',').next().unwrap_or(""));
                out.push(format!("{k} host directory {dir} shared (virtiofs)"));
            }
            if get("ivshmem").is_some() {
                out.push("ivshmem shared memory with the host".to_string());
            }
            for (k, v) in numbered("serial").chain(numbered("parallel")) {
                if v.starts_with("/dev/") {
                    out.push(format!("{k} host device {v}"));
                }
            }
        }
    }
    if let Some(h) = get("hookscript") {
        out.push(format!("hookscript {h}"));
    }
    out
}

/// The guest a cgroup v2 path belongs to (`/lxc/4001/ns/init.scope`, `/qemu.slice/150.scope`).
pub fn guest_of_cgroup(path: &str) -> Option<(GuestKind, u32)> {
    if let Some(rest) = path.strip_prefix("/lxc/") {
        return Some((GuestKind::Lxc, rest.split('/').next()?.parse().ok()?));
    }
    let rest = path.strip_prefix("/qemu.slice/")?;
    Some((
        GuestKind::Qemu,
        rest.split('/')
            .next()?
            .strip_suffix(".scope")?
            .parse()
            .ok()?,
    ))
}

/// Every PID on the host by guest; PIDs of no guest (the host's own) under `None`.
pub fn pids_by_guest() -> HashMap<Option<(GuestKind, u32)>, Vec<u32>> {
    let mut map: HashMap<_, Vec<u32>> = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse().ok()) else {
            continue;
        };
        let Ok(cg) = fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
            continue;
        };
        let guest = cg
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .and_then(guest_of_cgroup);
        map.entry(guest).or_default().push(pid);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_paths() {
        assert_eq!(
            guest_of_cgroup("/lxc/4001/ns/init.scope"),
            Some((GuestKind::Lxc, 4001))
        );
        assert_eq!(
            guest_of_cgroup("/lxc/4002/ns"),
            Some((GuestKind::Lxc, 4002))
        );
        assert_eq!(
            guest_of_cgroup("/qemu.slice/150.scope"),
            Some((GuestKind::Qemu, 150))
        );
        assert_eq!(guest_of_cgroup("/lxc.monitor/4001"), None);
        assert_eq!(guest_of_cgroup("/system.slice/pveproxy.service"), None);
    }

    #[test]
    fn lxc_risks() {
        let cfg = parse_config(
            "#my description: with colon\narch: amd64\nfeatures: nesting=1,mount=nfs,mknod=1\n\
             hostname: vs-alpine-priv\nmp0: /var/log,mp=/mnt/hostlog,ro=1\n\
             mp1: local-lvm:vm-4002-disk-1,mp=/data\ndev0: /dev/kvm,gid=104\n\
             lxc.apparmor.profile: unconfined\nlxc.cgroup2.devices.allow: a\n\
             [clean]\nunprivileged: 1\n",
        );
        assert_eq!(cfg[0], ("arch".to_string(), "amd64".to_string()));
        assert_eq!(
            risks(GuestKind::Lxc, &cfg),
            vec![
                "privileged",
                "nesting",
                "mount=nfs",
                "mknod",
                "mp0 host bind mount /var/log (ro)",
                "dev0 host device /dev/kvm",
                "apparmor unconfined",
                "raw lxc.cgroup2.devices.allow",
            ]
        );
        assert!(risks(GuestKind::Lxc, &parse_config("unprivileged: 1\n")).is_empty());
    }

    #[test]
    fn pending_changes() {
        let content = "unprivileged: 1\nfeatures: keyctl=1\nmp0: /srv,mp=/srv\n\
                       [pve:pending]\nfeatures: nesting=1\ndelete: mp0\n[clean]\nunprivileged: 0\n";
        let cfg = parse_config(content);
        let pending = with_pending(&cfg, content);
        assert_eq!(
            risks(GuestKind::Lxc, &cfg),
            vec!["keyctl", "mp0 host bind mount /srv"]
        );
        assert_eq!(risks(GuestKind::Lxc, &pending), vec!["nesting"]);
        assert_eq!(with_pending(&cfg, "unprivileged: 1\n"), cfg);
    }

    #[test]
    fn qemu_risks() {
        let cfg = parse_config(
            "args: -cpu host\nhostpci0: 0000:01:00.0\nusb0: spice\nusb1: host=1-2\n\
             virtiofs0: dirid=share,cache=auto\nivshmem: size=32,name=lg\n\
             serial0: socket\nhookscript: local:snippets/hook.pl\nscsi0: local-lvm:vm-1-disk-0\n",
        );
        assert_eq!(
            risks(GuestKind::Qemu, &cfg),
            vec![
                "raw QEMU args",
                "hostpci0 PCI passthrough",
                "usb1 USB passthrough",
                "virtiofs0 host directory share shared (virtiofs)",
                "ivshmem shared memory with the host",
                "hookscript local:snippets/hook.pl",
            ]
        );
    }
}
