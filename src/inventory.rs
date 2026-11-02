//! Inventory of each guest and of the node itself: OS packages, language
//! dependencies, and which of them are loaded in memory.
//!
//! - LXC shares the host kernel: its live root is `/proc/<pid>/root`, its
//!   mappings `/proc/<pid>/maps`, as for any container.
//! - A VM is opaque to the host: with `--guest-exec`, its package databases and
//!   mapped files are fetched through qemu-guest-agent and inventoried offline.
//! - The node: the host's own packages, the PVE stack (QEMU, LXC) matched by CPE.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use crate::guest::{Guest, GuestKind};
use crate::lang::{self, LangLimits};
use crate::model::{Coordinate, Inventory, Package, PackageKind, Reachability};
use crate::os::OsRelease;
use crate::pkgdb;
use crate::procfs;
use crate::qga::{self, Agent};
use crate::reach::{mark_loaded, FileIndex};
use crate::rootfs::Rootfs;

fn empty(guest: &Guest, os: Option<OsRelease>, warning: String) -> Inventory {
    Inventory {
        name: guest.name.clone(),
        digest: None,
        os,
        guest: Some(guest.clone()),
        packages: Vec::new(),
        mapped_files: 0,
        warnings: vec![warning],
    }
}

/// OS packages of `rootfs`, tagged loaded from `mapped` (in-root paths).
fn os_packages(
    rootfs: &Rootfs,
    os: Option<&OsRelease>,
    mapped: &BTreeSet<String>,
) -> (Vec<Package>, Vec<String>) {
    let (mut packages, mut warnings) = pkgdb::read(rootfs, os);
    if packages.is_empty() && warnings.is_empty() {
        warnings.push("no OS package database found".into());
    }
    let index = FileIndex::build(rootfs, &packages);
    mark_loaded(
        &mut packages,
        &index,
        rootfs,
        mapped.iter().map(String::as_str),
    );
    (packages, warnings)
}

/// A running container, through the live root of its processes.
pub fn scan_lxc(guest: &Guest, pids: &[u32], limits: &LangLimits) -> Inventory {
    let Some(rootfs) = pids
        .iter()
        .map(|&pid| Rootfs::of_pid(pid))
        .find(|fs| std::fs::read_dir(fs.root()).is_ok())
    else {
        return empty(guest, None, "stopped: not inspected".into());
    };
    let os = OsRelease::read(&rootfs);
    let mapped: BTreeSet<String> = pids.iter().flat_map(|&p| procfs::mapped_files(p)).collect();
    let (mut packages, warnings) = os_packages(&rootfs, os.as_ref(), &mapped);

    let exes: Vec<String> = pids
        .iter()
        .filter_map(|p| std::fs::read_link(format!("/proc/{p}/exe")).ok())
        .map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        })
        .collect();
    let mut lang = lang::scan(&rootfs, &exes, limits);
    crate::reach::mark_running_binaries(&mut lang, &exes);
    packages.extend(lang);

    Inventory {
        name: guest.name.clone(),
        digest: None,
        os,
        guest: Some(guest.clone()),
        packages,
        mapped_files: mapped.len(),
        warnings,
    }
}

/// Files mapped by every process of the guest, one canonical path per line.
const MAPS_SCRIPT: &str = r#"for m in /proc/[0-9]*/maps; do cat "$m" 2>/dev/null; done |
awk '{ p = $0; if (sub(/^[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +/, "", p) && p ~ /^\//) print p }' | sort -u"#;

/// The package databases, os-release and the usrmerge links, as a tar.gz on stdout.
const DB_SCRIPT: &str = r#"cd / || exit 1; set --
for f in etc/os-release usr/lib/os-release var/lib/dpkg/status lib/apk/db/installed var/lib/rpm/rpmdb.sqlite var/lib/dpkg/info/*.list; do
  [ -f "$f" ] && set -- "$@" "$f"
done
for f in bin sbin lib lib32 lib64 libx32 etc/os-release; do [ -L "$f" ] && set -- "$@" "$f"; done
[ $# -gt 0 ] || exit 3
exec tar -czf - "$@""#;

/// A VM, through its guest agent. Read-only commands run inside the guest
/// only when `exec` is set; otherwise just the agent's OS info is reported.
pub fn scan_vm(guest: &Guest, running: bool, exec: bool) -> Inventory {
    if !running {
        return empty(guest, None, "stopped: not inspected".into());
    }
    if !guest
        .get("agent")
        .is_some_and(|a| a.split(',').any(|o| o == "1" || o == "enabled=1"))
    {
        return empty(
            guest,
            None,
            "qemu-guest-agent not enabled: not inspected".into(),
        );
    }
    let mut agent = match Agent::connect(guest.vmid) {
        Ok(a) => a,
        Err(e) => return empty(guest, None, format!("guest agent unreachable: {e:#}")),
    };
    let os = agent.os_info().ok();
    if !exec {
        return empty(
            guest,
            os,
            "packages not inspected: guest exec is off (--guest-exec, or guest_exec in mlab; runs read-only commands in the VM via qemu-guest-agent)".into(),
        );
    }
    if os.as_ref().is_some_and(|o| o.id == "mswindows") {
        return empty(guest, os, "Windows guest: packages not inspected".into());
    }
    match fetch_vm(&mut agent, os.as_ref()) {
        Ok((packages, mapped_files, warnings, os_file)) => Inventory {
            name: guest.name.clone(),
            digest: None,
            os: os_file.or(os),
            guest: Some(guest.clone()),
            packages,
            mapped_files,
            warnings,
        },
        Err(e) => empty(guest, os, format!("guest inspection failed: {e:#}")),
    }
}

type Fetched = (Vec<Package>, usize, Vec<String>, Option<OsRelease>);

fn fetch_vm(agent: &mut Agent, os: Option<&OsRelease>) -> anyhow::Result<Fetched> {
    let timeout = Duration::from_secs(120);
    let maps = agent.exec_sh(MAPS_SCRIPT, timeout)?;
    let mapped: BTreeSet<String> = String::from_utf8_lossy(&maps.stdout)
        .lines()
        .map(|l| l.trim_end_matches(" (deleted)").to_string())
        .filter(|l| l.starts_with('/'))
        .collect();
    let db = agent.exec_sh(DB_SCRIPT, timeout)?;
    if db.code != 0 && db.stdout.is_empty() {
        anyhow::bail!(
            "tar exited {}: {}",
            db.code,
            String::from_utf8_lossy(&db.stderr).trim()
        );
    }

    let dir = tempdir()?;
    let result = (|| {
        qga::unpack(dir.path(), &db.stdout)?;
        // The canonical dirs of mapped files, so the usrmerge links resolve (`/lib/x` → `/usr/lib/x`).
        for f in &mapped {
            if let Some(parent) = Path::new(f).parent() {
                let _ = qga::safe_dirs(dir.path(), parent);
            }
        }
        let rootfs = Rootfs::new(dir.path());
        let os_file = OsRelease::read(&rootfs);
        let (packages, mut warnings) = os_packages(&rootfs, os_file.as_ref().or(os), &mapped);
        if maps.truncated || db.truncated {
            warnings.push("guest agent output truncated: inventory incomplete".into());
        }
        warnings.push("language dependencies not inspected in VMs".into());
        Ok((packages, mapped.len(), warnings, os_file))
    })();
    let _ = std::fs::remove_dir_all(dir.path());
    result
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

fn tempdir() -> anyhow::Result<TempDir> {
    use std::os::unix::fs::DirBuilderExt;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let p = std::env::temp_dir().join(format!("virtsec-{}-{nanos}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&p)?;
    Ok(TempDir(p))
}

/// Proxmox packages advisories are filed against upstream, by CPE.
const PVE_CPES: &[(&str, &str)] = &[
    ("pve-qemu-kvm", "a:qemu:qemu"),
    ("lxc-pve", "a:linuxcontainers:lxc"),
    ("lxcfs", "a:linuxcontainers:lxcfs"),
    ("pve-manager", "a:proxmox:virtual_environment"),
];

/// `1:10.0.2-4` → `10.0.2`.
fn upstream_version(v: &str) -> &str {
    let v = v.split_once(':').map_or(v, |(_, v)| v);
    v.split(['-', '+', '~']).next().unwrap_or(v)
}

/// The node itself: its packages tagged loaded by the host's own processes
/// (QEMU included), the PVE stack by CPE, the running kernel loaded.
pub fn host_inventory(host_pids: &[u32], match_kernel: bool) -> Inventory {
    let rootfs = Rootfs::new("/");
    let os = OsRelease::read(&rootfs);
    let mapped: BTreeSet<String> = host_pids
        .iter()
        .flat_map(|&p| procfs::mapped_files(p))
        .collect();
    let (mut packages, warnings) = os_packages(&rootfs, os.as_ref(), &mapped);

    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let kernel_file = format!("/boot/vmlinuz-{}", release.trim());
    for p in packages.iter_mut().filter(|p| p.kind == PackageKind::Os) {
        if let Some((_, cpe)) = PVE_CPES.iter().find(|(n, _)| *n == p.name) {
            p.coordinate = Some(Coordinate::Cpe {
                cpe: format!(
                    "cpe:2.3:{cpe}:{}:*:*:*:*:*:*:*",
                    upstream_version(&p.version)
                ),
            });
        }
        if p.files.contains(&kernel_file) {
            p.reachability = Reachability::Loaded;
            let upstream = upstream_version(release.trim());
            p.coordinate = match_kernel.then(|| Coordinate::Cpe {
                cpe: format!("cpe:2.3:o:linux:linux_kernel:{upstream}:*:*:*:*:*:*:*"),
            });
        }
    }

    let hostname = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    Inventory {
        name: format!("node {}", hostname.trim()),
        digest: None,
        os,
        guest: None,
        packages,
        mapped_files: mapped.len(),
        warnings,
    }
}

/// What to inventory on this node.
pub struct Scan<'a> {
    /// Proxmox config directory (`/etc/pve`).
    pub pve: &'a Path,
    /// Only these guests; empty = all.
    pub vmids: &'a [u32],
    pub kind: Option<GuestKind>,
    pub guest_exec: bool,
    /// Include the node itself.
    pub host: bool,
    pub match_kernel: bool,
}

/// Every wanted guest of this node, then the node (first) when asked.
pub fn scan_node(scan: &Scan) -> anyhow::Result<Vec<Inventory>> {
    crate::procfs::check_root_access()?;
    if !scan.pve.join("qemu-server").exists() && !scan.pve.join("lxc").exists() {
        anyhow::bail!(
            "{} has no guest configs: is this a Proxmox VE node?",
            scan.pve.display()
        );
    }
    let pids = crate::guest::pids_by_guest();
    let by_guest: std::collections::HashMap<_, _> = pids
        .iter()
        .filter_map(|(g, p)| Some(((*g)?, p.clone())))
        .collect();
    let limits = LangLimits::default();
    let mut invs: Vec<Inventory> = crate::guest::discover(scan.pve, &by_guest)
        .into_iter()
        .filter(|g| wanted(g, scan.vmids, scan.kind))
        .map(|g| {
            let p = by_guest
                .get(&(g.kind, g.vmid))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            match g.kind {
                GuestKind::Lxc => scan_lxc(&g, p, &limits),
                GuestKind::Qemu => scan_vm(&g, !p.is_empty(), scan.guest_exec),
            }
        })
        .collect();
    if scan.host {
        // A VM's QEMU process sits in the VM's cgroup but runs the host's binaries.
        let host: Vec<u32> = pids
            .iter()
            .filter(|(g, _)| g.is_none_or(|(k, _)| k == GuestKind::Qemu))
            .flat_map(|(_, p)| p.iter().copied())
            .collect();
        invs.insert(0, host_inventory(&host, scan.match_kernel));
    }
    Ok(invs)
}

/// A guest of `kind`, for the CLI's `--vmid` filter and the guest order.
pub fn wanted(g: &Guest, vmids: &[u32], kind: Option<GuestKind>) -> bool {
    (vmids.is_empty() || vmids.contains(&g.vmid)) && kind.is_none_or(|k| k == g.kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_versions() {
        assert_eq!(upstream_version("10.0.2-4"), "10.0.2");
        assert_eq!(upstream_version("1:6.0.5-1"), "6.0.5");
        assert_eq!(upstream_version("6.17.2-1-pve"), "6.17.2");
        assert_eq!(upstream_version("9.2.2"), "9.2.2");
    }
}
