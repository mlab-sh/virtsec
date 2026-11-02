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
use crate::model::{Coordinate, Inventory, Package, PackageKind, Reachability, Restart};
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
        ..Default::default()
    }
}

/// What the processes of a guest (or of the node) have mapped.
#[derive(Default)]
struct Mapped {
    files: BTreeSet<String>,
    /// Files replaced on disk since they were mapped, by process label
    /// (`comm[pid]`, empty when unknown).
    deleted: Vec<(String, BTreeSet<String>)>,
}

impl Mapped {
    fn of_pids(pids: &[u32]) -> Self {
        let mut m = Mapped::default();
        for &pid in pids {
            let (files, deleted) = procfs::mapped_files(pid);
            m.files.extend(files);
            if !deleted.is_empty() {
                m.deleted.push((procfs::label(pid), deleted));
            }
        }
        m
    }
}

/// OS packages of `rootfs`, tagged loaded from `mapped` (in-root paths), and
/// those whose replaced files are still mapped.
fn os_packages(
    rootfs: &Rootfs,
    os: Option<&OsRelease>,
    mapped: &Mapped,
) -> (Vec<Package>, Vec<String>, Vec<Restart>) {
    let (mut packages, mut warnings) = pkgdb::read(rootfs, os);
    if packages.is_empty() && warnings.is_empty() {
        warnings.push("no OS package database found".into());
    }
    let index = FileIndex::build(rootfs, &packages);
    mark_loaded(
        &mut packages,
        &index,
        rootfs,
        mapped.files.iter().map(String::as_str),
    );
    let restart = restarts(&packages, &index, rootfs, &mapped.deleted);
    (packages, warnings, restart)
}

/// Group deleted mapped files by owning package. A file no package owns any
/// more (package removed, memfd, `/dev/shm`) is not an upgrade: skipped.
fn restarts(
    packages: &[Package],
    index: &FileIndex,
    rootfs: &Rootfs,
    deleted: &[(String, BTreeSet<String>)],
) -> Vec<Restart> {
    let mut by_pkg: std::collections::BTreeMap<usize, BTreeSet<String>> = Default::default();
    for (proc, files) in deleted {
        for f in files {
            if let Some(i) = index.owner(rootfs, f) {
                let procs = by_pkg.entry(i).or_default();
                if !proc.is_empty() {
                    procs.insert(proc.clone());
                }
            }
        }
    }
    by_pkg
        .into_iter()
        .map(|(i, procs)| Restart {
            package: packages[i].name.clone(),
            processes: procs.into_iter().collect(),
        })
        .collect()
}

/// Debian / Ubuntu's `/run/reboot-required` (and the packages that asked for it).
fn reboot_required(rootfs: &Rootfs) -> Option<String> {
    if !rootfs.exists("/run/reboot-required") {
        return None;
    }
    let pkgs = rootfs
        .read_string("/run/reboot-required.pkgs", 64 * 1024)
        .unwrap_or_default();
    let mut pkgs: Vec<&str> = pkgs.split_whitespace().collect();
    pkgs.sort();
    pkgs.dedup();
    Some(if pkgs.is_empty() {
        "/run/reboot-required".to_string()
    } else {
        format!("/run/reboot-required by {}", pkgs.join(", "))
    })
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
    let mapped = Mapped::of_pids(pids);
    let (mut packages, warnings, restart) = os_packages(&rootfs, os.as_ref(), &mapped);

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
        mapped_files: mapped.files.len(),
        warnings,
        restart,
        reboot: reboot_required(&rootfs),
    }
}

/// Files mapped by every process of the guest, one canonical path per line.
const MAPS_SCRIPT: &str = r#"for m in /proc/[0-9]*/maps; do cat "$m" 2>/dev/null; done |
awk '{ p = $0; if (sub(/^[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +/, "", p) && p ~ /^\//) print p }' | sort -u"#;

/// The package databases, os-release and the usrmerge links, as a tar.gz on stdout.
const DB_SCRIPT: &str = r#"cd / || exit 1; set --
for f in etc/os-release usr/lib/os-release run/reboot-required run/reboot-required.pkgs var/lib/dpkg/status lib/apk/db/installed var/lib/rpm/rpmdb.sqlite var/lib/dpkg/info/*.list; do
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
        Ok(f) => Inventory {
            name: guest.name.clone(),
            digest: None,
            os: f.os.or(os),
            guest: Some(guest.clone()),
            packages: f.packages,
            mapped_files: f.mapped_files,
            warnings: f.warnings,
            restart: f.restart,
            reboot: f.reboot,
        },
        Err(e) => empty(guest, os, format!("guest inspection failed: {e:#}")),
    }
}

struct Fetched {
    packages: Vec<Package>,
    mapped_files: usize,
    warnings: Vec<String>,
    os: Option<OsRelease>,
    restart: Vec<Restart>,
    reboot: Option<String>,
}

fn fetch_vm(agent: &mut Agent, os: Option<&OsRelease>) -> anyhow::Result<Fetched> {
    let timeout = Duration::from_secs(120);
    let maps = agent.exec_sh(MAPS_SCRIPT, timeout)?;
    let lines = String::from_utf8_lossy(&maps.stdout);
    let lines = lines.lines().filter(|l| l.starts_with('/'));
    let mapped = Mapped {
        files: lines
            .clone()
            .map(|l| l.trim_end_matches(" (deleted)").to_string())
            .collect(),
        // The script doesn't say which process: the packages only.
        deleted: vec![(
            String::new(),
            lines
                .filter_map(|l| l.strip_suffix(" (deleted)"))
                .map(str::to_string)
                .collect(),
        )],
    };
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
        for f in &mapped.files {
            if let Some(parent) = Path::new(f).parent() {
                let _ = qga::safe_dirs(dir.path(), parent);
            }
        }
        let rootfs = Rootfs::new(dir.path());
        let os_file = OsRelease::read(&rootfs);
        let (packages, mut warnings, restart) =
            os_packages(&rootfs, os_file.as_ref().or(os), &mapped);
        if maps.truncated || db.truncated {
            warnings.push("guest agent output truncated: inventory incomplete".into());
        }
        warnings.push("language dependencies not inspected in VMs".into());
        Ok(Fetched {
            packages,
            mapped_files: mapped.files.len(),
            warnings,
            reboot: reboot_required(&rootfs),
            os: os_file,
            restart,
        })
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
    let mapped = Mapped::of_pids(host_pids);
    let (mut packages, mut warnings, restart) = os_packages(&rootfs, os.as_ref(), &mapped);

    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let kernel_file = format!("/boot/vmlinuz-{}", release.trim());
    let mut kernel_note = None;
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
            if match_kernel {
                let changelog = kernel_changelog(&p.name);
                p.backported = changelog_cves(&changelog);
                kernel_note = Some(format!(
                    "kernel matched by its upstream version {upstream} (NVD CPE){}; the {} CVEs its changelog names as fixed are not reported, other backports are not known",
                    ubuntu_base(&changelog)
                        .map(|b| format!(", built from {b}"))
                        .unwrap_or_default(),
                    p.backported.len()
                ));
            }
        }
    }

    warnings.extend(kernel_note);
    let hostname = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    Inventory {
        name: format!("node {}", hostname.trim()),
        digest: None,
        os,
        guest: None,
        packages,
        mapped_files: mapped.files.len(),
        warnings,
        restart,
        reboot: reboot_required(&rootfs).or_else(|| newer_kernel(release.trim())),
    }
}

/// The kernel package's changelog (`changelog.gz` for `-signed`, else
/// `changelog.Debian.gz`), empty when unreadable.
fn kernel_changelog(package: &str) -> String {
    use std::io::Read;
    let doc = Path::new("/usr/share/doc").join(package);
    ["changelog.gz", "changelog.Debian.gz"]
        .iter()
        .find_map(|f| {
            let gz = std::fs::File::open(doc.join(f)).ok()?;
            let mut s = String::new();
            flate2::read::GzDecoder::new(gz)
                .take(16 << 20)
                .read_to_string(&mut s)
                .ok()?;
            Some(s)
        })
        .unwrap_or_default()
}

/// Every `CVE-YYYY-N` the changelog names: PVE cherry-picks them.
fn changelog_cves(changelog: &str) -> Vec<String> {
    let mut out: Vec<String> = changelog
        .match_indices("CVE-")
        .filter_map(|(i, _)| {
            let rest = &changelog[i + 4..];
            let year = rest
                .get(..4)
                .filter(|y| y.bytes().all(|b| b.is_ascii_digit()))?;
            let n: String = rest
                .get(5..)?
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            (rest.as_bytes().get(4) == Some(&b'-') && n.len() >= 4)
                .then(|| format!("CVE-{year}-{n}"))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The Ubuntu kernel the PVE kernel is built from: the latest
/// `update sources to Ubuntu-7.0.0-18.18` entry.
fn ubuntu_base(changelog: &str) -> Option<String> {
    let at = changelog.find("sources to Ubuntu-")?;
    let tag: String = changelog[at + "sources to ".len()..]
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ',')
        .collect();
    Some(tag.trim_end_matches('.').to_string())
}

/// A kernel newer than the running one is installed (`/boot/vmlinuz-*`), and
/// the running one is not pinned (`proxmox-boot-tool kernel pin`).
fn newer_kernel(running: &str) -> Option<String> {
    let pin = std::fs::read_to_string("/etc/kernel/proxmox-boot-pin").unwrap_or_default();
    if pin.trim() == running {
        return None;
    }
    let installed = std::fs::read_dir("/boot").ok()?.flatten().filter_map(|e| {
        e.file_name()
            .to_str()?
            .strip_prefix("vmlinuz-")
            .map(str::to_string)
    });
    newest_kernel(running, installed)
}

fn newest_kernel(running: &str, installed: impl Iterator<Item = String>) -> Option<String> {
    let newest = installed.max_by(|a, b| crate::vuln::version_cmp(a, b))?;
    (crate::vuln::version_cmp(&newest, running).is_gt())
        .then(|| format!("kernel {newest} installed, {running} running"))
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

    #[test]
    fn kernel_changelog_facts() {
        let log = "proxmox-kernel-7.0 (7.0.2-3) trixie; urgency=medium\n\
                   * cherry-pick fix for CVE-2026-31431 and CVE-2026-1234.\n\
                   * update sources to Ubuntu-7.0.0-18.18 to avoid shipping...\n\
                   * not one: CVE-26-1, CVE-2026-12\n\
                   proxmox-kernel-7.0 (7.0.2-1)\n * update sources to Ubuntu-7.0.0-15.15\n\
                   * again CVE-2026-31431\n";
        assert_eq!(changelog_cves(log), ["CVE-2026-1234", "CVE-2026-31431"]);
        assert_eq!(ubuntu_base(log).as_deref(), Some("Ubuntu-7.0.0-18.18"));
        assert_eq!(ubuntu_base("nothing"), None);
    }

    #[test]
    fn newer_kernels() {
        let k = |v: &[&str]| {
            v.iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .into_iter()
        };
        assert_eq!(
            newest_kernel(
                "7.0.2-6-pve",
                k(&["7.0.2-6-pve", "7.0.2-10-pve", "6.17.2-1-pve"])
            ),
            Some("kernel 7.0.2-10-pve installed, 7.0.2-6-pve running".into())
        );
        assert_eq!(
            newest_kernel("7.0.2-6-pve", k(&["7.0.2-6-pve", "6.8.12-4-pve"])),
            None
        );
    }
}
