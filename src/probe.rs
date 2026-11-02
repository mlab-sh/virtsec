//! eBPF probe for `watch` (feature `ebpf`): exec, TCP connect and sensitive
//! file writes from the kernel, attributed to guests.
//!
//! Every record names its PID and cgroup id: a live process is attributed by
//! `/proc/<pid>/cgroup`, one already gone by its cgroup id (the inode of the
//! cgroup directory). Host processes are dropped. Records are never blocking:
//! the kernel drops on a full ring buffer, malformed ones are skipped here.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use aya::maps::RingBuf;
use aya::programs::{KProbe, TracePoint};
use aya::Ebpf;
use virtsec_probe_common::{af, kind, Event as KEvent};

use crate::guest::{self, GuestKind};
use crate::watch::{self, Event, Names, Severity};

/// eBPF exec / connect / file writes; the proc connector when the probe can't load.
pub fn follow(names: Names, tx: Sender<Event>) -> Result<()> {
    let mut ebpf = match load() {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("eBPF probe unavailable, exec events from the proc connector: {e:#}");
            return watch::follow_exec(names, tx);
        }
    };
    let mut ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow!("EVENTS ring buffer missing from the eBPF object"))?,
    )?;
    let fd = ring.as_raw_fd();
    let mut cgroups = CgroupIndex::default();
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd we own, for the ring buffer's fd.
        if unsafe { libc::poll(&mut pfd, 1, 1000) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e).context("ring buffer poll");
        }
        while let Some(item) = ring.next() {
            let Some(ev) = KEvent::from_bytes(&item) else {
                continue;
            };
            drop(item);
            if let Some(out) = to_event(&ev, &names, &mut cgroups) {
                if tx.send(out).is_err() {
                    return Ok(());
                }
            }
        }
    }
}

fn load() -> Result<Ebpf> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/virtsec-bpf"
    )))
    .context("cannot load the eBPF object (needs root)")?;
    let tp: &mut TracePoint = ebpf
        .program_mut("virtsec_execve")
        .ok_or_else(|| anyhow!("virtsec_execve missing"))?
        .try_into()?;
    tp.load()?;
    tp.attach("sched", "sched_process_exec")
        .context("attach sched:sched_process_exec")?;
    for (prog, symbol, optional) in [
        ("virtsec_tcp_v4_connect", "tcp_v4_connect", false),
        ("virtsec_tcp_v6_connect", "tcp_v6_connect", false),
        // Internal function, may be inlined: then no file writes, the rest goes on.
        ("virtsec_openat", "do_sys_openat2", true),
    ] {
        let attached = (|| -> Result<()> {
            let kp: &mut KProbe = ebpf
                .program_mut(prog)
                .ok_or_else(|| anyhow!("{prog} missing"))?
                .try_into()?;
            kp.load()?;
            kp.attach(symbol, 0)
                .with_context(|| format!("attach kprobe {symbol}"))?;
            Ok(())
        })();
        match attached {
            Err(e) if optional => tracing::warn!("{prog} unavailable on this kernel: {e:#}"),
            r => r?,
        }
    }
    Ok(ebpf)
}

/// Kernel cgroup id → guest, for records whose process is already gone.
#[derive(Default)]
struct CgroupIndex {
    ids: HashMap<u64, (GuestKind, u32)>,
    built: Option<Instant>,
}

impl CgroupIndex {
    fn get(&mut self, id: u64) -> Option<(GuestKind, u32)> {
        if let Some(g) = self.ids.get(&id) {
            return Some(*g);
        }
        // New guests appear rarely: rebuild on a miss, at most once a second.
        if self
            .built
            .is_none_or(|t| t.elapsed() > Duration::from_secs(1))
        {
            self.rebuild();
            return self.ids.get(&id).copied();
        }
        None
    }

    fn rebuild(&mut self) {
        self.ids.clear();
        self.built = Some(Instant::now());
        let root = PathBuf::from("/sys/fs/cgroup");
        let mut dirs = vec![root.join("lxc"), root.join("qemu.slice")];
        while let Some(dir) = dirs.pop() {
            let Ok(meta) = std::fs::metadata(&dir) else {
                continue;
            };
            let rel = format!("/{}", dir.strip_prefix(&root).unwrap_or(&dir).display());
            if let Some(g) = guest::guest_of_cgroup(&rel) {
                self.ids.insert(meta.ino(), g);
            }
            if let Ok(entries) = std::fs::read_dir(&dir) {
                dirs.extend(
                    entries
                        .flatten()
                        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                        .map(|e| e.path()),
                );
            }
        }
    }
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn dest_ip(ev: &KEvent) -> Option<IpAddr> {
    match ev.af {
        af::INET => {
            let o = &ev.daddr;
            Some(Ipv4Addr::new(o[0], o[1], o[2], o[3]).into())
        }
        af::INET6 => Some(Ipv6Addr::from(ev.daddr).into()),
        _ => None,
    }
}

/// Loopback and `0.0.0.0` (health checks, local services): not reported.
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

fn to_event(ev: &KEvent, names: &Names, cgroups: &mut CgroupIndex) -> Option<Event> {
    let (gk, vmid) = watch::guest_of_pid(ev.pid).or_else(|| cgroups.get(ev.cgroup_id))?;
    let comm = cstr(&ev.comm);
    let (sev, k, msg) = match (ev.kind, gk) {
        (kind::EXEC, _) => {
            return watch::exec_in_guest(gk, vmid, ev.pid, &cstr(&ev.filename), names)
        }
        (kind::CONNECT, _) => {
            let ip = dest_ip(ev).filter(|ip| !is_local(*ip))?;
            let dst = SocketAddr::new(ip, ev.dport);
            match gk {
                GuestKind::Lxc => (Severity::Info, "connect", format!("connect {dst} ({comm})")),
                // QEMU listens (VNC, migration over a tunnel); it connects out
                // only for network storage (Ceph, iSCSI, NBD).
                GuestKind::Qemu => (
                    Severity::Warning,
                    "vm_cgroup_connect",
                    format!("process in the VM's QEMU cgroup connects to {dst} ({comm})"),
                ),
            }
        }
        (kind::FILE_WRITE, GuestKind::Lxc) => {
            if watch::is_lxc_hook(vmid, ev.pid) {
                return None;
            }
            let path = cstr(&ev.filename);
            (
                Severity::Warning,
                "file_write",
                format!("write {path} ({comm})"),
            )
        }
        (kind::FILE_WRITE, GuestKind::Qemu) => (
            Severity::Critical,
            "vm_cgroup_write",
            format!(
                "process in the VM's QEMU cgroup opened {} for writing (possible VM escape) ({comm})",
                cstr(&ev.filename)
            ),
        ),
        _ => return None,
    };
    let mut out = Event::new(sev, "ebpf", k, msg);
    out.guest = Some(watch::guest_ref(names, gk, vmid));
    out.fields.insert("pid".into(), ev.pid.to_string());
    out.fields.insert("uid".into(), ev.uid.to_string());
    out.fields.insert("comm".into(), comm);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_destinations() {
        assert!(is_local("127.0.0.1".parse().unwrap()));
        assert!(is_local("0.0.0.0".parse().unwrap()));
        assert!(is_local("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_local("192.168.16.1".parse().unwrap()));
        assert!(!is_local("2606:4700::1".parse().unwrap()));
    }
}
