# Known limits

What virtsec does **not** see yet.

## Inventory

- **Stopped guests on block volumes are not inspected.** A stopped container
  or template whose root is a directory (ZFS subvolume, `dir` storage created
  with size 0) is read in place; on LVM, raw images or Ceph it would need a
  mount, and stopped VMs a disk mount too: only their
  [risks](Guest-Risks) are shown.
- **VMs need the guest agent** and `--guest-exec`. No agent: OS unknown, no
  packages. Windows: OS info only. Language dependencies are never inspected
  in VMs.
- **Interpreted daemons look dormant.** Loaded means *mapped in memory*: a
  Perl or Python program's own files are read, not mapped. On the node,
  `pve-manager` shows dormant while `pvedaemon` runs; its interpreter
  (`perl-base`) is loaded.
- **A snapshot.** `/proc/<pid>/maps` is read once per run: a library loaded
  later is seen at the next run.
- **Package granularity.** A loaded `libssl3` makes all its CVEs "loaded",
  including ones in functions nothing calls.
- **One node.** Only guests running on this node: one virtsec per node.

## Matching

- **The PVE stack** is matched by upstream CPE; on the lab no finding came
  back for QEMU 11.0 / LXC 7.0, not yet established as "none exist".
- **The kernel** only with `--match-kernel`, by its upstream version against
  NVD, which knows nothing of PVE's backports: on the lab, 6,109 CVEs for
  `7.0.2-6-pve`, nearly all 2026 kernel-CNA ones without a fixed version. The
  CVEs the kernel's own changelog names as fixed are dropped (8 there, none of
  them among the matches) and the node says which Ubuntu kernel it is built
  from (`Ubuntu-7.0.0-18.18`). Matching that Ubuntu source instead would know
  the backports, but vuln.mlab.sh times out (504) on Ubuntu's `linux` today.
- **API limits.** A full node without `$MLAB_API_KEY` can hit the anonymous
  rate limit; an unavailable API leaves the inventory, flagged per guest.

## watch

- **Without eBPF**, a process that exits before its `/proc` entry is read is
  lost (the proc connector gives the PID only).
- **Written paths are as passed** to `open()`: a relative path is not resolved
  against the process's working directory.
- **No UDP**, no listening sockets, no file reads; writes outside the
  sensitive prefixes are not reported.
- **Boot noise**: a guest starting floods `info` with its init's execs.
- **Config changes are polled** (every 2 s): two changes inside one poll
  interval show as one diff.
