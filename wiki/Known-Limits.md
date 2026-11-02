# Known limits

What virtsec does **not** see yet.

## Inventory

- **Stopped guests are not inspected.** Inspecting them would mean mounting
  their disks; only their [risks](Guest-Risks) are shown.
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
- **The kernel** only with `--match-kernel`: NVD knows nothing of PVE's
  backports.
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
