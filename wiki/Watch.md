# watch

```text
virtsec watch [--min-severity info|warning|critical] [--no-exec] [--no-journal]
              [--poll SECS] [-o pretty|json]
```

One live stream of what happens on the node, one line per event (pretty) or
one JSON object per line (`-o json`). Runs until interrupted. Needs root.

```text
$ virtsec watch --min-severity warning
16:11:37  WARN  config  lxc/4001 vs-deb12  risk added: mp0 host bind mount /var/tmp
16:13:23  WARN  exec    lxc/4001 vs-deb12  /dev/shm/y  /dev/shm/y
16:13:35  WARN  pve     API authentication failure for nosuchuser@pve from ::ffff:127.0.0.1
16:38:46  WARN  ebpf    lxc/4001 vs-deb12  write /etc/virtsec-test (bash)
16:38:57  CRIT  ebpf    qemu/3024 cirsec-rel-ubu24  process in the VM's QEMU cgroup opened /etc/virtsec-escape-test for writing (possible VM escape) (bash)
16:38:57  WARN  ebpf    qemu/3024 cirsec-rel-ubu24  process in the VM's QEMU cgroup connects to 1.1.1.1:80 (bash)
16:38:57  CRIT  exec    qemu/3024 cirsec-rel-ubu24  program run in the VM's QEMU cgroup (possible VM escape): /bin/true  /bin/true
```

## Sources

### exec

Every program started in a guest, attributed by cgroup. From the
[eBPF probe](eBPF-Probe) when the binary has it, else from the kernel's proc
connector (netlink, no extra toolchain; a process that exits before its
`/proc` entry is read is lost).

- **In an LXC**: every exec, `info`; `warning` when the binary runs from
  `/tmp/`, `/dev/shm/`, `/var/tmp/` or was deleted. LXC's own start/stop
  hooks (lxcfs mounts, autodev) run in the container's cgroup but on the
  host's root: they are not reported.
- **In a VM's QEMU cgroup** (`/qemu.slice/<vmid>.scope`): only QEMU itself and
  PVE's tap scripts (`pve-bridge`) ever run there. Anything else is
  `critical`, a possible VM escape.

Host processes are not reported.

### ebpf

With the [eBPF probe](eBPF-Probe): outbound TCP connects (loopback and
`0.0.0.0` dropped) and write-opens under `/etc/` (so `/etc/pve`),
`/usr/bin/`, `/usr/sbin/`, `/root/`, `/boot/`.

| Where | connect | sensitive write |
| --- | --- | --- |
| LXC | `info` | `warning` |
| VM's QEMU cgroup | `warning` (expected only with network storage: Ceph, iSCSI, NBD) | `critical` |

### pve

Followed from the journal of `pvedaemon`, `pveproxy` and `sshd`:

| kind | severity | from |
| --- | --- | --- |
| `auth_failure` | warning | `authentication failure; rhost=... user=...` (API / web UI) |
| `login` | info | `successful auth for user '...'` |
| `task` | info | `starting task UPID:...` (start, stop, backup, console, ...), with its guest |
| `ssh_login` | info | sshd `Accepted ...` |
| `ssh_failure` | warning | sshd `Failed ...`, `Invalid user ...` |

### config

The guest configs and cgroups are read every `--poll` seconds (2 by default;
pmxcfs has no inotify):

| kind | severity |
| --- | --- |
| `guest_created` | info, warning when it has [risks](Guest-Risks) |
| `guest_removed` | info |
| `started`, `stopped` | info |
| `risk_added` | warning |
| `risk_removed` | info |

## JSON

```json
{"time":"2026-11-02T15:44:26.892657421Z","severity":"warning","source":"ebpf","kind":"file_write","guest":{"kind":"lxc","vmid":4001,"name":"vs-deb12"},"message":"write /etc/virtsec-doc (sh)","fields":{"comm":"sh","pid":"28292","uid":"100000"}}
```

| Field | |
| --- | --- |
| `time` | UTC, RFC 3339 (pretty output shows local time). |
| `severity` | `info`, `warning`, `critical`. |
| `source` | `exec`, `ebpf`, `pve`, `config`. |
| `kind` | See the tables above; exec events are `exec` or `vm_cgroup_exec`, eBPF ones `connect`, `vm_cgroup_connect`, `file_write`, `vm_cgroup_write`. |
| `guest` | `{kind, vmid, name}`, absent for node-level events (API logins). |
| `fields` | Strings: `pid`, `ppid`, `uid` (host uid: `100000` is root in an unprivileged LXC), `comm`, `user`, `rhost`, `task`, `vmid`. |

## Noise

A guest booting floods `info` with its init's execs (an Alpine start: ~110
lines). `--min-severity warning` keeps what matters.
