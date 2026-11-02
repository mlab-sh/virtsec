# eBPF probe

Kernel events for [`watch`](Watch), built in with `--features ebpf`. The
programs started as a copy of [k3sec](https://github.com/mlab-sh/k3sec)'s
probe; the two tools are independent.

| Program | Hook | Event |
| --- | --- | --- |
| `virtsec_execve` | tracepoint `sched:sched_process_exec` | every successful exec |
| `virtsec_tcp_v4_connect` / `_v6_` | kprobes `tcp_v4_connect`, `tcp_v6_connect` | destination ip:port |
| `virtsec_openat` | kprobe `do_sys_openat2` | write-opens (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_APPEND`) under `/etc/`, `/usr/bin/`, `/usr/sbin/`, `/root/`, `/boot/`, filtered in the kernel |

Records go through a 256 KiB ring buffer. A full buffer drops records in the
kernel, it never blocks the traced process.

## Attribution

Each record carries a PID and the kernel cgroup id. A live process is
attributed by `/proc/<pid>/cgroup`; one already gone (a short exec) by its
cgroup id, the inode of its cgroup directory under `/sys/fs/cgroup/lxc` or
`/sys/fs/cgroup/qemu.slice`, re-indexed on a miss at most once a second.
Host processes are dropped.

LXC hooks run in the container's cgroup before `pivot_root`. A live process on
the host's root is a hook; for one already gone, the container is judged
instead: no process there on its own root yet means it is starting.

## Fallback

If the probe cannot load (not root, no tracefs, an
attachment refused), `watch` logs the reason and takes exec events from the
proc connector. If only `do_sys_openat2` cannot be attached (inlined on some
kernels), file writes are off and the rest goes on.

## Build

See [Development](Development#ebpf).
