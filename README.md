# virtsec

Runtime security CLI for **Proxmox VE** nodes: what runs in every LXC
container and VM, and which vulnerabilities touch code that is **actually
loaded**. Written in Rust. Runs as root on the node.

> **Early development.** Flags and output may change between releases.

- **LXC**: the container's live root (`/proc/<pid>/root`), OS packages
  (dpkg / apk / rpm), language lockfiles and Go binaries; each package tagged
  **loaded** (mapped by a process of the container) or **dormant**.
- **VMs**: through qemu-guest-agent. By default only the agent's OS info; with
  `--guest-exec`, two read-only commands run in the guest (`cat /proc/*/maps`,
  `tar` of the package databases) and the result is inventoried on the host.
- **The node**: the host's own packages, loaded by the host's processes (QEMU
  included). `pve-qemu-kvm`, `lxc-pve`, `lxcfs`, `pve-manager` are matched by
  upstream CPE; the running kernel only with `--match-kernel`.
- **Isolation risks** read from each guest's config: privileged containers,
  `nesting` / `keyctl` / `fuse` / `mount=`, host bind mounts, device
  passthrough, raw `lxc.*` keys, raw QEMU `args`, PCI / USB passthrough,
  hookscripts.
- Vulnerabilities are matched through [vuln.mlab.sh](https://vuln.mlab.sh)
  (API key optional: `$MLAB_API_KEY`).

## Usage

```bash
virtsec inventory                     # every guest + the node
virtsec inventory --kind lxc --sbom ./sbom
virtsec vulns --guest-exec --only-loaded
virtsec vulns --vmid 4001 -o json
```

Stopped guests are listed with their config risks, not inspected (nothing is
mounted or started).

## watch

One live stream, pretty or NDJSON (`-o json`):

- **exec**: every program started in a guest, attributed by cgroup. In an LXC
  each exec is reported (`WARN` when run from `/tmp`, `/dev/shm`, `/var/tmp` or
  deleted); LXC's own start hooks are not. In a VM's QEMU cgroup only QEMU and
  PVE's tap scripts may run: anything else is `CRIT`, a possible VM escape.
- **ebpf** (build with `--features ebpf`): exec straight from the kernel
  (short-lived processes included), outbound TCP connects (not loopback) and
  write-opens under `/etc/` (so `/etc/pve`), `/usr/bin/`, `/usr/sbin/`,
  `/root/`, `/boot/`. From QEMU's cgroup a connect is `WARN` (expected only with
  network storage: Ceph, iSCSI, NBD) and a sensitive write is `CRIT`. Without
  the feature, or if the probe can't load, exec comes from the proc connector.
- **pve**: API logins and authentication failures, PVE tasks, SSH logins and
  failures, from the journal of pvedaemon / pveproxy / sshd.
- **config**: guests created, removed, started, stopped; isolation risks added
  or removed, including changes waiting in `[pve:pending]` for the next start.

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

Known limits: without eBPF, a process that exits before virtsec reads
`/proc/<pid>` can't be attributed and is dropped; written paths are as the
process passed them (a relative path is not resolved); a guest booting floods
`info` with its init's execs.

## Build

```bash
cargo build --release                   # ./target/release/virtsec
cargo build --release --features rpm    # + RPM-based guests (bundles SQLite)
cargo build --release --features ebpf   # + the eBPF probe (Linux, Rust 1.91+, see below)
```

The eBPF probe needs a nightly with `rust-src` and `bpf-linker`; take its
prebuilt static binary (`cargo install` needs a system LLVM of the exact major
it was released for):

```bash
rustup toolchain install nightly --profile minimal --component rust-src
curl -fsSL https://github.com/aya-rs/bpf-linker/releases/download/v0.12.0/bpf-linker-$(uname -m)-unknown-linux-musl.tar.zst \
  | tar --zstd -x -C ~/.cargo/bin
```

The inventory code (rootfs resolver, package databases, reachability,
vuln.mlab.sh client) started as a copy of
[k3sec](https://github.com/mlab-sh/k3sec)'s `k3sec-inventory`; the two tools
are independent.
