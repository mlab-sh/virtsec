# Development

## Layout

```text
src/
  main.rs       CLI (clap): inventory, vulns, watch, serve
  guest.rs      guests from /etc/pve, config risks, cgroup → guest
  inventory.rs  LXC (live root), VM (guest agent), node (host + PVE CPEs)
  qga.rs        qemu-guest-agent client, hostile-archive unpacking
  watch.rs      event stream: proc connector exec, journal, config poll
  probe.rs      eBPF loader and attribution (feature `ebpf`)
  serve.rs      `virtsec serve`: mlab-agent tool (ops, config clamp, inventory loop)
  protocol.rs stream.rs   agent local protocol, numbered batches + backlog
  rootfs.rs pkgdb/ lang/ reach.rs procfs.rs os.rs purl.rs   inventory core
  vuln.rs mlab.rs cache.rs render.rs sbom.rs                matching and output
crates/
  virtsec-api/           the mlab-agent tool contract v1 (CBOR), imported by mlab
  virtsec-probe-common/  repr(C) event shared by kernel and userspace (no_std)
  virtsec-probe-ebpf/    the BPF programs (BPF target only, built by build.rs)
```

The inventory core, matching and output started as a copy of
[k3sec](https://github.com/mlab-sh/k3sec)'s `k3sec-inventory`, the probe as a
copy of its eBPF crates. Nothing is shared at build time: the tools are
independent.

## Build

```bash
cargo build --release                   # ./target/release/virtsec
cargo build --release --features rpm    # + RPM-based guests (bundles SQLite)
cargo test                              # unit tests, any OS
```

The binary runs on Linux only; it builds and its tests run on macOS too
(the eBPF and proc connector code is Linux-gated).

### eBPF

`--features ebpf` needs Linux, Rust 1.91+ (aya-build's dependencies), a
nightly with `rust-src`, and `bpf-linker`. Take bpf-linker's prebuilt static
binary: `cargo install` needs a system LLVM of the exact major it was released
for.

```bash
rustup toolchain install nightly --profile minimal --component rust-src
curl -fsSL https://github.com/aya-rs/bpf-linker/releases/download/v0.12.0/bpf-linker-$(uname -m)-unknown-linux-musl.tar.zst \
  | tar --zstd -x -C ~/.cargo/bin
cargo build --release --features ebpf
```

From a Mac (Apple silicon), cross-building for an x86_64 node in Docker:

```dockerfile
FROM rust:1.95-bookworm
RUN apt-get -qq update && apt-get -qq install -y gcc-x86-64-linux-gnu zstd \
 && rustup component add clippy && rustup target add x86_64-unknown-linux-gnu \
 && rustup toolchain install nightly --profile minimal --component rust-src \
 && curl -fsSL https://github.com/aya-rs/bpf-linker/releases/download/v0.12.0/bpf-linker-$(uname -m)-unknown-linux-musl.tar.zst \
    | tar --zstd -x -C /usr/local/cargo/bin
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc
```

```bash
docker build -t virtsec-build:ebpf - < Dockerfile
docker run --rm -v "$PWD":/src -w /src virtsec-build:ebpf \
  cargo build --release --features ebpf --target x86_64-unknown-linux-gnu
```

## Test lab

Every output in this wiki comes from a single PVE node:

- Proxmox VE 9.2.2, Debian 13, kernel 7.0.2-6-pve, 2 cores, 15 GB.
- **LXC 4001** `vs-deb12`: Debian 12, unprivileged, nginx.
- **LXC 4002** `vs-alpine-priv`: Alpine 3.22, privileged, `nesting=1`, host
  bind mount `mp0: /var/log,mp=/mnt/hostlog,ro=1`, nginx.
- **VM 3024** `cirsec-rel-ubu24`: Ubuntu 24.04 cloud image, qemu-guest-agent,
  snapshot `clean`.
- 22 more VMs stopped or templates.

The containers, from the node:

```bash
pct create 4001 local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst --hostname vs-deb12 \
  --unprivileged 1 --memory 512 --rootfs local-lvm:3 --net0 name=eth0,bridge=vmbr0,ip=dhcp
pct create 4002 local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz --hostname vs-alpine-priv \
  --unprivileged 0 --features nesting=1 --memory 256 --rootfs local-lvm:1 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp --mp0 /var/log,mp=/mnt/hostlog,ro=1
```

A VM escape is simulated, harmlessly, by moving a shell into a VM's QEMU
cgroup and acting from there:

```bash
bash -c 'echo $$ > /sys/fs/cgroup/qemu.slice/3024.scope/cgroup.procs; echo x > /etc/virtsec-escape-test; exec /bin/true'
rm -f /etc/virtsec-escape-test
```

### What the lab caught

- QEMU processes sit in their VM's cgroup: the node first showed
  `pve-qemu-kvm` dormant while VMs ran. They now count as host processes.
- LXC start hooks run in the container's cgroup: a restart printed 328 hook
  execs. Hooks are now told apart by their root (the host's), and the
  container's state when the process is already gone.
- `pct set` on a running container writes to `[pve:pending]`: a `nesting=1`
  added that way was missed. Pending risks are now shown.
