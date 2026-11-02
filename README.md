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

## Build

```bash
cargo build --release                   # ./target/release/virtsec
cargo build --release --features rpm    # + RPM-based guests (bundles SQLite)
```

The inventory code (rootfs resolver, package databases, reachability,
vuln.mlab.sh client) started as a copy of
[k3sec](https://github.com/mlab-sh/k3sec)'s `k3sec-inventory`; the two tools
are independent.
