# virtsec

**Runtime security for Proxmox VE nodes, in one Rust binary.**

virtsec runs as root on a PVE node and tells you what runs in every LXC
container and VM, which vulnerabilities touch code that is **actually loaded**,
and what happens on the node, live.

- **Inventory** of every guest and of the node itself: OS packages (dpkg / apk
  / rpm), language lockfiles and Go binaries (LXC), each tagged **loaded**
  (mapped by a process) or **dormant**.
- **VMs from the inside**, through qemu-guest-agent, opt-in (`--guest-exec`).
- **Vulnerabilities** matched through [vuln.mlab.sh](https://vuln.mlab.sh),
  loaded first; the PVE stack (QEMU, LXC) by upstream CPE.
- **Isolation risks** read from every guest's config: privileged containers,
  host bind mounts, passthrough, raw `lxc.*` / QEMU `args`, hookscripts.
- **A live stream**: execs in guests, outbound connects and sensitive writes
  (eBPF), PVE logins and tasks, guest config changes, and anything run from a
  VM's QEMU cgroup (a possible VM escape).

```text
$ virtsec vulns --vmid 4002
116 vulns, 103 loaded (0 KEV loaded) across 1 guests

vs-alpine-priv  Alpine Linux v3.22
  lxc 4002 running  risks: privileged, nesting, mp0 host bind mount /var/log (ro)
  116 vulns, 103 loaded
  LOADED        CRIT  9.8  CVE-2026-31789     libcrypto3 3.5.0-r0  → 3.5.6-r0
  LOADED        CRIT  9.8  CVE-2026-31789     libssl3 3.5.0-r0  → 3.5.6-r0
  LOADED        HIGH  8.1  CVE-2026-40200     musl 1.2.5-r10  → 1.2.5-r12
  ...
```

> **Early development.** Flags and output may change. Every output in this
> wiki was captured on the lab described in [Development](Development#test-lab).

## Compatibility

| | Status |
| --- | --- |
| **Proxmox VE 9.2** (Debian 13, kernel 7.0.2-pve) | Tested: `inventory`, `vulns`, `watch`, eBPF probe. |
| Proxmox VE 7.x / 8.x | Expected to work (cgroup v2 layout unchanged since 7.0), not tested. |
| LXC guests | Debian 12 and Alpine 3.22 tested, privileged and unprivileged. |
| VM guests | Ubuntu 24.04 with qemu-guest-agent tested. Windows guests: OS info only. |
| Clusters | One virtsec per node: it sees the guests running on its own node. |

## Commands

| Command | What it does |
| --- | --- |
| [`inventory`](Inventory) | Packages of every guest and of the node, loaded / dormant, `--sbom` CycloneDX per guest. |
| [`vulns`](Vulns) | Inventory + CVE matching, loaded and KEV first, filters for triage. |
| [`watch`](Watch) | Live stream: exec / connect / file writes in guests, PVE journal, config changes. |

## Key concepts

- **Loaded vs dormant**: a package is *loaded* when one of its files is mapped
  by a process of the guest (`/proc/<pid>/maps`), *dormant* otherwise. A CVE in
  a dormant package needs a restart or a new process to be reachable.
- **LXC vs VM**: an LXC shares the host kernel, so virtsec reads it like any
  container, through `/proc/<pid>/root`. A VM is opaque to the host: virtsec
  asks its guest agent, only when told to.
- **Nothing is changed.** virtsec never starts, stops, mounts or reconfigures a
  guest. `--guest-exec` runs two read-only commands in the VM, nothing else.
