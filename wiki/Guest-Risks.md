# Guest risks

Read from each guest's current config (`/etc/pve/lxc/<vmid>.conf`,
`/etc/pve/qemu-server/<vmid>.conf`), snapshot sections excluded. Shown on the
guest line of [`inventory`](Inventory) / [`vulns`](Vulns) and in `guest.risks`
in JSON; [`watch`](Watch) reports every risk added or removed.

## LXC

| Config | Risk shown | Why |
| --- | --- | --- |
| `unprivileged` absent or `0` | `privileged` | Container root is host root: an escape is a host compromise. |
| `features: nesting=1` | `nesting` | Exposes `/proc` and `/sys` more, needed for Docker or systemd in the container. |
| `features: keyctl=1` | `keyctl` | The container uses the kernel keyring. |
| `features: fuse=1` | `fuse` | FUSE device in the container. |
| `features: mount=nfs;cifs` | `mount=nfs;cifs` | The container may mount those filesystems itself. |
| `mpN: /host/path,...` | `mpN host bind mount /host/path` (`(ro)` if read-only) | A host directory inside the guest. Storage volumes (`storage:vol`) are not flagged. |
| `devN: /dev/...` | `devN host device /dev/...` | Host device passthrough. |
| `lxc.apparmor.profile: unconfined` | `apparmor unconfined` | No AppArmor confinement. |
| `lxc.cap.drop:` (empty) | `no capabilities dropped` | Keeps every capability. |
| any other `lxc.*` key | `raw lxc.<key>` | Raw LXC config bypasses PVE's checks (`lxc.mount.entry`, `lxc.cgroup2.devices.allow`, ...). |

## VM

| Config | Risk shown | Why |
| --- | --- | --- |
| `args:` | `raw QEMU args` | Arbitrary QEMU command line, outside PVE's checks. |
| `hostpciN:` | `hostpciN PCI passthrough` | The guest drives a host PCI device (DMA). |
| `usbN:` (not `spice`) | `usbN USB passthrough` | Host USB device. |
| `serialN:` / `parallelN:` on `/dev/...` | `serialN host device /dev/...` | Host character device. |

## Both

| Config | Risk shown |
| --- | --- |
| `hookscript:` | `hookscript <volume>`: a script PVE runs on the host at each start / stop. |

## Pending changes

A change made while the guest runs often lands in the config's
`[pve:pending]` section and applies at the next start. A risk that only exists
there is shown with `(pending restart)`:

```text
16:11:33  info  config  lxc/4001 vs-deb12  risk removed: nesting (pending restart)
```

A pending *removal* (`delete: mp0`) keeps the risk shown until the restart: the
bind mount is still there until then.
