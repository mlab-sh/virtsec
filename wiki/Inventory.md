# inventory

```text
virtsec inventory [--vmid ID]... [--kind lxc|vm] [--no-host] [--guest-exec]
                  [--match-kernel] [--sbom DIR] [-o pretty|json]
```

Lists every guest configured on the node (`/etc/pve/lxc`,
`/etc/pve/qemu-server`) plus the node itself, with their packages and which of
them are loaded. Needs root.

```text
$ virtsec inventory --guest-exec
node pve  Debian GNU/Linux 13 (trixie)
  packages: 738 OS (215 loaded, 523 dormant), 0 language deps · 388 mapped files
  loaded: bash 5.2.37-2+b9, chrony 4.6.1-3+deb13u1, coreutils 9.7-3, ... libasound2t64 1.2.14-1 +203 more
cirsec-rel-deb12
  qemu 3012 stopped
cirsec-rel-ubu24  Ubuntu 24.04.5 LTS
  qemu 3024 running
  packages: 666 OS (100 loaded, 566 dormant), 0 language deps · 198 mapped files
  loaded: cron 3.0pl1-184ubuntu2, dash 0.5.12-6ubuntu5, dbus-daemon 1.14.10-4ubuntu4.1, ...
  ! language dependencies not inspected in VMs
vs-deb12  Debian GNU/Linux 12 (bookworm)
  lxc 4001 running
  packages: 268 OS (48 loaded, 220 dormant), 0 language deps · 63 mapped files
vs-alpine-priv  Alpine Linux v3.22
  lxc 4002 running  risks: privileged, nesting, mp0 host bind mount /var/log (ro)
  packages: 35 OS (7 loaded, 28 dormant), 0 language deps · 9 mapped files
  loaded: busybox 1.37.0-r18, libcrypto3 3.5.0-r0, libssl3 3.5.0-r0, musl 1.2.5-r10, nginx 1.28.3-r7, pcre2 10.46-r1, zlib 1.3.1-r2
cirsec-tpl-deb12
  qemu 9012 template
```

The pretty output lists at most 12 loaded packages per guest; `-o json` has
them all. Stopped guests and templates take one line: their
[risks](Guest-Risks) are read from the config, nothing else is inspected.

## Restart and reboot needed

An upgrade replaces a library on disk, but a process that mapped the old one
keeps running it: the kernel shows the old file as `(deleted)` in
`/proc/<pid>/maps`. virtsec reports, per guest and for the node, each package
whose replaced files are still mapped, and by which processes. Matching uses
the **installed** version, so a CVE fixed on disk but still running only shows
here.

```text
vs-deb12  Debian GNU/Linux 12 (bookworm)
  lxc 4001 running
  packages: 268 OS (48 loaded, 220 dormant), 0 language deps · 63 mapped files
  ! restart needed, old code still running: libssl3 (nginx[14823] nginx[14824] sshd[14811] systemd-journal[14690] +1)
```

(After `apt-get install --reinstall libssl3` in the container, nginx running.)
In VMs the packages are named, not the processes. A **reboot** is flagged when
the guest or the node has `/run/reboot-required` (Debian, Ubuntu), and on the
node when a kernel newer than the running one is in `/boot` and the running one
is not pinned (`proxmox-boot-tool kernel pin`). JSON: `restart: [{package,
processes}]`, `reboot`.

## Per guest type

### LXC

Same as a container on any host: virtsec finds the container's processes by
cgroup (`/lxc/<vmid>/...`), reads its live root through `/proc/<pid>/root`
(every path resolved in userspace, anchored at that root, so a hostile symlink
never reaches the host), and its mappings through `/proc/<pid>/maps`.

- OS packages: dpkg, apk, rpm (`rpmdb.sqlite`, build with `--features rpm`).
- Language dependencies: lockfiles (npm, yarn, Cargo, Go, Composer, Bundler,
  Poetry, `requirements.txt` pins) and the build info of running Go binaries.

### VM

A VM's memory and disks are opaque to the host. Without options, virtsec only
asks the guest agent for its OS (`guest-get-osinfo`):

```text
$ virtsec inventory --vmid 3024
cirsec-rel-ubu24  Ubuntu 24.04.5 LTS
  qemu 3024 running
  packages: 0 OS (0 loaded, 0 dormant), 0 language deps · 0 mapped files
  ! packages not inspected: guest exec is off (--guest-exec, or guest_exec in mlab; runs read-only commands in the VM via qemu-guest-agent)
```

With `--guest-exec`, two commands run in the VM through `guest-exec`:

1. `cat /proc/*/maps`, reduced in the guest to the unique file paths;
2. `tar -czf -` of `os-release`, the package databases (`/var/lib/dpkg/status`
   and `info/*.list`, `/lib/apk/db/installed`, `rpmdb.sqlite`) and the usrmerge
   links (`/bin`, `/lib`, ...).

The archive is unpacked on the host into a private temporary directory and
inventoried like a container root. It is treated as hostile: only regular
files and symlinks with plain relative paths are kept, no entry is written
through a symlink, nothing overwrites, and the directory is removed afterwards.

Requires `agent: enabled=1` in the VM's config and the agent running in the
guest. Windows guests: OS info only. Language dependencies are not inspected.

### The node

The host's own packages, loaded by the host's processes, **QEMU processes
included** (they live in each VM's cgroup but run the host's binaries). The
running kernel's package is loaded. These packages are matched by upstream CPE
rather than by Debian name:

| Package | CPE |
| --- | --- |
| `pve-qemu-kvm` | `cpe:2.3:a:qemu:qemu:<version>` |
| `lxc-pve` | `cpe:2.3:a:linuxcontainers:lxc:<version>` |
| `lxcfs` | `cpe:2.3:a:linuxcontainers:lxcfs:<version>` |
| `pve-manager` | `cpe:2.3:a:proxmox:virtual_environment:<version>` |
| running kernel | `cpe:2.3:o:linux:linux_kernel:<version>`, only with `--match-kernel` (NVD ignores PVE backports: noisy) |

`--no-host` skips the node; it is also skipped when `--vmid` or `--kind` is given.

## JSON

```json
{
  "guests": [
    {
      "name": "vs-alpine-priv",
      "os": { "id": "alpine", "pretty_name": "Alpine Linux v3.22", "version_id": "3.22.0" },
      "guest": {
        "kind": "lxc", "vmid": 4002, "name": "vs-alpine-priv", "status": "running",
        "risks": ["privileged", "nesting", "mp0 host bind mount /var/log (ro)"]
      },
      "mapped_files": 2,
      "packages": [
        {
          "kind": "os", "name": "acl-libs", "version": "2.3.2-r1", "source": "acl",
          "purl": "pkg:apk/alpine/acl-libs@2.3.2-r1?arch=x86_64&distro=alpine-3.22.0&upstream=acl",
          "reachability": "dormant"
        }
      ]
    }
  ]
}
```

The node has no `guest` field. `status` is `running`, `stopped` or `template`.
`--sbom DIR` writes one CycloneDX 1.5 JSON per guest, with `virtsec:reachability`
and `virtsec:kind` properties on each component.
