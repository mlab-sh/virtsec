# audit

```text
virtsec audit [--vmid ID]... [--kind lxc|vm] [--no-host] [--guest-exec]
              [--fail-on info|warning|critical] [-o pretty|json]
```

The security posture of the node and its guests, read from their
configuration: what an admin set, or forgot to set. CVEs are
[`vulns`](Vulns)' job. Needs root; changes nothing.

```text
$ virtsec audit
9 checks failed: 2 critical, 5 warning, 2 info

node
  CRIT  no second factor: mcp@pve, root@pam
        fix: Datacenter → Permissions → Two Factor: add TOTP or WebAuthn (root@pam first)
  WARN  datacenter firewall is off: neither the node nor any guest is filtered by PVE
        fix: Datacenter → Firewall → Options → Firewall: Yes (allow 8006 and 22 from the admin network first)
  WARN  SSH accepts root logins with a password
        fix: PermitRootLogin prohibit-password in sshd_config (a PVE cluster only needs root's key)
  WARN  https://enterprise.proxmox.com/debian/pve is enabled but never fetched (no subscription?): no updates from it
        fix: add a subscription key, or replace it with the no-subscription repository
  info  web UI and API (8006) accept connections from every address
        fix: ALLOW_FROM="<admin network>" and DENY_FROM="all" in /etc/default/pveproxy, or a firewall rule

vs-alpine-priv (lxc 4002)
  CRIT  isolation risk: nesting
  WARN  isolation risk: privileged
  info  isolation risk: mp0 host bind mount /var/log (ro)
```

`--fail-on SEVERITY` exits with status **3** when a check at or above it
fails (for a cron or CI); errors exit 1.

## Checks

| id | Severity | Read from | Fails when |
| --- | --- | --- | --- |
| `firewall.datacenter` | warning | `/etc/pve/firewall/cluster.fw` | `[OPTIONS] enable: 1` is missing: nothing is filtered. |
| `firewall.node` | warning | `/etc/pve/nodes/<node>/host.fw` | `enable: 0` while the datacenter firewall is on. |
| `firewall.guest` | warning | `/etc/pve/firewall/<vmid>.fw`, `netN` | Datacenter firewall on, but the guest's is off, or a NIC lacks `firewall=1`. |
| `users.no_second_factor` | critical for `root@pam`, else warning | `user.cfg`, `priv/tfa.cfg`, `domains.cfg` | An enabled user has no TOTP / WebAuthn / U2F / Yubico factor and its realm enforces none. Only *which users* have a factor is read, never the factors. |
| `users.token_privsep` | warning | `user.cfg` | An API token has privilege separation off: it can do all its user can. `priv/token.cfg` (the secrets) is not read. |
| `ssh.root_password` / `ssh.password` | warning / info | `sshd -T` | Root may log in with a password / anyone may. |
| `webui.open` | info | `/etc/default/pveproxy` | No `ALLOW_FROM` nor `LISTEN_IP`. |
| `apt.test_repo` | warning | APT sources (`.list`, `.sources`) | `pve-test` / `pvetest` enabled. |
| `apt.no_subscription` | info | APT sources | `pve-no-subscription` enabled. |
| `apt.enterprise_unreachable` | warning | APT sources, `/var/lib/apt/lists` | An `enterprise.proxmox.com` repo is enabled but its index was never fetched: without a subscription `apt update` fails on it, and PVE (or Ceph) updates silently stop. |
| `apt.stale` | warning | `/var/lib/apt/lists/*Release` | Newest list older than 7 days. |
| `corosync.unencrypted` | warning | `/etc/pve/corosync.conf` | `crypto_cipher: none` or `secauth: off`. |
| `restart_needed` | warning | inventory | [Old code still mapped](Inventory#restart-and-reboot-needed) after an upgrade. |
| `reboot_needed` | warning | inventory | `/run/reboot-required`, or a newer kernel than the running one. |
| `guest.risk` | see below | guest config | Each [isolation risk](Guest-Risks). |

A risk is **critical** when the container is privileged and also has a way
out: nesting, AppArmor unconfined, no capabilities dropped, or a writable host
bind mount. Privileged alone, raw `lxc.*` / QEMU `args`, hookscripts, host
devices and passthrough are **warnings**; the rest (read-only bind mounts,
keyctl, fuse, mount) **info**.

## JSON

`{"checks": [{id, severity, guest?: {kind, vmid, name}, message, fix?}]}`,
node checks first, then by vmid, most severe first.
