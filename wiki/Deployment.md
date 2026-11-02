# Deployment

virtsec runs on each Proxmox VE node, as root: it reads guests' roots
(`/proc/<pid>/root`), the qemu-guest-agent sockets
(`/var/run/qemu-server/<vmid>.qga`), the journal, and loads the eBPF probe.

## Standalone

```bash
sudo apt install virtsec      # apt.mlab.sh, see the README's Install; /usr/bin/virtsec
virtsec inventory
virtsec watch --min-severity warning
```

## With an mlab workspace

One **mlab-agent** per node starts `virtsec serve` as its tool
([Tool API](Tool-API)). Everything is then driven from the workspace:
inventory, vulnerabilities, the live stream, and the config.

1. **Install** mlab-agent and virtsec on the node (apt.mlab.sh):

   ```bash
   sudo apt install mlab-agent virtsec
   ```

2. **Enrol** the node with a code from the workspace (Agents → Enrol an
   agent). A multi-node code enrols every node of a PVE cluster within 24 h:

   ```bash
   sudo mlab-agent enroll --server https://mlab.sh --code <code> \
     --expect-fingerprint <fingerprint> --label "$(hostname)"
   ```

3. **Write the policy**, `/etc/mlab-agent/policy.toml`. mlab drafts one
   (workspace → Agents → Policy); the admin of the node owns it, nothing remote
   can change it:

   ```toml
   enabled = true
   upload_hosts = ["<account>.eu.r2.cloudflarestorage.com"]   # from mlab's draft

   [tools.virtsec]
   path = "/usr/bin/virtsec"
   sha256 = "<mlab-agent tools hash /usr/bin/virtsec>"
   enabled = true
   allowed_ops = ["status", "configure", "events_since", "inventory", "sbom"]

   [tools.virtsec.settings]
   allow_ebpf = true
   allow_journal = true
   allow_config = true
   allow_inventory = true
   allow_guest_exec = false   # true lets mlab inspect VMs from the inside
   vmids = []                 # [] = every guest
   ```

   The `sha256` pins the binary: after a virtsec upgrade, update it
   (`mlab-agent tools hash /usr/bin/virtsec`) and restart the agent.

4. **Run the agent as root.** The `mlab-agent` package's unit runs the agent
   as the `mlab-agent` user with no capability and no netlink: virtsec would
   refuse to start (it reads guests' roots, `/etc/pve`, the guest agent
   sockets and the journal, and loads its eBPF probe). On a PVE node, add this
   drop-in, which keeps the rest of the unit's sandbox:

   ```bash
   sudo mkdir -p /etc/systemd/system/mlab-agent.service.d
   sudo tee /etc/systemd/system/mlab-agent.service.d/virtsec.conf >/dev/null <<'EOF'
   [Service]
   User=root
   Group=root
   CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_NET_ADMIN
   RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
   EOF
   sudo systemctl daemon-reload
   sudo systemctl enable --now mlab-agent
   sudo mlab-agent tools check     # virtsec  0.1.0  Running
   ```

   Enrol as root too (step 2): the agent's key is then root's, readable by
   the agent running as root.

The node appears in the workspace's Virtualization tab once its first
`status` reaches mlab.

## What the policy controls

| Setting | Default | Effect |
| --- | --- | --- |
| `allow_ebpf` | true | Kernel events: exec, connects, sensitive writes. |
| `allow_journal` | true | PVE API logins, auth failures, tasks, SSH. |
| `allow_config` | true | Guest config and state changes. |
| `allow_inventory` | true | Package inventory, hence vulnerabilities. |
| `allow_guest_exec` | **false** | Read-only commands in VMs through qemu-guest-agent (`cat /proc/*/maps`, `tar` of the package databases). Off: VMs report their OS only. |
| `vmids` | `[]` | Guests mlab may see; `[]` = all. |
| `backlog_events` | 50000 | Events held for `events_since` (memory). |

Unknown keys are refused at start (`init_failed: invalid
[tools.virtsec.settings]`).
