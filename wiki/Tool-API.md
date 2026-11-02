# Tool API (mlab-agent)

With an [mlab](https://mlab.sh) workspace, `virtsec serve` runs as a tool of
**mlab-agent** on each PVE node: the agent owns the workspace identity and the
only outbound connection, virtsec has no key and talks to nothing. See
[Deployment](Deployment) to set it up.

The contract is the `virtsec-api` crate (`crates/virtsec-api`): op names,
CBOR arguments and answers, events, and the frozen v1 wire schema. It depends
on nothing of virtsec, so mlab imports it alone. Every struct refuses unknown
fields; adding one is a new `API_VERSION`. Golden files
(`crates/virtsec-api/tests/golden/*.hex`) freeze the v1 bytes.

## Local protocol

mlab-agent's tool protocol v1: a big-endian `u32` length, then one CBOR map
tagged by `t` (`init`, `call`, `shutdown` from the agent; `ready`,
`init_failed`, `result`, `failure`, `event` from the tool). Implemented in
`src/protocol.rs` from the spec. The agent:

1. checks the binary's pinned `sha256`, then starts `virtsec serve` in
   `<agent config>/tools/virtsec` with an empty environment;
2. sends `init` with `[tools.virtsec.settings]`; virtsec answers `ready`
   (name `virtsec`, its version, the 5 ops) or `init_failed` (bad settings,
   not root, not a PVE node);
3. sends one `call` at a time; events virtsec emits are read **only while a
   call is served**, so batches wait in virtsec's backlog until the next call.

## Ops

| op | args | answer |
| --- | --- | --- |
| `status` | none | `Status` |
| `configure` | `Config` | `Configured {config, clamped}`: the config in force, and what the policy cut |
| `events_since` | `EventsSince {boot_id, after_seq}` | `Backlog {boot_id, batches (≤ 1), oldest_seq, last_seq}` |
| `inventory` | `InventoryRequest {vmid?}`, needs an upload | blob: CBOR `Inventory`; body `InventoryInfo {guests, packages}` |
| `sbom` | `SbomRequest {vmid?}` (none = the node), needs an upload | blob: CycloneDX 1.5 JSON; body `SbomInfo {vmid, components}` |

Errors use the agent's codes: `bad_request` (bad arguments, no upload target),
`not_found` (no such guest inventoried), `unknown_op`, `internal`.

## Events

| name | body | when |
| --- | --- | --- |
| `batch` | `Batch {api_version, boot_id, seq, node, events, dropped, urgent}` | every 2 s with events, at once with a critical one (`urgent`) |
| `status` | `Status` | 10 s after start, then every minute, and after `configure` |
| `inventory_ready` | `InventoryReady {vmid?, name, packages, loaded}` | a guest or the node was inventoried and changed |

`seq` grows by one per batch within a `boot_id` (one process). A gap is
recovered with `events_since`; a new `boot_id` means the previous process's
undelivered batches are gone. The backlog holds `backlog_events` events (at
most 32 MiB). Batches are at most 768 KiB and 2000 events.

### SecEvent

| Field | |
| --- | --- |
| `source` | `exec`, `ebpf`, `pve`, `config` |
| `timestamp` | Unix ms, UTC |
| `kind` | see [Watch](Watch) |
| `severity` | `info`, `warning`, `critical` |
| `guest` | `{kind: lxc\|qemu, vmid, name}`, null for node-level events |
| `message` | text |
| `metadata` | flat strings: `pid`, `ppid`, `uid`, `comm`, `user`, `rhost`, `task`, `vmid`, `dest` |
| `payload` | `{"dest": "ip:port"}` on connects, else null |

## Config and policy

mlab chooses a `Config`; the host admin's policy (`Settings`) is its ceiling,
and `configure` answers what it cut.

```text
Config   { sources {ebpf, journal, config, inventory}, kinds, vmids, min_severity, guest_exec }
Settings { allow_ebpf, allow_journal, allow_config, allow_inventory,   (default true)
           allow_guest_exec,                                           (default false)
           vmids, backlog_events }                                     ([] = all, 50000)
```

- A source turned on by mlab but not allowed is turned off.
- `guest_exec` (read-only commands in VMs through qemu-guest-agent) needs
  `allow_guest_exec = true` in the policy.
- `vmids` outside the policy's list are cut; an empty list means every guest
  the policy allows.
- `kinds` other than `exec`, `connect`, `file_write` are dropped.

The config is saved in the tool's work dir (`config.cbor`) and re-clamped
against the current policy at every start.

## Inventory

`Inventory {format: "virtsec-inventory", api_version, generated_at, node,
cluster_id, node_info {pve_version, kernel, os}, guests}`. Each entry is a
`GuestInventory {guest {kind, vmid, name, status, risks}?, name, os, packages,
mapped_files, warnings}`; the node has no `guest`. Packages carry their
`purl`, `reachability` and a vuln.mlab.sh `coordinate` (ecosystem / purl /
CPE): mlab matches them itself.

virtsec inventories at start, every hour, when a guest starts and after
`configure`, and announces what changed with `inventory_ready`.

`cluster_id` is the PVE cluster name (`cluster_name` in `corosync.conf`), the
node name on a standalone node: mlab groups nodes by it.
