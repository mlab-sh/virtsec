# vulns

```text
virtsec vulns [inventory options] [--min-severity SEV] [--only-loaded] [--kev-only]
              [--mlab-url URL] [--no-cache]
```

[`inventory`](Inventory), then every package matched against
[vuln.mlab.sh](https://vuln.mlab.sh). Findings are sorted loaded first, KEV
first, then by severity.

```text
$ virtsec vulns --vmid 4002
116 vulns, 103 loaded (0 KEV loaded) across 1 guests

vs-alpine-priv  Alpine Linux v3.22
  lxc 4002 running  risks: privileged, nesting, mp0 host bind mount /var/log (ro)
  116 vulns, 103 loaded
  LOADED        CRIT  9.8  CVE-2026-31789     libcrypto3 3.5.0-r0  → 3.5.6-r0
  LOADED        CRIT  9.8  CVE-2026-31789     libssl3 3.5.0-r0  → 3.5.6-r0
  LOADED        CRIT  9.8  CVE-2026-63073     libcrypto3 3.5.0-r0  → 3.5.8-r0
  LOADED        CRIT  9.1  CVE-2026-34182     libcrypto3 3.5.0-r0  → 3.5.7-r0
  LOADED        HIGH  8.8  CVE-2025-15467     libssl3 3.5.0-r0  → 3.5.5-r0
  LOADED        HIGH  8.1  CVE-2026-40200     musl 1.2.5-r10  → 1.2.5-r12
  LOADED        HIGH  7.8  CVE-2026-22184     zlib 1.3.1-r2  → 1.3.2-r0
  ...
```

Columns: reachability, KEV (CISA / EU known exploited), severity, CVSS, id,
package and installed version, fixed version when the distro has one.

## Matching

- **OS packages** by distro ecosystem and *source* package (Debian, Ubuntu,
  Alpine, Rocky, Alma). Other distros are inventoried with a warning, not matched.
- **Language dependencies** by ecosystem coordinates (purl).
- **The PVE stack** by upstream CPE, see [Inventory](Inventory#the-node).
  On the lab (QEMU 11.0, LXC 7.0) no PVE-stack finding came back; whether the
  feed has nothing for those versions or does not resolve the CPEs is not
  established yet.

## Options

| Option | |
| --- | --- |
| `--only-loaded` | Hide findings in dormant packages. |
| `--kev-only` | Only known-exploited CVEs. |
| `--min-severity` | `unknown`, `low`, `medium`, `high`, `critical`. |
| `--mlab-url` | Another vuln.mlab.sh (on-prem mlab). `$MLAB_API_KEY` raises the rate limit. |
| `--no-cache` | Ignore cached results (`$XDG_CACHE_HOME/virtsec`, else `~/.cache/virtsec`). |

Guests have no image digest, so results are not cached per guest; only shared
data (the KEV catalogue) is.

## When the API is unavailable

virtsec retries (honouring `Retry-After` on 429), then prints the inventory
with `! vulnerability matching unavailable: ...` on every guest instead of
failing. Without an API key, a full node (hundreds of packages per guest) can
hit the anonymous rate limit: set `$MLAB_API_KEY`, or narrow with `--vmid` /
`--kind`.
