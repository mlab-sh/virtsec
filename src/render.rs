//! Pretty and JSON reports for `virtsec inventory` / `virtsec vulns`.

use std::fmt::Write;

use owo_colors::OwoColorize;
use serde_json::json;

use crate::model::{Inventory, PackageKind, Reachability};
use crate::vuln::{Finding, VulnSeverity, Vulns};

/// Which findings to show (`--min-severity`, `--only-loaded`, `--kev-only`).
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub min_severity: Option<VulnSeverity>,
    pub only_loaded: bool,
    pub kev_only: bool,
}

impl Filter {
    pub fn keeps(&self, f: &Finding) -> bool {
        self.min_severity.is_none_or(|m| f.severity >= m)
            && (!self.only_loaded || f.reachability == Reachability::Loaded)
            && (!self.kev_only || f.is_kev())
    }
}

/// Paint `s` only when `on` (pretty output on a TTY).
fn paint(on: bool, s: &str, f: impl Fn(&str) -> String) -> String {
    if on {
        f(s)
    } else {
        s.to_string()
    }
}

fn image_title(inv: &Inventory, color: bool) -> String {
    let digest = inv
        .digest
        .as_deref()
        .map(|d| format!(" ({})", d.chars().take(19).collect::<String>()))
        .unwrap_or_default();
    let os = inv
        .os
        .as_ref()
        .map(|o| {
            format!(
                "  {}",
                if o.pretty_name.is_empty() {
                    &o.id
                } else {
                    &o.pretty_name
                }
            )
        })
        .unwrap_or_default();
    format!(
        "{}{digest}{os}",
        paint(color, &inv.name, |s| s.bold().to_string())
    )
}

/// `lxc 4001 running · unprivileged · ! privileged, nesting`
fn guest_line(inv: &Inventory, color: bool) -> Option<String> {
    let g = inv.guest.as_ref()?;
    let mut s = format!("{} {} {}", g.kind.as_str(), g.vmid, g.status);
    if !g.risks.is_empty() {
        let _ = write!(
            s,
            "  {} {}",
            paint(color, "risks:", |s| s.yellow().to_string()),
            g.risks.join(", ")
        );
    }
    Some(s)
}

/// Loaded packages listed per guest in pretty output.
const MAX_LOADED_SHOWN: usize = 12;

pub fn inventory_pretty(invs: &[Inventory], color: bool) -> String {
    let mut out = String::new();
    if invs.is_empty() {
        out.push_str("no guests on this node\n");
    }
    for inv in invs {
        let os = inv
            .packages
            .iter()
            .filter(|p| p.kind == PackageKind::Os)
            .count();
        let lang = inv
            .packages
            .iter()
            .filter(|p| p.kind == PackageKind::Lang)
            .count();
        let _ = writeln!(out, "{}", image_title(inv, color));
        if let Some(g) = guest_line(inv, color) {
            let _ = writeln!(out, "  {g}");
        }
        if inv.guest.as_ref().is_some_and(|g| g.status != "running") {
            continue; // nothing inspected: the config risks are all there is
        }
        let _ = writeln!(
            out,
            "  packages: {os} OS ({} loaded, {} dormant), {lang} language deps · {} mapped files",
            inv.count(Reachability::Loaded),
            inv.count(Reachability::Dormant),
            inv.mapped_files
        );
        let mut loaded: Vec<String> = inv
            .packages
            .iter()
            .filter(|p| p.reachability == Reachability::Loaded)
            .map(|p| format!("{} {}", p.name, p.version))
            .collect();
        if !loaded.is_empty() {
            // The full list is in `-o json`; a node maps hundreds of packages.
            let extra = loaded.len().saturating_sub(MAX_LOADED_SHOWN);
            loaded.truncate(MAX_LOADED_SHOWN);
            let more = if extra > 0 {
                format!(" +{extra} more")
            } else {
                String::new()
            };
            let _ = writeln!(out, "  loaded: {}{more}", loaded.join(", "));
        }
        for w in &inv.warnings {
            let _ = writeln!(
                out,
                "  {} {w}",
                paint(color, "!", |s| s.yellow().to_string())
            );
        }
        out.push('\n');
    }
    out
}

pub fn inventory_json(invs: &[Inventory]) -> serde_json::Value {
    json!({ "guests": invs })
}

fn finding_line(f: &Finding, color: bool) -> String {
    let reach = match f.reachability {
        Reachability::Loaded => paint(color, "LOADED ", |s| s.red().bold().to_string()),
        Reachability::Dormant => paint(color, "dormant", |s| s.dimmed().to_string()),
        Reachability::Unknown => "unknown".to_string(),
    };
    let kev = match f.kev {
        Some(true) => paint(color, "KEV", |s| s.red().bold().to_string()),
        Some(false) => "   ".to_string(),
        None => "?  ".to_string(),
    };
    let sev = format!("{:<4}", f.severity.label());
    let sev = match f.severity {
        VulnSeverity::Critical | VulnSeverity::High => paint(color, &sev, |s| s.red().to_string()),
        VulnSeverity::Medium => paint(color, &sev, |s| s.yellow().to_string()),
        _ => sev,
    };
    let cvss = f
        .cvss
        .map(|c| format!("{c:>4.1}"))
        .unwrap_or_else(|| "   -".into());
    let fixed = f
        .fixed
        .as_deref()
        .map(|v| format!("  → {v}"))
        .unwrap_or_default();
    format!(
        "  {reach}  {kev}  {sev} {cvss}  {:<18} {} {}{fixed}",
        f.id, f.package, f.version
    )
}

fn kept<'a>(v: &'a Vulns, filter: &'a Filter) -> impl Iterator<Item = &'a Finding> {
    v.findings.iter().filter(|f| filter.keeps(f))
}

fn totals(results: &[(&Inventory, &Vulns)], filter: &Filter) -> (usize, usize, usize) {
    let all: Vec<&Finding> = results.iter().flat_map(|(_, v)| kept(v, filter)).collect();
    let loaded = all
        .iter()
        .filter(|f| f.reachability == Reachability::Loaded);
    (
        all.len(),
        loaded.clone().count(),
        loaded.filter(|f| f.is_kev()).count(),
    )
}

pub fn vulns_pretty(results: &[(&Inventory, &Vulns)], filter: &Filter, color: bool) -> String {
    let (total, loaded, kev) = totals(results, filter);
    let mut out = format!(
        "{} vulns, {} loaded ({} KEV loaded) across {} guests\n",
        total,
        paint(color, &loaded.to_string(), |s| s.red().bold().to_string()),
        kev,
        results.iter().filter(|(i, _)| i.guest.is_some()).count(),
    );
    out.push('\n');
    for (inv, v) in results {
        let shown: Vec<&Finding> = kept(v, filter).collect();
        let n_loaded = shown
            .iter()
            .filter(|f| f.reachability == Reachability::Loaded)
            .count();
        let _ = writeln!(out, "{}", image_title(inv, color));
        if let Some(g) = guest_line(inv, color) {
            let _ = writeln!(out, "  {g}");
        }
        if inv.guest.as_ref().is_some_and(|g| g.status != "running") {
            continue; // nothing inspected: the config risks are all there is
        }
        let _ = writeln!(
            out,
            "  {} vulns, {n_loaded} loaded{}",
            shown.len(),
            if v.cached { " (cached)" } else { "" }
        );
        for f in &shown {
            let _ = writeln!(out, "{}", finding_line(f, color));
        }
        let warn = |out: &mut String, msg: String| {
            let _ = writeln!(
                out,
                "  {} {msg}",
                paint(color, "!", |s| s.yellow().to_string())
            );
        };
        if let Some(e) = &v.error {
            warn(&mut out, format!("vulnerability matching unavailable: {e}"));
        }
        if v.unscanned > 0 {
            warn(
                &mut out,
                format!(
                    "{} packages not scanned by the API this run (not clean)",
                    v.unscanned
                ),
            );
        }
        for w in &inv.warnings {
            warn(&mut out, w.clone());
        }
        out.push('\n');
    }
    out
}

pub fn vulns_json(results: &[(&Inventory, &Vulns)], filter: &Filter) -> serde_json::Value {
    let (total, loaded, kev) = totals(results, filter);
    let guests: Vec<_> = results
        .iter()
        .map(|(inv, v)| {
            json!({
                "name": inv.name,
                "os": inv.os,
                "guest": inv.guest,
                "findings": kept(v, filter).collect::<Vec<_>>(),
                "unmatched_packages": v.unmatched,
                "unscanned_packages": v.unscanned,
                "cached": v.cached,
                "error": v.error,
                "warnings": inv.warnings,
            })
        })
        .collect();
    json!({
        "summary": { "vulns": total, "loaded": loaded, "kev_loaded": kev },
        "guests": guests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, r: Reachability, kev: bool, sev: VulnSeverity) -> Finding {
        Finding {
            id: id.into(),
            advisories: vec![],
            package: "openssl".into(),
            version: "3.0.11".into(),
            purl: "pkg:deb/debian/openssl@3.0.11".into(),
            severity: sev,
            cvss: Some(7.5),
            kev: Some(kev),
            fixed: Some("3.0.15".into()),
            summary: String::new(),
            reachability: r,
        }
    }

    fn sample() -> (Inventory, Vulns) {
        let inv = Inventory {
            name: "nginx:1.27".into(),
            digest: Some("sha256:0123456789abcdef0123".into()),
            os: None,
            guest: None,
            packages: vec![],
            mapped_files: 0,
            warnings: vec![],
        };
        let v = Vulns {
            findings: vec![
                finding("CVE-1", Reachability::Loaded, true, VulnSeverity::High),
                finding(
                    "CVE-2",
                    Reachability::Dormant,
                    false,
                    VulnSeverity::Critical,
                ),
                finding("CVE-3", Reachability::Loaded, false, VulnSeverity::Low),
            ],
            unscanned: 2,
            ..Default::default()
        };
        (inv, v)
    }

    #[test]
    fn pretty_header_and_filters() {
        let (inv, v) = sample();
        let out = vulns_pretty(&[(&inv, &v)], &Filter::default(), false);
        assert!(
            out.starts_with("3 vulns, 2 loaded (1 KEV loaded) across 0 guests"),
            "{out}"
        );
        assert!(out.contains("LOADED   KEV  HIGH  7.5  CVE-1"), "{out}");
        assert!(out.contains("→ 3.0.15"));
        assert!(out.contains("2 packages not scanned"));

        let only = Filter {
            only_loaded: true,
            min_severity: Some(VulnSeverity::Medium),
            ..Default::default()
        };
        let out = vulns_pretty(&[(&inv, &v)], &only, false);
        assert!(out.starts_with("1 vulns, 1 loaded"), "{out}");

        let json = vulns_json(
            &[(&inv, &v)],
            &Filter {
                kev_only: true,
                ..Default::default()
            },
        );
        assert_eq!(json["summary"]["vulns"], 1);
        assert_eq!(json["guests"][0]["findings"][0]["id"], "CVE-1");
        assert_eq!(json["guests"][0]["findings"][0]["reachability"], "loaded");
    }
}
