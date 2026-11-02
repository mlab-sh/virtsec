//! Vulnerability matching: the [`VulnSource`] abstraction, the OSV subset we
//! read, and turning advisories into per-CVE [`Finding`]s with reachability.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Result;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use crate::cache::Cache;
use crate::model::{Coordinate, Inventory, Reachability};

/// Normalized vulnerability severity (CVSS v3 qualitative bands).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum VulnSeverity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl VulnSeverity {
    pub fn from_cvss(score: f64) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Medium,
            s if s > 0.0 => Self::Low,
            _ => Self::Unknown,
        }
    }

    /// GHSA / NVD labels (`MODERATE` is GitHub's medium).
    pub fn from_label(label: &str) -> Self {
        match label.to_ascii_uppercase().as_str() {
            "CRITICAL" => Self::Critical,
            "HIGH" => Self::High,
            "MODERATE" | "MEDIUM" => Self::Medium,
            "LOW" => Self::Low,
            _ => Self::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "UNKN",
            Self::Low => "LOW",
            Self::Medium => "MED",
            Self::High => "HIGH",
            Self::Critical => "CRIT",
        }
    }
}

/// The subset of an OSV record virtsec reads (see the `OsvVuln` schema).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// CVEs a Debian / Ubuntu record is about (often instead of `aliases`).
    #[serde(default)]
    pub upstream: Vec<String>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub affected: Vec<Affected>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Affected {
    #[serde(default)]
    pub package: Option<AffectedPackage>,
    #[serde(default)]
    pub ranges: Vec<Range>,
    /// Debian's triage of this package: `{"urgency": "unimportant"}`, ...
    #[serde(default)]
    pub ecosystem_specific: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AffectedPackage {
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Range {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub events: Vec<BTreeMap<String, String>>,
}

/// CVE enrichment (the `CveItem` schema of `GET /api/v1/cve/{id}`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CveInfo {
    #[serde(default)]
    pub cvss_score: Option<f64>,
    #[serde(default)]
    pub cvss_severity: Option<String>,
    #[serde(default)]
    pub in_kev: bool,
    #[serde(default)]
    pub in_eu_kev: bool,
}

/// Where vulnerabilities come from. vuln.mlab.sh by default; a trait so tests
/// mock it and an on-prem mlab can be plugged in.
#[async_trait::async_trait]
pub trait VulnSource: Send + Sync {
    /// Identifies the backend in cache entries (e.g. its base URL).
    fn id(&self) -> &str;

    /// One answer per coordinate, in order. `None` = not scanned (outage,
    /// unqueryable, truncated): never to be read as "no vulns".
    async fn scan(&self, coords: &[Coordinate]) -> Result<Vec<Option<Vec<Advisory>>>>;

    /// CVSS / KEV for one CVE; `Ok(None)` when the CVE is unknown.
    async fn cve(&self, id: &str) -> Result<Option<CveInfo>>;

    /// The whole known-exploited catalogue at once, by CVE id, so KEV status
    /// doesn't need one request per CVE. `Ok(None)`: not supported.
    async fn known_exploited(&self) -> Result<Option<HashMap<String, CveInfo>>> {
        Ok(None)
    }
}

/// One vulnerability of one package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// The CVE, or the advisory id when it has none (GHSA, GO-…).
    pub id: String,
    /// Every advisory describing it (DEBIAN-CVE-…, GHSA-…).
    pub advisories: Vec<String>,
    pub package: String,
    pub version: String,
    pub purl: String,
    pub severity: VulnSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f64>,
    /// In CISA or EU KEV. `None` = could not be checked.
    pub kev: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    pub reachability: Reachability,
}

impl Finding {
    pub fn is_kev(&self) -> bool {
        self.kev == Some(true)
    }

    /// Triage order: loaded+KEV, loaded, KEV, rest; then severity, CVSS.
    pub fn sort_key(&self) -> impl Ord {
        let loaded = self.reachability == Reachability::Loaded;
        let tier = match (loaded, self.is_kev()) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => 2,
            _ => 3,
        };
        (
            tier,
            std::cmp::Reverse(self.severity),
            std::cmp::Reverse((self.cvss.unwrap_or(0.0) * 10.0) as u32),
            self.id.clone(),
        )
    }
}

/// The matching outcome for one image.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Vulns {
    pub findings: Vec<Finding>,
    /// Packages that cannot be matched: unsupported ecosystem, or no exact
    /// version (a wildcard match would claim every CVE of the product).
    pub unmatched: usize,
    /// Packages the source could not scan this time (not clean!).
    pub unscanned: usize,
    pub cached: bool,
    /// Set when matching failed altogether (API unreachable, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Coordinates per scan request: the anonymous tier's `max_packages`.
const CHUNK: usize = 512;
/// Concurrent CVE enrichment requests.
const ENRICH_CONCURRENCY: usize = 8;
/// CVEs enriched one by one per run. A single dormant `linux-libc-dev` drags
/// in the ~9k CVEs Debian files against its `linux` source package.
const ENRICH_MAX: usize = 800;

/// Match every image's packages, from the cache when fresh. Coordinates are
/// deduplicated across images so shared base layers are asked about once.
/// Never fails: an unreachable source leaves `error` set on the images.
pub async fn match_images(
    source: &dyn VulnSource,
    cache: &Cache,
    images: &[Inventory],
) -> Vec<Vulns> {
    let mut out: Vec<Option<Vulns>> = vec![None; images.len()];
    let mut todo: Vec<usize> = Vec::new();
    for (i, img) in images.iter().enumerate() {
        match img.digest.as_ref().and_then(|d| cache.get(source.id(), d)) {
            Some(by_purl) => out[i] = Some(join(img, &by_purl, true)),
            None => todo.push(i),
        }
    }

    // Unique coordinates still to ask about.
    let mut coords: Vec<Coordinate> = Vec::new();
    let mut seen = HashSet::new();
    for &i in &todo {
        for p in &images[i].packages {
            if let Some(c) = matchable(p).filter(|c| seen.insert((*c).clone())) {
                coords.push(c.clone());
            }
        }
    }

    let answers = match scan_all(source, &coords).await {
        Ok(a) => a,
        Err(e) => {
            let msg = format!("{e:#}");
            tracing::warn!(error = %msg, "vulnerability matching unavailable; inventory only");
            for &i in &todo {
                out[i] = Some(Vulns {
                    error: Some(msg.clone()),
                    ..Default::default()
                });
            }
            return out.into_iter().map(Option::unwrap_or_default).collect();
        }
    };
    let by_coord: HashMap<&Coordinate, &Option<Vec<Advisory>>> =
        coords.iter().zip(answers.iter()).collect();

    // Advisories → findings per package purl, then enrich the CVEs once.
    let mut per_image: Vec<(usize, HashMap<String, Vec<Finding>>, usize)> = Vec::new();
    for &i in &todo {
        let mut by_purl = HashMap::new();
        let mut unscanned = 0;
        for p in &images[i].packages {
            let Some(coord) = matchable(p) else { continue };
            match by_coord.get(coord) {
                Some(Some(advs)) => {
                    by_purl.insert(p.purl.clone(), findings_for(p, coord, advs));
                }
                _ => unscanned += 1,
            }
        }
        per_image.push((i, by_purl, unscanned));
    }
    let kev = known_exploited(source, cache).await;
    if let Some(kev) = &kev {
        for f in per_image
            .iter_mut()
            .flat_map(|(_, m, _)| m.values_mut().flatten())
        {
            match kev.get(&f.id) {
                Some(info) => apply_enrichment(f, Some(info)),
                None if f.id.starts_with("CVE-") => f.kev = Some(false),
                None => {}
            }
        }
    }
    // Per-CVE lookups for the rest (CVSS, EU KEV), loaded code first. Kernel
    // CPE matches (thousands, all "loaded") would eat the whole budget: skipped.
    let cpe_purls: HashSet<&str> = todo
        .iter()
        .flat_map(|&i| &images[i].packages)
        .filter(|p| matches!(p.coordinate, Some(Coordinate::Cpe { .. })))
        .map(|p| p.purl.as_str())
        .collect();
    let mut wanted: Vec<(bool, String)> = per_image
        .iter()
        .flat_map(|(_, m, _)| m.values().flatten())
        .filter(|f| f.id.starts_with("CVE-") && f.cvss.is_none())
        .filter(|f| !cpe_purls.contains(f.purl.as_str()))
        .map(|f| (f.reachability != Reachability::Loaded, f.id.clone()))
        .collect();
    wanted.sort();
    let mut ids: Vec<String> = Vec::new();
    let mut seen_ids = HashSet::new();
    for (_, id) in wanted {
        if seen_ids.insert(id.clone()) {
            ids.push(id);
        }
    }
    if ids.len() > ENRICH_MAX {
        tracing::info!(
            skipped = ids.len() - ENRICH_MAX,
            "CVE enrichment capped: the rest keep their advisory severity"
        );
        ids.truncate(ENRICH_MAX);
    }
    let info = enrich(source, ids).await;

    for (i, mut by_purl, unscanned) in per_image {
        for f in by_purl.values_mut().flatten() {
            if let Some(Some(i)) = info.get(&f.id) {
                apply_enrichment(f, Some(i));
            }
        }
        if let (Some(d), 0) = (&images[i].digest, unscanned) {
            cache.put(source.id(), d, &by_purl);
        }
        let mut v = join(&images[i], &by_purl, false);
        v.unscanned = unscanned;
        out[i] = Some(v);
    }
    out.into_iter().map(Option::unwrap_or_default).collect()
}

async fn scan_all(
    source: &dyn VulnSource,
    coords: &[Coordinate],
) -> Result<Vec<Option<Vec<Advisory>>>> {
    let mut all = Vec::with_capacity(coords.len());
    for chunk in coords.chunks(CHUNK) {
        let mut answers = source.scan(chunk).await?;
        answers.resize(chunk.len(), None); // a short answer is "not scanned"
        all.extend(answers);
    }
    Ok(all)
}

/// The KEV catalogue, from the cache or the source; `None` if unavailable.
async fn known_exploited(
    source: &dyn VulnSource,
    cache: &Cache,
) -> Option<HashMap<String, CveInfo>> {
    if let Some(kev) = cache.get_json("kev", source.id()) {
        return Some(kev);
    }
    match source.known_exploited().await {
        Ok(Some(kev)) => {
            cache.put_json("kev", source.id(), &kev);
            Some(kev)
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!("KEV catalogue unavailable, checking CVEs one by one: {e:#}");
            None
        }
    }
}

/// `None` entries = enrichment failed for that CVE (KEV unknown).
async fn enrich(source: &dyn VulnSource, ids: Vec<String>) -> HashMap<String, Option<CveInfo>> {
    if !ids.is_empty() {
        tracing::info!(cves = ids.len(), "enriching CVEs (CVSS, KEV)");
    }
    futures::stream::iter(ids)
        .map(|id| async move {
            let info = match source.cve(&id).await {
                Ok(i) => Some(i.unwrap_or_default()),
                Err(e) => {
                    tracing::debug!(cve = %id, error = %e, "CVE enrichment failed");
                    None
                }
            };
            (id, info)
        })
        .buffer_unordered(ENRICH_CONCURRENCY)
        .collect()
        .await
}

fn apply_enrichment(f: &mut Finding, info: Option<&CveInfo>) {
    let Some(info) = info else { return };
    f.kev = Some(info.in_kev || info.in_eu_kev);
    if let Some(score) = info.cvss_score {
        f.cvss = Some(score);
        f.severity = VulnSeverity::from_cvss(score);
    } else if let Some(label) = &info.cvss_severity {
        f.severity = VulnSeverity::from_label(label);
    }
}

/// The coordinate to match a package on: none without an exact version.
fn matchable(p: &crate::model::Package) -> Option<&Coordinate> {
    p.coordinate.as_ref().filter(|c| c.is_exact())
}

/// Attach the image's current reachability to its cached/fresh findings.
fn join(img: &Inventory, by_purl: &HashMap<String, Vec<Finding>>, cached: bool) -> Vulns {
    let mut findings = Vec::new();
    let mut unmatched = 0;
    for p in &img.packages {
        if matchable(p).is_none() {
            unmatched += 1;
        }
        let fixed_here = |f: &&Finding| !p.backported.contains(&f.id);
        for f in by_purl
            .get(&p.purl)
            .into_iter()
            .flatten()
            .filter(fixed_here)
        {
            let mut f = f.clone();
            f.reachability = p.reachability;
            findings.push(f);
        }
    }
    findings.sort_by_key(Finding::sort_key);
    Vulns {
        findings,
        unmatched,
        cached,
        ..Default::default()
    }
}

/// The baseline key of an inventory: its vmid, or `node`.
fn seen_key(inv: &Inventory) -> String {
    inv.guest
        .as_ref()
        .map_or("node".to_string(), |g| g.vmid.to_string())
}

fn seen_id(f: &Finding) -> String {
    format!("{} {}", f.id, f.purl)
}

/// This run's findings as the next baseline. A guest whose matching failed
/// keeps what `prev` had for it, so an API outage doesn't make all "new".
pub fn seen(
    invs: &[Inventory],
    vulns: &[Vulns],
    prev: Option<&crate::cache::Seen>,
) -> crate::cache::Seen {
    let mut out = prev.cloned().unwrap_or_default();
    for (inv, v) in invs.iter().zip(vulns) {
        if v.error.is_none() && v.unscanned == 0 {
            out.insert(seen_key(inv), v.findings.iter().map(seen_id).collect());
        }
    }
    out
}

/// Drop the findings `prev` already had (`--new`). Without a baseline all are new.
pub fn keep_new(invs: &[Inventory], vulns: &mut [Vulns], prev: Option<&crate::cache::Seen>) {
    let Some(prev) = prev else { return };
    for (inv, v) in invs.iter().zip(vulns.iter_mut()) {
        if let Some(old) = prev.get(&seen_key(inv)) {
            v.findings.retain(|f| !old.contains(&seen_id(f)));
        }
    }
}

/// Group a package's advisories by CVE (several feeds describe the same one).
pub fn findings_for(
    pkg: &crate::model::Package,
    coord: &Coordinate,
    advisories: &[Advisory],
) -> Vec<Finding> {
    let installed = match coord {
        Coordinate::Eco { version, .. } => version.as_str(),
        _ => pkg.version.as_str(),
    };
    let mut by_id: BTreeMap<String, Finding> = BTreeMap::new();
    for adv in advisories.iter().filter(|a| !unimportant(a, coord)) {
        let label = adv
            .database_specific
            .as_ref()
            .and_then(|d| d.get("severity"))
            .and_then(|s| s.as_str())
            .map(VulnSeverity::from_label)
            .unwrap_or(VulnSeverity::Unknown);
        let fixed = fixed_version(adv, coord, installed);
        // A distro errata (RLSA-…) can fix several CVEs: one finding each.
        for id in cves_of(adv) {
            let f = by_id.entry(id.clone()).or_insert_with(|| Finding {
                // KEV only lists CVEs: a CVE-less advisory is known not to be in it.
                kev: (!id.starts_with("CVE-")).then_some(false),
                id,
                advisories: Vec::new(),
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                purl: pkg.purl.clone(),
                severity: VulnSeverity::Unknown,
                cvss: None,
                fixed: None,
                summary: String::new(),
                reachability: pkg.reachability,
            });
            f.advisories.push(adv.id.clone());
            f.severity = f.severity.max(label);
            if f.fixed.is_none() {
                f.fixed = fixed.clone();
            }
            if f.summary.is_empty() {
                f.summary = adv.summary.clone();
            }
        }
    }
    // Kernel CPE matches aren't enriched one by one (see `match_images`):
    // without the KEV catalogue they'd all read "unknown".
    if matches!(coord, Coordinate::Cpe { .. }) {
        by_id
            .values_mut()
            .for_each(|f| f.kev = f.kev.or(Some(false)));
    }
    by_id.into_values().collect()
}

/// The CVEs an advisory is about: its id (`CVE-…`, `DEBIAN-CVE-…`),
/// `aliases` and `upstream`; the advisory id itself when it names none.
fn cves_of(adv: &Advisory) -> Vec<String> {
    let mut ids: Vec<String> = adv
        .id
        .find("CVE-")
        .map(|i| adv.id[i..].to_string())
        .into_iter()
        .chain(
            adv.aliases
                .iter()
                .chain(&adv.upstream)
                .filter(|a| a.starts_with("CVE-"))
                .cloned(),
        )
        .collect();
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        ids.push(adv.id.clone());
    }
    ids
}

/// The smallest `fixed` of a range containing `installed`, for this package
/// in this ecosystem (a distro record lists every release branch).
/// Debian triaged the issue as not one for this package ("unimportant":
/// disputed, or harmless as Debian builds it): not a finding. Only this
/// package's entries count; another package's triage says nothing about it.
fn unimportant(adv: &Advisory, coord: &Coordinate) -> bool {
    let Coordinate::Eco {
        ecosystem, name, ..
    } = coord
    else {
        return false;
    };
    let mut ours = adv
        .affected
        .iter()
        .filter(|a| {
            a.package
                .as_ref()
                .is_some_and(|p| &p.ecosystem == ecosystem && &p.name == name)
        })
        .peekable();
    ours.peek().is_some()
        && ours.all(|a| {
            a.ecosystem_specific
                .as_ref()
                .and_then(|e| e.get("urgency"))
                .and_then(|u| u.as_str())
                == Some("unimportant")
        })
}

fn fixed_version(adv: &Advisory, coord: &Coordinate, installed: &str) -> Option<String> {
    let (eco, name) = match coord {
        Coordinate::Eco {
            ecosystem, name, ..
        } => (Some(ecosystem.as_str()), Some(name.as_str())),
        _ => (None, None),
    };
    let mut best: Option<String> = None;
    for aff in &adv.affected {
        if let (Some(p), Some(eco), Some(name)) = (&aff.package, eco, name) {
            if p.ecosystem != eco || p.name != name {
                continue;
            }
        }
        for range in aff.ranges.iter().filter(|r| r.kind != "GIT") {
            let mut introduced = "0".to_string();
            for ev in &range.events {
                if let Some(i) = ev.get("introduced") {
                    introduced = i.clone();
                } else if let Some(fix) = ev.get("fixed") {
                    let opened = introduced == "0" || version_cmp(&introduced, installed).is_le();
                    if opened && version_cmp(installed, fix).is_lt() {
                        best = match best {
                            Some(b) if version_cmp(&b, fix).is_le() => Some(b),
                            _ => Some(fix.clone()),
                        };
                    }
                }
            }
        }
    }
    best
}

/// Loose version ordering across ecosystems: digit runs compare numerically,
/// letter runs lexically, `~` (dpkg pre-release) sorts lowest, even below the
/// end of the string. Good enough to pick the right range: the source has
/// already decided what is affected.
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn tokens(s: &str) -> Vec<(u8, u64, String)> {
        let mut out = Vec::new();
        let mut chars = s.trim_start_matches('v').chars().peekable();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                let mut n = String::new();
                while let Some(&d) = chars.peek().filter(|d| d.is_ascii_digit()) {
                    n.push(d);
                    chars.next();
                }
                out.push((3, n.parse().unwrap_or(u64::MAX), String::new()));
            } else if c == '~' {
                out.push((0, 0, String::new()));
                chars.next();
            } else if c.is_ascii_alphabetic() {
                let mut w = String::new();
                while let Some(&d) = chars.peek().filter(|d| d.is_ascii_alphabetic()) {
                    w.push(d);
                    chars.next();
                }
                out.push((2, 0, w));
            } else {
                chars.next(); // separators
            }
        }
        out.push((1, 0, String::new())); // end: above `~`, below anything else
        out
    }
    tokens(a).cmp(&tokens(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Package, PackageKind};
    use std::cmp::Ordering;

    fn adv(json: serde_json::Value) -> Advisory {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn version_ordering() {
        assert_eq!(
            version_cmp("1:9.2p1-2", "1:9.2p1-2+deb12u3"),
            Ordering::Less
        );
        assert_eq!(version_cmp("1.36.1-r20", "1.36.1-r7"), Ordering::Greater);
        assert_eq!(version_cmp("3.0.15-1~deb12u1", "3.0.15-1"), Ordering::Less);
        assert_eq!(version_cmp("v1.9.1", "1.9.1"), Ordering::Equal);
    }

    #[test]
    fn debian_unimportant_is_not_a_finding() {
        let pkg = Package::new(
            "nginx",
            "1.25.3-1~bookworm",
            PackageKind::Os,
            "pkg:deb/debian/nginx@1.25.3-1~bookworm".into(),
        );
        let coord = Coordinate::eco("Debian:12", "nginx", "1.25.3-1~bookworm");
        let entry = |name: &str, urgency: &str| {
            serde_json::json!({
                "package": {"ecosystem": "Debian:12", "name": name},
                "ecosystem_specific": {"urgency": urgency},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
            })
        };
        let advs = vec![
            // Triaged unimportant for nginx: gone.
            adv(
                serde_json::json!({"id": "DEBIAN-CVE-2013-0337", "affected": [entry("nginx", "unimportant")]}),
            ),
            // Unimportant for another package only: still a finding for nginx.
            adv(serde_json::json!({"id": "DEBIAN-CVE-2023-44487",
                "affected": [entry("dnsdist", "unimportant"), entry("nginx", "not yet assigned")]})),
            // No triage at all (another source): kept.
            adv(serde_json::json!({"id": "GHSA-yyyy", "aliases": ["CVE-2024-9"]})),
        ];
        let ids: Vec<String> = findings_for(&pkg, &coord, &advs)
            .into_iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(ids, ["CVE-2023-44487", "CVE-2024-9"]);
    }

    #[test]
    fn groups_by_cve_and_picks_matching_branch_fix() {
        let mut pkg = Package::new(
            "busybox",
            "1.36.1-r15",
            PackageKind::Os,
            "pkg:apk/alpine/busybox@1.36.1-r15".into(),
        );
        pkg.reachability = Reachability::Loaded;
        let coord = Coordinate::eco("Alpine:v3.19", "busybox", "1.36.1-r15");
        let advs = vec![
            adv(serde_json::json!({
                "id": "ALPINE-CVE-2023-42363",
                "summary": "use-after-free in xasprintf",
                "affected": [
                    {"package": {"ecosystem": "Alpine:v3.18", "name": "busybox"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.36.1-r7"}]}]},
                    {"package": {"ecosystem": "Alpine:v3.19", "name": "busybox"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.36.1-r17"}]}]}
                ]
            })),
            adv(serde_json::json!({
                "id": "GHSA-xxxx", "aliases": ["CVE-2023-42363"],
                "database_specific": {"severity": "MODERATE"}
            })),
            adv(serde_json::json!({"id": "GHSA-only", "database_specific": {"severity": "HIGH"}})),
            adv(serde_json::json!({"id": "RLSA-2024:1", "aliases": ["CVE-2024-1", "CVE-2024-2"]})),
        ];
        let f = findings_for(&pkg, &coord, &advs);
        assert_eq!(f.len(), 4, "an errata naming two CVEs gives two findings");
        assert!(f
            .iter()
            .any(|f| f.id == "CVE-2024-2" && f.advisories == ["RLSA-2024:1"]));
        let cve = f.iter().find(|f| f.id == "CVE-2023-42363").unwrap();
        assert_eq!(cve.advisories, ["ALPINE-CVE-2023-42363", "GHSA-xxxx"]);
        assert_eq!(cve.fixed.as_deref(), Some("1.36.1-r17"));
        assert_eq!(cve.severity, VulnSeverity::Medium);
        assert_eq!(cve.kev, None, "to be enriched");
        assert_eq!(cve.reachability, Reachability::Loaded);
        let ghsa = f.iter().find(|f| f.id == "GHSA-only").unwrap();
        assert_eq!(ghsa.kev, Some(false));
        assert_eq!(ghsa.severity, VulnSeverity::High);
    }

    #[test]
    fn debian_upstream_field_and_multi_range() {
        let pkg = Package::new(
            "lodash",
            "4.17.20",
            PackageKind::Lang,
            "pkg:npm/lodash@4.17.20".into(),
        );
        let coord = Coordinate::eco("npm", "lodash", "4.17.20");
        let a = adv(serde_json::json!({
            "id": "DEBIAN-X", "upstream": ["CVE-2021-23337"],
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.10.2"}]},
                {"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]}
            ]}]
        }));
        let f = findings_for(&pkg, &coord, &[a]);
        assert_eq!(f[0].id, "CVE-2021-23337");
        assert_eq!(f[0].fixed.as_deref(), Some("4.17.21"));
    }

    /// Answers every coordinate with one advisory, or fails when `down`.
    struct MockSource {
        down: bool,
        scans: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl VulnSource for MockSource {
        fn id(&self) -> &str {
            "mock"
        }
        async fn scan(&self, coords: &[Coordinate]) -> Result<Vec<Option<Vec<Advisory>>>> {
            self.scans.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.down {
                anyhow::bail!("cannot reach mock");
            }
            Ok(coords
                .iter()
                .map(|_| Some(vec![adv(serde_json::json!({"id": "DEBIAN-CVE-2024-6387"}))]))
                .collect())
        }
        async fn cve(&self, _id: &str) -> Result<Option<CveInfo>> {
            Ok(Some(CveInfo {
                cvss_score: Some(8.1),
                in_kev: true,
                ..Default::default()
            }))
        }
    }

    #[test]
    fn new_findings_against_the_baseline() {
        let f = |id: &str| Finding {
            id: id.into(),
            advisories: vec![],
            package: "openssl".into(),
            version: "3".into(),
            purl: "pkg:deb/debian/openssl@3".into(),
            severity: VulnSeverity::High,
            cvss: None,
            kev: None,
            fixed: None,
            summary: String::new(),
            reachability: Reachability::Loaded,
        };
        let invs = [image("a")];
        let mut first = vec![Vulns {
            findings: vec![f("CVE-1")],
            ..Default::default()
        }];
        let base = seen(&invs, &first, None);
        assert_eq!(base["node"].len(), 1);
        keep_new(&invs, &mut first, None);
        assert_eq!(first[0].findings.len(), 1, "no baseline: all new");

        let invs = &invs[..];
        let mut next = vec![Vulns {
            findings: vec![f("CVE-1"), f("CVE-2")],
            ..Default::default()
        }];
        keep_new(invs, &mut next, Some(&base));
        assert_eq!(next[0].findings.len(), 1);
        assert_eq!(next[0].findings[0].id, "CVE-2");

        let failed = vec![Vulns {
            error: Some("down".into()),
            ..Default::default()
        }];
        assert_eq!(
            seen(invs, &failed, Some(&base)),
            base,
            "a failed run keeps the baseline"
        );
    }

    fn image(digest: &str) -> Inventory {
        let mut ssh = Package::new(
            "openssh-server",
            "1:9.2p1-2",
            PackageKind::Os,
            "pkg:deb/debian/openssh-server@1:9.2p1-2".into(),
        );
        ssh.coordinate = Some(Coordinate::eco("Debian:12", "openssh", "1:9.2p1-2"));
        ssh.reachability = Reachability::Loaded;
        let mut client = Package::new(
            "openssh-client",
            "1:9.2p1-2",
            PackageKind::Os,
            "pkg:deb/debian/openssh-client@1:9.2p1-2".into(),
        );
        client.coordinate = ssh.coordinate.clone();
        Inventory {
            name: "sshd".into(),
            digest: Some(digest.into()),
            os: None,
            guest: None,
            packages: vec![
                ssh,
                client,
                Package::new("noeco", "1", PackageKind::Os, "pkg:x/noeco@1".into()),
            ],
            mapped_files: 0,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn match_enriches_dedups_and_caches() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(
            Some(dir.path().into()),
            std::time::Duration::from_secs(60),
            true,
        );
        let src = MockSource {
            down: false,
            scans: Default::default(),
        };
        let res = match_images(&src, &cache, &[image("sha256:1"), image("sha256:2")]).await;
        assert_eq!(
            src.scans.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one request, coords deduped"
        );
        let v = &res[0];
        assert_eq!(v.findings.len(), 2, "both binaries of the source package");
        assert_eq!(v.unmatched, 1);
        let top = &v.findings[0];
        assert_eq!(
            (top.id.as_str(), top.package.as_str()),
            ("CVE-2024-6387", "openssh-server")
        );
        assert!(top.is_kev());
        assert_eq!(top.severity, VulnSeverity::High);
        assert_eq!(top.reachability, Reachability::Loaded);
        assert_eq!(v.findings[1].reachability, Reachability::Dormant);

        // Second run: served from cache, reachability re-applied from the inventory.
        let mut img = image("sha256:1");
        img.packages[0].reachability = Reachability::Dormant;
        let again = match_images(&src, &cache, &[img]).await;
        assert!(again[0].cached);
        assert_eq!(src.scans.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(again[0].findings[0].reachability, Reachability::Dormant);
    }

    /// Per-CVE lookups always fail; KEV comes from the bulk catalogue.
    struct CatalogSource;

    #[async_trait::async_trait]
    impl VulnSource for CatalogSource {
        fn id(&self) -> &str {
            "catalog"
        }
        async fn scan(&self, coords: &[Coordinate]) -> Result<Vec<Option<Vec<Advisory>>>> {
            Ok(coords
                .iter()
                .map(|_| {
                    Some(vec![
                        adv(serde_json::json!({"id": "DEBIAN-CVE-2024-6387"})),
                        adv(serde_json::json!({"id": "DEBIAN-CVE-2024-0001"})),
                    ])
                })
                .collect())
        }
        async fn cve(&self, _id: &str) -> Result<Option<CveInfo>> {
            anyhow::bail!("per-CVE endpoint down")
        }
        async fn known_exploited(&self) -> Result<Option<HashMap<String, CveInfo>>> {
            let info = CveInfo {
                cvss_score: Some(8.1),
                in_kev: true,
                ..Default::default()
            };
            Ok(Some(HashMap::from([("CVE-2024-6387".to_string(), info)])))
        }
    }

    #[tokio::test]
    async fn kev_from_bulk_catalogue() {
        let cache = Cache::new(None, std::time::Duration::from_secs(60), true);
        let res = match_images(&CatalogSource, &cache, &[image("sha256:1")]).await;
        let by = |id: &str| res[0].findings.iter().find(|f| f.id == id).unwrap();
        assert_eq!(by("CVE-2024-6387").kev, Some(true));
        assert_eq!(by("CVE-2024-6387").cvss, Some(8.1));
        // Not in the catalogue: known not KEV, even though enrichment failed.
        assert_eq!(by("CVE-2024-0001").kev, Some(false));
    }

    #[tokio::test]
    async fn unreachable_source_degrades() {
        let cache = Cache::new(None, std::time::Duration::from_secs(60), true);
        let src = MockSource {
            down: true,
            scans: Default::default(),
        };
        let res = match_images(&src, &cache, &[image("sha256:1")]).await;
        assert!(res[0].findings.is_empty());
        assert!(res[0].error.as_deref().unwrap().contains("cannot reach"));
    }

    #[test]
    fn triage_order() {
        let mk = |id: &str, r: Reachability, kev: bool, sev: VulnSeverity| Finding {
            id: id.into(),
            advisories: vec![],
            package: "p".into(),
            version: "1".into(),
            purl: "pkg:x/p@1".into(),
            severity: sev,
            cvss: None,
            kev: Some(kev),
            fixed: None,
            summary: String::new(),
            reachability: r,
        };
        let mut v = [
            mk(
                "dormant-crit",
                Reachability::Dormant,
                false,
                VulnSeverity::Critical,
            ),
            mk("loaded-low", Reachability::Loaded, false, VulnSeverity::Low),
            mk(
                "loaded-kev",
                Reachability::Loaded,
                true,
                VulnSeverity::Medium,
            ),
            mk(
                "loaded-high",
                Reachability::Loaded,
                false,
                VulnSeverity::High,
            ),
        ];
        v.sort_by_key(Finding::sort_key);
        let ids: Vec<&str> = v.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            ["loaded-kev", "loaded-high", "loaded-low", "dormant-crit"]
        );
    }
}
