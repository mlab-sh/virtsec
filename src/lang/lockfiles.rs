//! Lockfile parsers. Each returns `(name, version)` pairs for one ecosystem;
//! malformed input yields what could be read, never an error.

use serde_json::Value;

/// A lockfile kind, from its file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lockfile {
    PackageLock,
    YarnLock,
    CargoLock,
    GoSum,
    Requirements,
    PoetryLock,
    ComposerLock,
    GemfileLock,
}

impl Lockfile {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "package-lock.json" | ".package-lock.json" | "npm-shrinkwrap.json" => Self::PackageLock,
            "yarn.lock" => Self::YarnLock,
            "Cargo.lock" => Self::CargoLock,
            "go.sum" => Self::GoSum,
            "requirements.txt" => Self::Requirements,
            "poetry.lock" => Self::PoetryLock,
            "composer.lock" => Self::ComposerLock,
            "Gemfile.lock" => Self::GemfileLock,
            _ => return None,
        })
    }

    /// The OSV ecosystem name.
    pub fn ecosystem(self) -> &'static str {
        match self {
            Self::PackageLock | Self::YarnLock => "npm",
            Self::CargoLock => "crates.io",
            Self::GoSum => "Go",
            Self::Requirements | Self::PoetryLock => "PyPI",
            Self::ComposerLock => "Packagist",
            Self::GemfileLock => "RubyGems",
        }
    }

    pub fn parse(self, content: &str) -> Vec<(String, String)> {
        match self {
            Self::PackageLock => package_lock(content),
            Self::YarnLock => yarn_lock(content),
            Self::CargoLock => toml_packages(content, true),
            Self::PoetryLock => toml_packages(content, false),
            Self::GoSum => go_sum(content),
            Self::Requirements => requirements(content),
            Self::ComposerLock => composer_lock(content),
            Self::GemfileLock => gemfile_lock(content),
        }
    }
}

/// npm v2/v3 (`packages`, keyed by `node_modules/…` path) or v1 (`dependencies`, nested).
fn package_lock(content: &str) -> Vec<(String, String)> {
    let Ok(doc) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    let str_of = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    if let Some(pkgs) = doc.get("packages").and_then(Value::as_object) {
        return pkgs
            .iter()
            .filter(|(_, v)| v.get("link").and_then(Value::as_bool) != Some(true))
            .filter_map(|(path, v)| {
                let name = path.rsplit_once("node_modules/")?.1.to_string();
                Some((str_of(v, "name").unwrap_or(name), str_of(v, "version")?))
            })
            .collect();
    }
    fn walk(deps: &Value, out: &mut Vec<(String, String)>) {
        for (name, v) in deps.as_object().into_iter().flatten() {
            if let Some(ver) = v.get("version").and_then(Value::as_str) {
                out.push((name.clone(), ver.to_string()));
            }
            if let Some(nested) = v.get("dependencies") {
                walk(nested, out);
            }
        }
    }
    let mut out = Vec::new();
    if let Some(deps) = doc.get("dependencies") {
        walk(deps, &mut out);
    }
    out
}

/// yarn v1 (`version "1.2.3"`) and berry (`version: 1.2.3`).
fn yarn_lock(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in content.lines() {
        if !line.starts_with(' ') && line.ends_with(':') && !line.starts_with('#') {
            // `"@babel/core@^7.0.0", "@babel/core@^7.1.0":` or `lodash@npm:^4.17.0:`
            let first = line.trim_end_matches(':').split(", ").next().unwrap_or("");
            let spec = first.trim_matches('"');
            current = spec
                .get(1..)
                .and_then(|s| s.find('@'))
                .map(|at| spec[..at + 1].to_string())
                .filter(|n| n != "__metadata");
        } else if let Some(name) = &current {
            let t = line.trim();
            if let Some(v) = t
                .strip_prefix("version ")
                .or_else(|| t.strip_prefix("version: "))
            {
                out.push((name.clone(), v.trim_matches('"').to_string()));
                current = None;
            }
        }
    }
    out
}

/// `[[package]]` tables of Cargo.lock / poetry.lock. Cargo entries without
/// `source` are workspace members or path deps, not published crates.
fn toml_packages(content: &str, need_source: bool) -> Vec<(String, String)> {
    content
        .split("[[package]]")
        .skip(1)
        .filter_map(|block| {
            // Stop at the next table (`[package.dependencies]`, `[metadata]`).
            let block = block.split("\n[").next().unwrap_or("");
            let field = |k: &str| {
                block.lines().find_map(|l| {
                    let (key, v) = l.split_once('=')?;
                    (key.trim() == k).then(|| v.trim().trim_matches('"').to_string())
                })
            };
            if need_source && field("source").is_none() {
                return None;
            }
            Some((field("name")?, field("version")?))
        })
        .collect()
}

/// `module version[/go.mod] h1:…`, deduplicated.
fn go_sum(content: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = content
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (m, v) = (it.next()?, it.next()?);
            Some((m.to_string(), v.trim_end_matches("/go.mod").to_string()))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `name==version` pins only (extras, markers and comments stripped).
fn requirements(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .filter_map(|l| {
            let l = l.split('#').next()?.split(';').next()?.trim();
            let (name, ver) = l.split_once("==")?;
            let name = name.split('[').next()?.trim();
            let ver = ver.split_whitespace().next()?;
            (!name.is_empty()).then(|| (name.to_string(), ver.to_string()))
        })
        .collect()
}

fn composer_lock(content: &str) -> Vec<(String, String)> {
    let Ok(doc) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    ["packages", "packages-dev"]
        .iter()
        .filter_map(|k| doc.get(k).and_then(Value::as_array))
        .flatten()
        .filter_map(|p| {
            let name = p.get("name")?.as_str()?;
            let ver = p.get("version")?.as_str()?;
            Some((name.to_string(), ver.trim_start_matches('v').to_string()))
        })
        .collect()
}

/// The `GEM` section's `specs:`, top-level entries (4-space indent) only.
fn gemfile_lock(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_gem = false;
    for line in content.lines() {
        if !line.starts_with(' ') {
            in_gem = line == "GEM";
            continue;
        }
        if !in_gem || line.starts_with("     ") {
            continue;
        }
        if let Some(spec) = line.strip_prefix("    ") {
            if let Some((name, rest)) = spec.split_once(" (") {
                out.push((name.to_string(), rest.trim_end_matches(')').to_string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<(String, String)> {
        let path = format!(
            "{}/tests/fixtures/lockfiles/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let content = std::fs::read_to_string(&path).unwrap();
        let file = name.rsplit('/').next().unwrap();
        Lockfile::from_name(file).unwrap().parse(&content)
    }

    fn has(deps: &[(String, String)], name: &str, version: &str) -> bool {
        deps.iter().any(|(n, v)| n == name && v == version)
    }

    #[test]
    fn npm_v3_and_v1() {
        let v3 = fixture("v3/package-lock.json");
        assert!(has(&v3, "express", "4.18.2"));
        assert!(has(&v3, "@types/node", "20.11.5"));
        assert!(has(&v3, "debug", "2.6.9"), "nested node_modules path");
        assert!(!v3.iter().any(|(n, _)| n == "local-lib"), "links skipped");
        assert!(
            !v3.iter().any(|(n, _)| n.is_empty()),
            "root package skipped"
        );

        let v1 = fixture("v1/package-lock.json");
        assert!(has(&v1, "lodash", "4.17.20"));
        assert!(has(&v1, "minimist", "0.0.8"), "nested v1 deps");
    }

    #[test]
    fn yarn_v1_and_berry() {
        let v1 = fixture("yarn.lock");
        assert!(has(&v1, "@babel/code-frame", "7.23.5"));
        assert!(has(&v1, "lodash", "4.17.21"));
        let berry = fixture("berry/yarn.lock");
        assert!(has(&berry, "lodash", "4.17.21"));
        assert!(!berry.iter().any(|(n, _)| n.starts_with("__metadata")));
    }

    #[test]
    fn cargo_and_poetry() {
        let cargo = fixture("Cargo.lock");
        assert!(has(&cargo, "serde", "1.0.197"));
        assert!(
            !cargo.iter().any(|(n, _)| n == "my-app"),
            "workspace member skipped"
        );
        let poetry = fixture("poetry.lock");
        assert!(has(&poetry, "requests", "2.31.0"));
        assert!(has(&poetry, "urllib3", "2.2.1"));
    }

    #[test]
    fn go_sum_dedups_mod_lines() {
        let go = fixture("go.sum");
        assert!(has(&go, "github.com/gin-gonic/gin", "v1.9.1"));
        assert_eq!(
            go.iter()
                .filter(|(n, _)| n == "github.com/gin-gonic/gin")
                .count(),
            1
        );
    }

    #[test]
    fn requirements_pins_only() {
        let r = fixture("requirements.txt");
        assert!(has(&r, "Django", "4.2.10"));
        assert!(has(&r, "requests", "2.31.0"), "extras stripped");
        assert!(has(&r, "pyyaml", "6.0.1"), "marker stripped");
        assert!(!r.iter().any(|(n, _)| n == "flask"), "unpinned skipped");
    }

    #[test]
    fn composer_and_gemfile() {
        let c = fixture("composer.lock");
        assert!(has(&c, "symfony/http-kernel", "6.4.3"));
        assert!(
            has(&c, "phpunit/phpunit", "10.5.10"),
            "dev packages included"
        );
        let g = fixture("Gemfile.lock");
        assert!(has(&g, "rails", "7.1.3"));
        assert!(has(&g, "nokogiri", "1.16.2-x86_64-linux"));
        assert!(
            !g.iter()
                .any(|(_, v)| v.starts_with('=') || v.starts_with('>')),
            "nested requirement lines are not specs"
        );
    }
}
