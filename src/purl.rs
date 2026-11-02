//! Package URLs (<https://github.com/package-url/purl-spec>).

/// `pkg:<ty>/<namespace>/<name>@<version>?<qualifiers>`. `namespace` may hold
/// several `/`-separated segments (Go modules); each is encoded on its own.
/// Qualifiers are emitted sorted by key, empty values dropped, per the spec.
pub fn build(
    ty: &str,
    namespace: Option<&str>,
    name: &str,
    version: &str,
    qualifiers: &[(&str, String)],
) -> String {
    let mut out = format!("pkg:{ty}/");
    if let Some(ns) = namespace.filter(|n| !n.is_empty()) {
        for seg in ns.split('/') {
            out.push_str(&encode(seg));
            out.push('/');
        }
    }
    out.push_str(&encode(name));
    if !version.is_empty() {
        out.push('@');
        out.push_str(&encode(version));
    }
    let mut quals: Vec<_> = qualifiers.iter().filter(|(_, v)| !v.is_empty()).collect();
    quals.sort_by_key(|(k, _)| *k);
    for (i, (k, v)) in quals.iter().enumerate() {
        out.push(if i == 0 { '?' } else { '&' });
        out.push_str(k);
        out.push('=');
        out.push_str(&encode(v));
    }
    out
}

/// Purl for a language dependency, by OSV ecosystem name.
pub fn lang(ecosystem: &str, name: &str, version: &str) -> String {
    let split = |n: &str| match n.rsplit_once('/') {
        Some((ns, n)) => (Some(ns.to_string()), n.to_string()),
        None => (None, n.to_string()),
    };
    let (ty, (ns, n)) = match ecosystem {
        "npm" => ("npm", split(name)),
        "crates.io" => ("cargo", (None, name.to_string())),
        "Go" => ("golang", split(name)),
        // PEP 503 normalization, as the purl spec asks.
        "PyPI" => (
            "pypi",
            (None, name.to_ascii_lowercase().replace(['_', '.'], "-")),
        ),
        "Packagist" => ("composer", split(name)),
        "RubyGems" => ("gem", (None, name.to_string())),
        other => (other, (None, name.to_string())),
    };
    build(ty, ns.as_deref(), &n, version, &[])
}

/// Percent-encode everything but unreserved characters and `:` (kept readable
/// in Debian epochs, as common purl producers do).
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_purls() {
        assert_eq!(
            lang("npm", "@babel/core", "7.24.0"),
            "pkg:npm/%40babel/core@7.24.0"
        );
        assert_eq!(lang("npm", "lodash", "4.17.21"), "pkg:npm/lodash@4.17.21");
        assert_eq!(
            lang("crates.io", "serde", "1.0.200"),
            "pkg:cargo/serde@1.0.200"
        );
        assert_eq!(
            lang("Go", "github.com/gin-gonic/gin", "v1.9.1"),
            "pkg:golang/github.com/gin-gonic/gin@v1.9.1"
        );
        assert_eq!(
            lang("PyPI", "Django_Rest.framework", "3.15.1"),
            "pkg:pypi/django-rest-framework@3.15.1"
        );
        assert_eq!(
            lang("Packagist", "symfony/http-kernel", "6.4.0"),
            "pkg:composer/symfony/http-kernel@6.4.0"
        );
        assert_eq!(lang("RubyGems", "rails", "7.1.3"), "pkg:gem/rails@7.1.3");
    }

    #[test]
    fn qualifiers_sorted_and_encoded() {
        let p = build(
            "apk",
            Some("alpine"),
            "busybox",
            "1.36.1-r20",
            &[
                ("distro", "alpine-3.19.9".into()),
                ("arch", "x86_64".into()),
                ("upstream", String::new()),
            ],
        );
        assert_eq!(
            p,
            "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19.9"
        );
    }
}
