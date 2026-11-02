//! vuln.mlab.sh client ([`VulnSource`]).
//!
//! Spec: doc.mlab.sh `openapi.vuln.yaml` (vuln.mlab.sh API 2.5.0).
//! * `POST /api/v2/scan`, pre-parsed mode `{"packages":[ScanCoordinate…]}`:
//!   the SBOM endpoint, answering `results[i]` for `packages[i]` (OSV records).
//!   Pre-parsed rather than uploading the CycloneDX document: the response is
//!   index-aligned (no re-matching of echoed coordinates) and distro packages
//!   are asked by *source* package, which is how distro advisories are filed.
//! * `GET /api/v1/cve/{id}`: CVSS, CISA / EU KEV. Errors are HTTP 200 with
//!   `{"error": …}`.
//!
//! Auth: `Authorization: Bearer <MLAB_API_KEY>` (optional; raises the tier's
//! limits). The key never reaches logs or error messages.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::{RequestBuilder, Response, StatusCode};
use serde_json::Value;

use crate::model::Coordinate;
use crate::vuln::{Advisory, CveInfo, VulnSource};

/// Attempts for network errors / 5xx (backoff 1s, 2s, 4s).
const MAX_ATTEMPTS: u32 = 4;
/// 429s waited out (anonymous scans have a 10 s cooldown).
const MAX_COOLDOWNS: u32 = 6;
/// Safety bound on the KEV catalogue pagination (100 per page).
const MAX_KEV_PAGES: usize = 50;

/// An API key whose `Debug` never shows it.
#[derive(Clone)]
pub struct ApiKey(String);

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

#[derive(Debug, Clone)]
pub struct MlabClient {
    http: reqwest::Client,
    base: String,
    key: Option<ApiKey>,
}

impl MlabClient {
    pub const DEFAULT_URL: &'static str = "https://vuln.mlab.sh";

    pub fn new(base: &str, key: Option<String>) -> Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            bail!("invalid --mlab-url `{base}`: expected http(s)://host");
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("virtsec/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            http,
            base,
            key: key.filter(|k| !k.is_empty()).map(ApiKey),
        })
    }

    fn authed(&self, req: RequestBuilder) -> RequestBuilder {
        match &self.key {
            Some(ApiKey(k)) => req.bearer_auth(k),
            None => req,
        }
    }

    /// Send with retries: backoff on network errors and 5xx, honor
    /// `Retry-After` on 429, fail readably on any other refusal.
    async fn send(&self, build: impl Fn() -> RequestBuilder) -> Result<Response> {
        let (mut attempts, mut cooldowns) = (0, 0);
        let mut backoff = Duration::from_secs(1);
        loop {
            let wait = match self.authed(build()).send().await {
                Ok(r) if r.status() == StatusCode::TOO_MANY_REQUESTS => {
                    cooldowns += 1;
                    if cooldowns > MAX_COOLDOWNS {
                        bail!(
                            "{} keeps rate-limiting (429); set MLAB_API_KEY for higher limits",
                            self.base
                        );
                    }
                    let secs = r
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
                        .unwrap_or(10);
                    tracing::info!("vuln.mlab.sh cooldown, retrying in {secs}s");
                    Duration::from_secs(secs.min(60))
                }
                Ok(r) if r.status().is_server_error() => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        bail!(
                            "{} answered {} after {attempts} attempts",
                            self.base,
                            r.status()
                        );
                    }
                    {
                        let next = backoff * 2;
                        std::mem::replace(&mut backoff, next)
                    }
                }
                Ok(r) if !r.status().is_success() => {
                    let status = r.status();
                    let body: Value = r.json().await.unwrap_or_default();
                    let msg = body["message"]
                        .as_str()
                        .or(body["error"].as_str())
                        .unwrap_or("");
                    bail!("{} refused the request ({status}): {msg}", self.base);
                }
                Ok(r) => return Ok(r),
                Err(e) => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        // reqwest errors carry the URL, never request headers.
                        bail!("cannot reach {} after {attempts} attempts: {e}", self.base);
                    }
                    tracing::debug!(error = %e, "vuln API request failed, retrying in {backoff:?}");
                    {
                        let next = backoff * 2;
                        std::mem::replace(&mut backoff, next)
                    }
                }
            };
            tokio::time::sleep(wait).await;
        }
    }
}

#[async_trait::async_trait]
impl VulnSource for MlabClient {
    fn id(&self) -> &str {
        &self.base
    }

    async fn scan(&self, coords: &[Coordinate]) -> Result<Vec<Option<Vec<Advisory>>>> {
        let url = format!("{}/api/v2/scan", self.base);
        let body = serde_json::json!({ "packages": coords });
        let doc: ScanDoc = self
            .send(|| self.http.post(&url).json(&body))
            .await?
            .json()
            .await
            .context("invalid JSON from /api/v2/scan")?;
        if doc.truncated {
            tracing::warn!(
                "{}",
                doc.truncation["message"]
                    .as_str()
                    .unwrap_or("scan truncated by the API")
            );
        }
        if doc.outage {
            tracing::warn!("vuln.mlab.sh reports a database outage: some packages not scanned");
        }
        let results = doc
            .results
            .context("unexpected /api/v2/scan response: no `results` array")?;
        Ok(results
            .into_iter()
            .map(|r| {
                r.ok.then_some(r.vulns)
                    .flatten()
                    .map(|v| v.into_iter().filter_map(|l| l.0).collect())
            })
            .collect())
    }

    async fn cve(&self, id: &str) -> Result<Option<CveInfo>> {
        let url = format!("{}/api/v1/cve/{id}", self.base);
        let doc: Value = self
            .send(|| self.http.get(&url))
            .await?
            .json()
            .await
            .context("invalid JSON from /api/v1/cve")?;
        if doc.get("error").is_some() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_value(doc).unwrap_or_default()))
    }

    /// `GET /api/v1/cve?kevOnly=1`, paginated (100 per page, ~18 pages).
    async fn known_exploited(&self) -> Result<Option<HashMap<String, CveInfo>>> {
        let url = format!("{}/api/v1/cve", self.base);
        let mut out = HashMap::new();
        for page in 0..MAX_KEV_PAGES {
            let doc: Value = self
                .send(|| {
                    self.http.get(&url).query(&[
                        ("kevOnly", "1"),
                        ("limit", "100"),
                        ("page", &page.to_string()),
                    ])
                })
                .await?
                .json()
                .await
                .context("invalid JSON from /api/v1/cve")?;
            if let Some(e) = doc["error"].as_str() {
                bail!("KEV listing refused: {e}");
            }
            let cves = doc["cves"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default();
            for c in cves {
                if let (Some(id), Ok(info)) = (c["id"].as_str(), serde_json::from_value(c.clone()))
                {
                    out.insert(id.to_string(), info);
                }
            }
            let total = doc["total_results"].as_u64().unwrap_or(0) as usize;
            if cves.is_empty() || out.len() >= total {
                break;
            }
        }
        tracing::debug!(kev = out.len(), "fetched KEV catalogue");
        Ok(Some(out))
    }
}

/// `ok:false` (unqueryable / outage) is "not scanned", not "clean". Records
/// are decoded one by one so a single odd one can't sink the whole answer.
/// The parts of a `/api/v2/scan` answer virtsec reads. Decoded straight into
/// these types, record by record: a 512-package answer is never held whole as
/// a JSON tree (with every advisory's `versions` list, 430 MiB on the lab).
#[derive(serde::Deserialize)]
struct ScanDoc {
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    truncation: Value,
    #[serde(default)]
    outage: bool,
    results: Option<Vec<ScanResult>>,
}

#[derive(serde::Deserialize)]
struct ScanResult {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    vulns: Option<Vec<Lenient>>,
}

/// One OSV record; a malformed one is skipped, not the whole answer.
struct Lenient(Option<Advisory>);

impl<'de> serde::Deserialize<'de> for Lenient {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        Ok(Lenient(match serde_json::from_value(v) {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::debug!(error = %e, "skipping malformed OSV record");
                None
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_doc_skips_malformed_records_only() {
        let doc: ScanDoc = serde_json::from_str(
            r#"{"results": [
                {"ok": false, "vulns": [{"id": "A"}]},
                {"ok": true, "vulns": [42, {"id": "B", "versions": ["1", "2"]}]},
                {"ok": true}
            ]}"#,
        )
        .unwrap();
        let ids: Vec<Option<Vec<String>>> = doc
            .results
            .unwrap()
            .into_iter()
            .map(|r| {
                r.ok.then_some(r.vulns)
                    .flatten()
                    .map(|v| v.into_iter().filter_map(|l| l.0.map(|a| a.id)).collect())
            })
            .collect();
        assert_eq!(ids, [None, Some(vec!["B".to_string()]), None]);
    }
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A one-connection-per-response HTTP mock: serves `responses` in order
    /// and records the raw requests.
    async fn mock(responses: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            for resp in responses {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 64 * 1024];
                let mut req = Vec::new();
                // Read headers, then the announced body.
                loop {
                    let n = sock.read(&mut buf).await.unwrap();
                    req.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&req).to_string();
                    if let Some(h) = text.find("\r\n\r\n") {
                        let len = text
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if req.len() >= h + 4 + len {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&req).to_string());
                sock.write_all(resp.as_bytes()).await.unwrap();
                sock.shutdown().await.ok();
            }
        });
        (format!("http://{addr}"), seen)
    }

    fn http(status: &str, extra: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn scan_retries_cooldown_and_maps_results() {
        let ok = r#"{"tier":"free","truncated":false,"outage":false,"results":[
            {"ok":true,"vulns":[{"id":"DEBIAN-CVE-2024-6387","upstream":["CVE-2024-6387"]},{"id":42}]},
            {"ok":true,"vulns":[]},
            {"ok":false,"unqueryable":true}]}"#;
        let (base, seen) = mock(vec![
            http(
                "429 Too Many Requests",
                "retry-after: 0\r\n",
                r#"{"error":"cooldown"}"#,
            ),
            http("200 OK", "", ok),
        ])
        .await;
        let client = MlabClient::new(&base, Some("s3cr3t-key".into())).unwrap();
        let coords = vec![
            Coordinate::eco("Debian:12", "openssh", "1:9.2p1-2"),
            Coordinate::eco("Debian:12", "dash", "0.5.12-2"),
            Coordinate::Purl {
                purl: "pkg:generic/x@1".into(),
            },
        ];
        let res = client.scan(&coords).await.unwrap();
        assert_eq!(res.len(), 3);
        let first = res[0].as_ref().unwrap();
        assert_eq!(first.len(), 1, "malformed record skipped, not fatal");
        assert_eq!(first[0].upstream, ["CVE-2024-6387"]);
        assert_eq!(res[1].as_deref().map(<[_]>::len), Some(0));
        assert!(res[2].is_none(), "ok:false is not clean");

        let reqs = seen.lock().unwrap();
        assert_eq!(reqs.len(), 2, "429 was retried");
        assert!(reqs[1].starts_with("POST /api/v2/scan"));
        assert!(reqs[1]
            .to_ascii_lowercase()
            .contains("authorization: bearer s3cr3t-key"));
        assert!(reqs[1].contains(r#""ecosystem":"Debian:12""#));
        assert!(
            !format!("{client:?}").contains("s3cr3t"),
            "key redacted in Debug"
        );
    }

    #[tokio::test]
    async fn cve_enrichment_and_not_found() {
        let (base, _) = mock(vec![
            http(
                "200 OK",
                "",
                r#"{"id":"CVE-2024-6387","cvss_score":8.1,"cvss_severity":"HIGH","in_kev":true}"#,
            ),
            http("200 OK", "", r#"{"error":"CVE not found"}"#),
        ])
        .await;
        let client = MlabClient::new(&base, None).unwrap();
        let info = client.cve("CVE-2024-6387").await.unwrap().unwrap();
        assert!(info.in_kev);
        assert_eq!(info.cvss_score, Some(8.1));
        assert!(client.cve("CVE-0000-0000").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn refusal_is_readable_and_bad_url_rejected() {
        let (base, _) = mock(vec![http(
            "413 Payload Too Large",
            "",
            r#"{"error":"payload_too_large","message":"The request body is larger than 4 MiB"}"#,
        )])
        .await;
        let client = MlabClient::new(&base, None).unwrap();
        let err = client.scan(&[]).await.unwrap_err().to_string();
        assert!(
            err.contains("413") && err.contains("larger than 4 MiB"),
            "{err}"
        );

        assert!(MlabClient::new("ftp://x", None).is_err());
    }
}
