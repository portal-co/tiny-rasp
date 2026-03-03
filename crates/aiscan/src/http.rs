// AIKEY-l4qkxonqry2b4gj7bsrkqpryiy
//! HTTP AI scanner — POSTs to an external scoring service.
//!
//! Request  (JSON): `{"path": "<path>", "content": "<utf-8 text>"}`
//! Response (JSON): `{"likely_ai": <bool>, "confidence": <float 0-1>}`

use std::path::Path;

use anyhow::{Context, Result};
use env_traits::{AiEnv, NetworkEnv};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct ScanRequest<'a> {
    path:    &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ScanResponse {
    likely_ai:  bool,
    confidence: f64,
}

pub struct HttpAiEnv<N> {
    endpoint: String,
    network:  N,
}

impl<N: NetworkEnv> HttpAiEnv<N> {
    pub fn new(endpoint: impl Into<String>, network: N) -> Self {
        Self { endpoint: endpoint.into(), network }
    }
}

impl<N: NetworkEnv> AiEnv for HttpAiEnv<N> {
    fn scan(&self, path: &Path, content: &[u8]) -> Result<(bool, f64)> {
        let body = serde_json::to_vec(&ScanRequest {
            path:    &path.display().to_string(),
            content: &String::from_utf8_lossy(content),
        })
        .context("aiscan/http: serialize request")?;

        let resp_bytes = self
            .network
            .post_json(&self.endpoint, &body)
            .with_context(|| format!("aiscan/http: POST {}", self.endpoint))?;

        let resp: ScanResponse =
            serde_json::from_slice(&resp_bytes).context("aiscan/http: deserialize response")?;

        Ok((resp.likely_ai, resp.confidence))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use env_fake::FakeNetworkEnv;

    #[test]
    fn returns_server_verdict() {
        let body = br#"{"likely_ai": true, "confidence": 0.87}"#;
        let net = FakeNetworkEnv::default().with_response("http://ai.test/scan", body.as_ref());
        let scanner = HttpAiEnv::new("http://ai.test/scan", net);
        let (likely, conf) = scanner
            .scan(Path::new("foo.rs"), b"some content")
            .unwrap();
        assert!(likely);
        assert!((conf - 0.87).abs() < 1e-9);
    }

    #[test]
    fn propagates_network_error() {
        let net = FakeNetworkEnv::default(); // no response registered → Err
        let scanner = HttpAiEnv::new("http://ai.test/scan", net);
        assert!(scanner.scan(Path::new("foo.rs"), b"x").is_err());
    }
}
