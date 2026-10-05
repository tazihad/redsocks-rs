use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use md5::{Digest, Md5};
use rand::RngCore;
use std::collections::HashMap;

pub fn basic_auth_header(user: &str, pass: &str) -> String {
    let credentials = format!("{}:{}", user, pass);
    let encoded = BASE64.encode(credentials.as_bytes());
    format!("Basic {}", encoded)
}

#[derive(Debug, Clone, Default)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub qop: Option<String>,
    pub algorithm: Option<String>,
}

impl DigestChallenge {
    pub fn parse(header: &str) -> Option<Self> {
        // header like: Digest realm="...", nonce="...", qop="auth"
        let trimmed = header.trim();
        let payload = if let Some(stripped) = trimmed.strip_prefix("Digest ") {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("digest ") {
            stripped
        } else {
            trimmed
        };

        let mut map = HashMap::new();
        let mut in_quotes = false;
        let mut start = 0;
        let bytes = payload.as_bytes();

        let mut parts = Vec::new();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'"' {
                in_quotes = !in_quotes;
            } else if b == b',' && !in_quotes {
                parts.push(&payload[start..i]);
                start = i + 1;
            }
        }
        if start < payload.len() {
            parts.push(&payload[start..]);
        }

        for part in parts {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim().trim_matches('"').to_string();
                map.insert(k, v);
            }
        }

        let realm = map.remove("realm")?;
        let nonce = map.remove("nonce")?;
        let opaque = map.remove("opaque");
        let qop = map.remove("qop");
        let algorithm = map.remove("algorithm");

        Some(DigestChallenge {
            realm,
            nonce,
            opaque,
            qop,
            algorithm,
        })
    }

    pub fn response_header(
        &self,
        user: &str,
        pass: &str,
        method: &str,
        uri: &str,
        nc_count: u32,
    ) -> String {
        // HA1 = MD5(username:realm:password)
        let ha1_raw = format!("{}:{}:{}", user, self.realm, pass);
        let mut hasher = Md5::new();
        hasher.update(ha1_raw.as_bytes());
        let ha1 = hex_digest(hasher.finalize());

        // HA2 = MD5(method:uri)
        let ha2_raw = format!("{}:{}", method, uri);
        let mut hasher = Md5::new();
        hasher.update(ha2_raw.as_bytes());
        let ha2 = hex_digest(hasher.finalize());

        let nc = format!("{:08x}", nc_count);
        let mut rng = rand::thread_rng();
        let mut cnonce_bytes = [0u8; 8];
        rng.fill_bytes(&mut cnonce_bytes);
        let cnonce = hex_bytes(&cnonce_bytes);

        let response = if let Some(qop) = &self.qop {
            let qop_val = if qop.contains("auth") { "auth" } else { qop };
            // response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
            let resp_raw = format!(
                "{}:{}:{}:{}:{}:{}",
                ha1, self.nonce, nc, cnonce, qop_val, ha2
            );
            let mut hasher = Md5::new();
            hasher.update(resp_raw.as_bytes());
            hex_digest(hasher.finalize())
        } else {
            // response = MD5(HA1:nonce:HA2)
            let resp_raw = format!("{}:{}:{}", ha1, self.nonce, ha2);
            let mut hasher = Md5::new();
            hasher.update(resp_raw.as_bytes());
            hex_digest(hasher.finalize())
        };

        let mut res = format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
            user, self.realm, self.nonce, uri, response
        );

        if let Some(qop) = &self.qop {
            let qop_val = if qop.contains("auth") { "auth" } else { qop };
            res.push_str(&format!(
                ", qop={}, nc={}, cnonce=\"{}\"",
                qop_val, nc, cnonce
            ));
        }

        if let Some(opaque) = &self.opaque {
            res.push_str(&format!(", opaque=\"{}\"", opaque));
        }

        res
    }
}

fn hex_digest(bytes: md5::digest::Output<Md5>) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_auth() {
        let h = basic_auth_header("user", "pass");
        assert_eq!(h, "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn test_digest_auth_parse() {
        let header = r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let challenge = DigestChallenge::parse(header).expect("parse challenge");
        assert_eq!(challenge.realm, "testrealm@host.com");
        assert_eq!(challenge.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
        assert_eq!(challenge.qop.as_deref(), Some("auth,auth-int"));
        assert_eq!(
            challenge.opaque.as_deref(),
            Some("5ccc069c403ebaf9f0171e9517f40e41")
        );

        let resp =
            challenge.response_header("Mufasa", "Circle Of Life", "CONNECT", "1.2.3.4:443", 1);
        assert!(resp.starts_with("Digest username=\"Mufasa\""));
        assert!(resp.contains("uri=\"1.2.3.4:443\""));
    }
}
