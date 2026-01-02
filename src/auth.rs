use crate::config::Config;
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use url::Url;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct AuthConfig {
    pub access_key: String,
    pub secret_key: String,
}

impl AuthConfig {
    pub fn from_config(config: &Config) -> anyhow::Result<Option<Self>> {
        match (&config.server.access_key, &config.server.secret_key) {
            (Some(access_key), Some(secret_key)) => Ok(Some(AuthConfig {
                access_key: access_key.clone(),
                secret_key: secret_key.clone(),
            })),
            (None, None) => Ok(None),
            _ => Err(anyhow::anyhow!(
                "Both access_key and secret_key must be provided together"
            )),
        }
    }
}

pub fn error_response(code: &str, message: &str) -> Response {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>{}</Code>
  <Message>{}</Message>
</Error>"#,
        code, message
    );
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Content-Type", "application/xml")
        .body(axum::body::Body::from(xml))
        .unwrap()
}

pub fn verify_signature(
    auth_config: &AuthConfig,
    method: &str,
    uri: &str,
    headers: &HeaderMap,
    body_hash: &str,
) -> anyhow::Result<bool> {
    // Extract Authorization header
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| anyhow::anyhow!("Missing Authorization header"))?
        .to_str()?;

    // Parse Authorization header: AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;

    for part in auth_header.split(',') {
        let part = part.trim();
        if part.starts_with("Credential=") {
            credential = Some(part.strip_prefix("Credential=").unwrap());
        } else if part.starts_with("SignedHeaders=") {
            signed_headers = Some(part.strip_prefix("SignedHeaders=").unwrap());
        } else if part.starts_with("Signature=") {
            signature = Some(part.strip_prefix("Signature=").unwrap());
        }
    }

    let credential = credential.ok_or_else(|| anyhow::anyhow!("Missing Credential"))?;
    let signed_headers = signed_headers.ok_or_else(|| anyhow::anyhow!("Missing SignedHeaders"))?;
    let signature = signature.ok_or_else(|| anyhow::anyhow!("Missing Signature"))?;

    // Parse credential: access_key/date/region/service/aws4_request
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 {
        return Err(anyhow::anyhow!("Invalid credential format"));
    }

    let access_key = parts[0];
    let date = parts[1];
    let region = parts[2];
    let service = parts[3];

    if access_key != auth_config.access_key {
        return Ok(false);
    }

    // Extract date from headers
    let amz_date = headers
        .get("x-amz-date")
        .ok_or_else(|| anyhow::anyhow!("Missing x-amz-date header"))?
        .to_str()?;

    // Build canonical request
    let canonical_uri = canonicalize_uri(uri)?;
    let canonical_query_string = canonicalize_query_string(uri)?;
    let canonical_headers = canonicalize_headers(headers, signed_headers)?;
    let signed_headers_list = signed_headers;

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        canonical_uri,
        canonical_query_string,
        canonical_headers,
        signed_headers_list,
        body_hash
    );

    // Create string to sign
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{}/{}/aws4_request\n{}",
        amz_date,
        date,
        region,
        service,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    // Calculate signature
    let date_key = hmac_sha256(format!("AWS4{}", auth_config.secret_key).as_bytes(), date);
    let date_region_key = hmac_sha256(&date_key, region);
    let date_region_service_key = hmac_sha256(&date_region_key, service);
    let signing_key = hmac_sha256(&date_region_service_key, "aws4_request");

    let computed_signature = hex::encode(hmac_sha256(&signing_key, &string_to_sign));

    Ok(computed_signature == signature)
}

fn canonicalize_uri(uri: &str) -> anyhow::Result<String> {
    let url = Url::parse(uri)?;
    let path = url.path();
    
    // URL encode the path (but preserve /)
    let mut encoded = String::new();
    for segment in path.split('/') {
        if !encoded.is_empty() {
            encoded.push('/');
        }
        encoded.push_str(&percent_encode(segment));
    }
    
    Ok(encoded)
}

fn canonicalize_query_string(uri: &str) -> anyhow::Result<String> {
    let url = Url::parse(uri)?;
    let mut params: Vec<(String, String)> = Vec::new();
    
    for (key, value) in url.query_pairs() {
        params.push((
            percent_encode(&key.to_string()),
            percent_encode(&value.to_string()),
        ));
    }
    
    params.sort_by(|a, b| {
        if a.0 != b.0 {
            a.0.cmp(&b.0)
        } else {
            a.1.cmp(&b.1)
        }
    });
    
    Ok(params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&"))
}

fn canonicalize_headers(headers: &HeaderMap, signed_headers: &str) -> anyhow::Result<String> {
    let mut header_list: Vec<(String, String)> = Vec::new();
    let signed_header_names: Vec<&str> = signed_headers.split(';').collect();
    
    for name in &signed_header_names {
        let name_lower = name.to_lowercase();
        if let Some(value) = headers.get(*name) {
            let value_str = value.to_str()?.trim();
            header_list.push((name_lower, value_str.to_string()));
        }
    }
    
    header_list.sort_by(|a, b| a.0.cmp(&b.0));
    
    Ok(header_list
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n")
}

fn percent_encode(s: &str) -> String {
    let mut encoded = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub fn calculate_body_hash(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

pub async fn authenticate_request(
    auth_config: Option<&AuthConfig>,
    method: &str,
    uri: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> anyhow::Result<()> {
    let auth_config = match auth_config {
        Some(config) => config,
        None => return Ok(()), // No auth required
    };

    // Check for required headers
    if !headers.contains_key("authorization") {
        return Err(anyhow::anyhow!("Missing Authorization header"));
    }

    if !headers.contains_key("x-amz-date") {
        return Err(anyhow::anyhow!("Missing x-amz-date header"));
    }

    // Calculate body hash
    let body_hash = calculate_body_hash(body);

    // Verify signature
    if !verify_signature(auth_config, method, uri, headers, &body_hash)? {
        return Err(anyhow::anyhow!("Invalid signature"));
    }

    Ok(())
}

