use crate::auth::{AuthConfig, authenticate_request, error_response};
use crate::storage::Storage;
use axum::body::to_bytes;
use axum::{
    Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{delete, get, put},
};
use serde::Deserialize;
use std::sync::Arc;

/// Extract bucket name from Host header (virtual-hosted style) or path (path-style)
fn extract_bucket_name(
    headers: &HeaderMap,
    path_bucket: Option<&str>,
    uri: &Uri,
    bucket_hostname_pattern: Option<&str>,
) -> Option<String> {
    // If bucket is in path, use path-style
    if let Some(bucket) = path_bucket {
        return Some(bucket.to_string());
    }

    // Try virtual-hosted style only if pattern is configured
    let pattern = match bucket_hostname_pattern {
        Some(p) => p,
        None => return None,
    };

    if let Some(host) = headers.get("host").and_then(|h| h.to_str().ok()) {
        // Remove port if present
        let host_without_port = host.split(':').next().unwrap_or(host);

        // Parse pattern: {bucket}.s3.example.com -> extract bucket from host
        if let Some(bucket_placeholder) = pattern.find("{bucket}") {
            // Replace {bucket} with actual bucket name
            let before = &pattern[..bucket_placeholder];
            let after = &pattern[bucket_placeholder + "{bucket}".len()..];

            // Match host against pattern
            if host_without_port.starts_with(before) && host_without_port.ends_with(after) {
                let bucket_start = before.len();
                let bucket_end = host_without_port.len() - after.len();

                if bucket_start < bucket_end {
                    let potential_bucket = &host_without_port[bucket_start..bucket_end];

                    // Validate bucket name: S3 bucket names: 3-63 chars, lowercase letters, numbers, dots, hyphens
                    if !potential_bucket.is_empty()
                        && potential_bucket.len() >= 3
                        && potential_bucket.len() <= 63
                        && potential_bucket.chars().all(|c| {
                            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'
                        })
                    {
                        // For virtual-hosted style, path should not start with bucket name
                        // Path should be "/" or "/key" or "/key/path"
                        if !uri.path().starts_with(&format!("/{}", potential_bucket)) {
                            return Some(potential_bucket.to_string());
                        }
                    }
                }
            }
        } else {
            // Pattern doesn't contain {bucket}, treat as base domain
            // Extract subdomain as bucket name
            if host_without_port.ends_with(pattern) {
                let subdomain = host_without_port
                    .strip_suffix(pattern)
                    .and_then(|s| s.strip_suffix("."))
                    .filter(|s| !s.is_empty());

                if let Some(potential_bucket) = subdomain {
                    // Validate bucket name
                    if potential_bucket.len() >= 3
                        && potential_bucket.len() <= 63
                        && potential_bucket.chars().all(|c| {
                            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'
                        })
                    {
                        if !uri.path().starts_with(&format!("/{}", potential_bucket)) {
                            return Some(potential_bucket.to_string());
                        }
                    }
                }
            }
        }
    }

    None
}

pub struct AppState<S> {
    pub storage: Arc<S>,
    pub auth_config: Option<Arc<AuthConfig>>,
    pub bucket_hostname_pattern: Option<String>,
}

impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        AppState {
            storage: Arc::clone(&self.storage),
            auth_config: self.auth_config.clone(),
            bucket_hostname_pattern: self.bucket_hostname_pattern.clone(),
        }
    }
}

pub fn router<S: Storage + 'static>(
    storage: Arc<S>,
    auth_config: Option<Arc<AuthConfig>>,
    bucket_hostname_pattern: Option<String>,
) -> Router {
    let app_state = AppState {
        storage,
        auth_config: auth_config.clone(),
        bucket_hostname_pattern,
    };

    Router::new()
        // Path-style routes
        .route("/", get(list_buckets))
        .route(
            "/:bucket",
            get(list_objects_path)
                .put(create_bucket_path)
                .delete(delete_bucket_path),
        )
        .route(
            "/:bucket/*key",
            get(get_object_path)
                .put(put_object_path)
                .delete(delete_object_path),
        )
        // Virtual-hosted style routes (bucket in Host header)
        // Note: "/" route handles both list_buckets (no bucket) and list_objects_vhost (with bucket in Host)
        .route(
            "/*key",
            get(get_object_vhost)
                .put(put_object_vhost)
                .delete(delete_object_vhost),
        )
        .with_state(app_state)
}

async fn list_buckets<S: Storage>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> impl IntoResponse {
    // Check if this is a virtual-hosted style request (bucket in Host header)
    if let Some(bucket) = extract_bucket_name(
        &headers,
        None,
        &uri,
        state.bucket_hostname_pattern.as_deref(),
    ) {
        // This is actually a list objects request for a bucket
        return list_objects_vhost_internal(state, bucket, headers, method, uri).await;
    }

    // Check authentication
    if let Some(ref auth_config) = state.auth_config {
        match authenticate_request(
            Some(auth_config),
            method.as_str(),
            &uri.to_string(),
            &headers,
            &[],
        )
        .await
        {
            Err(e) => {
                let code = if e.to_string().contains("Missing") {
                    "AccessDenied"
                } else {
                    "SignatureDoesNotMatch"
                };
                return error_response(code, &e.to_string());
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    match storage.list_buckets().await {
        Ok(buckets) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult>
  <Buckets>
{}
  </Buckets>
</ListAllMyBucketsResult>"#,
                buckets
                    .iter()
                    .map(|b| format!("    <Bucket><Name>{}</Name></Bucket>", b))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
    }
}

async fn create_bucket_path<S: Storage>(
    State(state): State<AppState<S>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> impl IntoResponse {
    // Check authentication
    if let Some(ref auth_config) = state.auth_config {
        match authenticate_request(
            Some(auth_config),
            method.as_str(),
            &uri.to_string(),
            &headers,
            &[],
        )
        .await
        {
            Err(e) => {
                let code = if e.to_string().contains("Missing") {
                    "AccessDenied"
                } else {
                    "SignatureDoesNotMatch"
                };
                return error_response(code, &e.to_string());
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    match storage.create_bucket(&bucket).await {
        Ok(_) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
    }
}

async fn delete_bucket_path<S: Storage>(
    State(state): State<AppState<S>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> impl IntoResponse {
    // Check authentication
    if let Some(ref auth_config) = state.auth_config {
        match authenticate_request(
            Some(auth_config),
            method.as_str(),
            &uri.to_string(),
            &headers,
            &[],
        )
        .await
        {
            Err(e) => {
                let code = if e.to_string().contains("Missing") {
                    "AccessDenied"
                } else {
                    "SignatureDoesNotMatch"
                };
                return error_response(code, &e.to_string());
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    match storage.delete_bucket(&bucket).await {
        Ok(_) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
    }
}

#[derive(Deserialize)]
struct ListObjectsQuery {
    prefix: Option<String>,
}

async fn list_objects_path<S: Storage>(
    State(state): State<AppState<S>>,
    Path(bucket): Path<String>,
    Query(params): Query<ListObjectsQuery>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> impl IntoResponse {
    // Check authentication
    if let Some(ref auth_config) = state.auth_config {
        match authenticate_request(
            Some(auth_config),
            method.as_str(),
            &uri.to_string(),
            &headers,
            &[],
        )
        .await
        {
            Err(e) => {
                let code = if e.to_string().contains("Missing") {
                    "AccessDenied"
                } else {
                    "SignatureDoesNotMatch"
                };
                return error_response(code, &e.to_string());
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    if !storage.bucket_exists(&bucket).await {
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
</Error>"#
        );
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/xml")
            .body(Body::from(xml))
            .unwrap();
    }

    match storage
        .list_objects(&bucket, params.prefix.as_deref())
        .await
    {
        Ok(objects) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>{}</Name>
  <Contents>
{}
  </Contents>
</ListBucketResult>"#,
                bucket,
                objects
                    .iter()
                    .map(|o| format!("    <Key>{}</Key>", o))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
    }
}

async fn get_object_path<S: Storage>(
    State(state): State<AppState<S>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> impl IntoResponse {
    // Check authentication
    if let Some(ref auth_config) = state.auth_config {
        match authenticate_request(
            Some(auth_config),
            method.as_str(),
            &uri.to_string(),
            &headers,
            &[],
        )
        .await
        {
            Err(e) => {
                let code = if e.to_string().contains("Missing") {
                    "AccessDenied"
                } else {
                    "SignatureDoesNotMatch"
                };
                return error_response(code, &e.to_string());
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    if !storage.bucket_exists(&bucket).await {
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
</Error>"#
        );
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/xml")
            .body(Body::from(xml))
            .unwrap();
    }

    match storage.get_object(&bucket, &key).await {
        Ok(data) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(data))
            .unwrap(),
        Err(_) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist</Message>
</Error>"#
            );
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
    }
}

async fn put_object_path<S: Storage>(
    State(state): State<AppState<S>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Body,
) -> impl IntoResponse {
    // Read body first for authentication
    let bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap();
        }
    };

    // Check authentication
    if let Some(ref auth_config) = state.auth_config {
        match authenticate_request(
            Some(auth_config),
            method.as_str(),
            &uri.to_string(),
            &headers,
            &bytes,
        )
        .await
        {
            Err(e) => {
                let code = if e.to_string().contains("Missing") {
                    "AccessDenied"
                } else {
                    "SignatureDoesNotMatch"
                };
                return error_response(code, &e.to_string());
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    if !storage.bucket_exists(&bucket).await {
        // Auto-create bucket if it doesn't exist
        if let Err(e) = storage.create_bucket(&bucket).await {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap();
        }
    }

    match storage.put_object(&bucket, &key, bytes).await {
        Ok(_) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
    }
}

async fn delete_object_path<S: Storage>(
    State(state): State<AppState<S>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> impl IntoResponse {
    // Check authentication
    if let Some(ref auth_config) = state.auth_config {
        match authenticate_request(
            Some(auth_config),
            method.as_str(),
            &uri.to_string(),
            &headers,
            &[],
        )
        .await
        {
            Err(e) => {
                let code = if e.to_string().contains("Missing") {
                    "AccessDenied"
                } else {
                    "SignatureDoesNotMatch"
                };
                return error_response(code, &e.to_string());
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    match storage.delete_object(&bucket, &key).await {
        Ok(_) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
    }
}

// Helper function for virtual-hosted style list objects
async fn list_objects_vhost_internal<S: Storage>(
    state: AppState<S>,
    bucket: String,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    // Check authentication
    if let Some(ref auth_config) = state.auth_config {
        match authenticate_request(
            Some(auth_config),
            method.as_str(),
            &uri.to_string(),
            &headers,
            &[],
        )
        .await
        {
            Err(e) => {
                let code = if e.to_string().contains("Missing") {
                    "AccessDenied"
                } else {
                    "SignatureDoesNotMatch"
                };
                return error_response(code, &e.to_string());
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    if !storage.bucket_exists(&bucket).await {
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
</Error>"#
        );
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/xml")
            .body(Body::from(xml))
            .unwrap();
    }

    // Parse query parameters
    let prefix = uri.query().and_then(|q| {
        url::Url::parse(&format!("http://example.com?{}", q))
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find(|(k, _)| k == "prefix")
                    .map(|(_, v)| v.to_string())
            })
    });

    match storage.list_objects(&bucket, prefix.as_deref()).await {
        Ok(objects) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>{}</Name>
  <Contents>
{}
  </Contents>
</ListBucketResult>"#,
                bucket,
                objects
                    .iter()
                    .map(|o| format!("    <Key>{}</Key>", o))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
    }
}

// Virtual-hosted style handlers (bucket in Host header)
async fn get_object_vhost<S: Storage>(
    State(state): State<AppState<S>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> impl IntoResponse {
    // Extract bucket from Host header
    let bucket = match extract_bucket_name(
        &headers,
        None,
        &uri,
        state.bucket_hostname_pattern.as_deref(),
    ) {
        Some(b) => b,
        None => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InvalidRequest</Code>
  <Message>Could not determine bucket name</Message>
</Error>"#
            );
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap();
        }
    };

    // Check authentication
    if let Some(ref auth_config) = state.auth_config {
        match authenticate_request(
            Some(auth_config),
            method.as_str(),
            &uri.to_string(),
            &headers,
            &[],
        )
        .await
        {
            Err(e) => {
                let code = if e.to_string().contains("Missing") {
                    "AccessDenied"
                } else {
                    "SignatureDoesNotMatch"
                };
                return error_response(code, &e.to_string());
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    if !storage.bucket_exists(&bucket).await {
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
</Error>"#
        );
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/xml")
            .body(Body::from(xml))
            .unwrap();
    }

    match storage.get_object(&bucket, &key).await {
        Ok(data) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(data))
            .unwrap(),
        Err(_) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist</Message>
</Error>"#
            );
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
    }
}

async fn put_object_vhost<S: Storage>(
    State(state): State<AppState<S>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Body,
) -> impl IntoResponse {
    // Extract bucket from Host header
    let bucket = match extract_bucket_name(
        &headers,
        None,
        &uri,
        state.bucket_hostname_pattern.as_deref(),
    ) {
        Some(b) => b,
        None => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InvalidRequest</Code>
  <Message>Could not determine bucket name</Message>
</Error>"#
            );
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap();
        }
    };

    // Read body first for authentication
    let bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap();
        }
    };

    // Check authentication
    if let Some(ref auth_config) = state.auth_config {
        match authenticate_request(
            Some(auth_config),
            method.as_str(),
            &uri.to_string(),
            &headers,
            &bytes,
        )
        .await
        {
            Err(e) => {
                let code = if e.to_string().contains("Missing") {
                    "AccessDenied"
                } else {
                    "SignatureDoesNotMatch"
                };
                return error_response(code, &e.to_string());
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    if !storage.bucket_exists(&bucket).await {
        // Auto-create bucket if it doesn't exist
        if let Err(e) = storage.create_bucket(&bucket).await {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap();
        }
    }

    match storage.put_object(&bucket, &key, bytes).await {
        Ok(_) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
    }
}

async fn delete_object_vhost<S: Storage>(
    State(state): State<AppState<S>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> impl IntoResponse {
    // Extract bucket from Host header
    let bucket = match extract_bucket_name(
        &headers,
        None,
        &uri,
        state.bucket_hostname_pattern.as_deref(),
    ) {
        Some(b) => b,
        None => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InvalidRequest</Code>
  <Message>Could not determine bucket name</Message>
</Error>"#
            );
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap();
        }
    };

    // Check authentication
    if let Some(ref auth_config) = state.auth_config {
        match authenticate_request(
            Some(auth_config),
            method.as_str(),
            &uri.to_string(),
            &headers,
            &[],
        )
        .await
        {
            Err(e) => {
                let code = if e.to_string().contains("Missing") {
                    "AccessDenied"
                } else {
                    "SignatureDoesNotMatch"
                };
                return error_response(code, &e.to_string());
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    match storage.delete_object(&bucket, &key).await {
        Ok(_) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>{}</Message>
</Error>"#,
                e
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
    }
}
