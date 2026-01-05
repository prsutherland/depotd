use crate::api::AppState;
use crate::storage::Storage;
use axum::{
    body::Body,
    http::{HeaderMap, Request, Uri},
};

/// Extract bucket name from Host header (virtual-hosted style) or path (path-style)
pub fn extract_bucket_name(
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

/// Function that rewrites request URI to include bucket from hostname pattern
/// This is used with the VhostRewriteLayer to rewrite URIs before routing
fn rewrite_request_uri_with_bucket<S: Storage + 'static>(
    mut request: Request<Body>,
    state: AppState<S>,
) -> Request<Body> {
    // Check if bucket is already in path (path-style)
    let uri = request.uri();
    let path = uri.path();

    // Try to extract bucket from Host header first (virtual-hosted style)
    let vhost_bucket = extract_bucket_name(
        request.headers(),
        None,
        uri,
        state.bucket_hostname_pattern.as_deref(),
    );

    // Check if path already has a bucket (path-style request)
    // Path-style: /bucket or /bucket/key
    // Virtual-hosted: / or /key (bucket in hostname)
    // When hostname matches the pattern, vhost-style takes precedence
    let has_bucket_in_path = if let Some(ref vhost_bucket_name) = vhost_bucket {
        // If we have a vhost bucket from hostname (hostname matches pattern):
        // - Vhost-style takes precedence, so we rewrite using the vhost bucket
        // - Only exception: if path segment matches vhost bucket name exactly, it's ambiguous
        //   In this case, we treat it as path-style to avoid double-rewriting
        if path.len() <= 1 {
            false
        } else {
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if segments.is_empty() {
                false
            } else {
                let first_segment = segments[0];
                // Only treat as path-style if path segment exactly matches vhost bucket
                // (to avoid rewriting /bucket to /bucket/bucket)
                first_segment == vhost_bucket_name.as_str()
            }
        }
    } else {
        // No vhost bucket (hostname doesn't match pattern) → use path-style
        if path.len() <= 1 {
            false
        } else {
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if segments.is_empty() {
                false
            } else {
                let first_segment = segments[0];
                // Consider it path-style if the segment looks like a bucket name
                first_segment.len() >= 3
                    && first_segment.len() <= 63
                    && first_segment.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'
                    })
            }
        }
    };

    // If path doesn't have a bucket, try to extract from hostname and rewrite
    if !has_bucket_in_path {
        if let Some(bucket) = vhost_bucket {
            // Rewrite the URI to include the bucket in the path
            let new_path = if path == "/" {
                format!("/{}", bucket)
            } else {
                format!("/{}{}", bucket, path)
            };

            // Preserve query string from original URI
            let new_path_and_query = if let Some(query) = uri.query() {
                format!("{}?{}", new_path, query)
            } else {
                new_path
            };

            // Reconstruct URI with new path
            let mut parts = uri.clone().into_parts();
            if let Ok(path_and_query) =
                axum::http::uri::PathAndQuery::from_maybe_shared(new_path_and_query)
            {
                parts.path_and_query = Some(path_and_query);

                if let Ok(new_uri) = Uri::from_parts(parts) {
                    *request.uri_mut() = new_uri;
                }
            }
        }
    }

    request
}

/// Layer that rewrites URIs based on virtual-hosted style requests
#[derive(Clone)]
pub struct VhostRewriteLayer<S> {
    state: std::sync::Arc<AppState<S>>,
}

impl<S: Storage + 'static> VhostRewriteLayer<S> {
    pub fn new(state: AppState<S>) -> Self {
        Self {
            state: std::sync::Arc::new(state),
        }
    }
}

impl<S: Storage + 'static, Inner> tower::Layer<Inner> for VhostRewriteLayer<S> {
    type Service = VhostRewriteService<S, Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        VhostRewriteService {
            inner,
            state: std::sync::Arc::clone(&self.state),
        }
    }
}

/// Service that rewrites request URIs based on virtual-hosted style
pub struct VhostRewriteService<S: Storage + 'static, Inner> {
    inner: Inner,
    state: std::sync::Arc<AppState<S>>,
}

impl<S: Storage + 'static, Inner> Clone for VhostRewriteService<S, Inner>
where
    Inner: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            state: std::sync::Arc::clone(&self.state),
        }
    }
}

impl<S: Storage + 'static, Inner> tower::Service<Request<Body>> for VhostRewriteService<S, Inner>
where
    Inner: tower::Service<
            Request<Body>,
            Response = axum::response::Response,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    Inner::Future: Send + 'static,
{
    type Response = Inner::Response;
    type Error = Inner::Error;
    type Future = Inner::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // Rewrite the URI
        let state = (*self.state).clone();
        req = rewrite_request_uri_with_bucket(req, state);

        // Call inner service
        self.inner.call(req)
    }
}

/// Create a layer that rewrites URIs based on virtual-hosted style requests
/// This must be applied around the entire Router (not as a layer on the Router)
/// so it runs before routing happens
pub fn vhost_rewrite_layer<S: Storage + 'static>(state: AppState<S>) -> VhostRewriteLayer<S> {
    VhostRewriteLayer::new(state)
}
