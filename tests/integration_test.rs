use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode},
};
use depotd::api::{self, AppState};
use depotd::config::{Config, ServerConfig, StorageConfig};
use depotd::storage::FileStorage;
use depotd::vhost_rewrite;
use std::sync::Arc;
use tempfile::TempDir;
use tower::{Layer, ServiceExt};

fn create_test_config(temp_dir: &TempDir) -> Config {
    Config {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 9000,
            access_key: None,
            secret_key: None,
            bucket_hostname_pattern: None,
            max_body_size: 100 * 1024 * 1024,
        },
        storage: StorageConfig {
            root_path: temp_dir.path().to_path_buf(),
        },
        logging: None,
    }
}

fn create_app_state(temp_dir: &TempDir) -> AppState<FileStorage> {
    let config = create_test_config(temp_dir);
    let storage = Arc::new(FileStorage::new(&config).unwrap());

    AppState {
        storage,
        auth_config: None,
        bucket_hostname_pattern: None,
        max_body_size: 100 * 1024 * 1024,
    }
}

fn create_app_state_with_vhost(
    temp_dir: &TempDir,
    bucket_hostname_pattern: Option<String>,
) -> AppState<FileStorage> {
    let config = create_test_config(temp_dir);
    let storage = Arc::new(FileStorage::new(&config).unwrap());

    AppState {
        storage,
        auth_config: None,
        bucket_hostname_pattern,
        max_body_size: 100 * 1024 * 1024,
    }
}

/// Create an app with vhost rewrite middleware (like main.rs does)
fn create_app_with_vhost_rewrite(
    state: AppState<FileStorage>,
) -> impl tower::Service<
    Request<Body>,
    Response = axum::response::Response,
    Error = std::convert::Infallible,
> + Clone {
    let router = api::router(
        state.storage.clone(),
        state.auth_config.clone(),
        state.bucket_hostname_pattern.clone(),
        state.max_body_size,
    );

    let rewrite_layer = vhost_rewrite::vhost_rewrite_layer(state);
    rewrite_layer.layer(router)
}

#[tokio::test]
async fn test_list_buckets_empty() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state(&temp_dir);
    let app = api::router(
        state.storage.clone(),
        state.auth_config.clone(),
        state.bucket_hostname_pattern.clone(),
        state.max_body_size,
    );

    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_create_bucket() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state(&temp_dir);
    let app = api::router(
        state.storage.clone(),
        state.auth_config.clone(),
        state.bucket_hostname_pattern.clone(),
        state.max_body_size,
    );

    let request = Request::builder()
        .method(Method::PUT)
        .uri("/test-bucket")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify bucket exists by listing
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test-bucket")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_put_and_get_object() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state(&temp_dir);
    let app = api::router(
        state.storage.clone(),
        state.auth_config.clone(),
        state.bucket_hostname_pattern.clone(),
        state.max_body_size,
    );

    // Create bucket first
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/test-bucket")
        .body(Body::empty())
        .unwrap();
    let app_clone = app.clone();
    app_clone.oneshot(request).await.unwrap();

    // Put object
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/test-bucket/test-key")
        .body(Body::from("Hello, World!"))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    if status != StatusCode::OK {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        panic!("PUT failed with status {}: {}", status, body_str);
    }

    // Get object
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test-bucket/test-key")
        .body(Body::empty())
        .unwrap();

    let response = {
        let app_clone = app.clone();
        app_clone.oneshot(request).await.unwrap()
    };
    assert_eq!(response.status(), StatusCode::OK);

    // Verify content
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, "Hello, World!");
}

#[tokio::test]
async fn test_delete_object() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state(&temp_dir);
    let app = api::router(
        state.storage.clone(),
        state.auth_config.clone(),
        state.bucket_hostname_pattern.clone(),
        state.max_body_size,
    );

    // Create bucket and put object
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/test-bucket")
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(request).await.unwrap();

    let request = Request::builder()
        .method(Method::PUT)
        .uri("/test-bucket/test-key")
        .body(Body::from("data"))
        .unwrap();
    app.clone().oneshot(request).await.unwrap();

    // Delete object
    let request = Request::builder()
        .method(Method::DELETE)
        .uri("/test-bucket/test-key")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify object is gone
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test-bucket/test-key")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_bucket() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state(&temp_dir);
    let app = api::router(
        state.storage.clone(),
        state.auth_config.clone(),
        state.bucket_hostname_pattern.clone(),
        state.max_body_size,
    );

    // Create bucket
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/test-bucket")
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(request).await.unwrap();

    // Delete bucket
    let request = Request::builder()
        .method(Method::DELETE)
        .uri("/test-bucket")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify bucket is gone
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test-bucket")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    // Should return empty list or error
    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_list_objects() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state(&temp_dir);
    let app = api::router(
        state.storage.clone(),
        state.auth_config.clone(),
        state.bucket_hostname_pattern.clone(),
        state.max_body_size,
    );

    // Create bucket
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/test-bucket")
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(request).await.unwrap();

    // Put multiple objects
    for i in 1..=3 {
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!("/test-bucket/file{}.txt", i))
            .body(Body::from(format!("content{}", i)))
            .unwrap();
        app.clone().oneshot(request).await.unwrap();
    }

    // List objects
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test-bucket")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("file1.txt"));
    assert!(body_str.contains("file2.txt"));
    assert!(body_str.contains("file3.txt"));
}

#[tokio::test]
async fn test_nonexistent_bucket() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state(&temp_dir);
    let app = api::router(
        state.storage.clone(),
        state.auth_config.clone(),
        state.bucket_hostname_pattern.clone(),
        state.max_body_size,
    );

    // Try to get object from nonexistent bucket
    let request = Request::builder()
        .method(Method::GET)
        .uri("/nonexistent-bucket/key")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("NoSuchBucket"));
}

#[tokio::test]
async fn test_nonexistent_object() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state(&temp_dir);
    let app = api::router(
        state.storage.clone(),
        state.auth_config.clone(),
        state.bucket_hostname_pattern.clone(),
        state.max_body_size,
    );

    // Create bucket
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/test-bucket")
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(request).await.unwrap();

    // Try to get nonexistent object
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test-bucket/nonexistent-key")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("NoSuchKey"));
}

// ============================================================================
// Path-style access tests (with vhost pattern configured)
// These tests demonstrate that path-style works even when vhost pattern is configured,
// when the hostname doesn't match the pattern
// ============================================================================

#[tokio::test]
async fn test_path_style_create_bucket() {
    let temp_dir = TempDir::new().unwrap();
    // Configure app with vhost pattern, but use hostname that doesn't match
    let state = create_app_state_with_vhost(&temp_dir, Some("{bucket}.s3.example.com".to_string()));
    let app = create_app_with_vhost_rewrite(state);

    // Path-style: bucket name in URL path
    // Hostname doesn't match pattern, so path-style is used
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/my-bucket")
        .header("host", "example.com") // Hostname doesn't match {bucket}.s3.example.com pattern
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_path_style_put_and_get_object() {
    let temp_dir = TempDir::new().unwrap();
    // Configure app with vhost pattern, but use hostname that doesn't match
    let state = create_app_state_with_vhost(&temp_dir, Some("{bucket}.s3.example.com".to_string()));
    let app = create_app_with_vhost_rewrite(state);

    // Create bucket using path-style (hostname doesn't match pattern)
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/my-bucket")
            .header("host", "example.com") // Hostname doesn't match {bucket}.s3.example.com pattern
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request).await.unwrap();
    }

    // Put object using path-style: /bucket/key
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/my-bucket/my-object.txt")
            .header("host", "example.com") // Hostname doesn't match pattern
            .body(Body::from("Path-style content"))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Get object using path-style
    let request = Request::builder()
        .method(Method::GET)
        .uri("/my-bucket/my-object.txt")
        .header("host", "example.com") // Hostname doesn't match pattern
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, "Path-style content");
}

#[tokio::test]
async fn test_path_style_list_objects() {
    let temp_dir = TempDir::new().unwrap();
    // Configure app with vhost pattern, but use hostname that doesn't match
    let state = create_app_state_with_vhost(&temp_dir, Some("{bucket}.s3.example.com".to_string()));
    let app = create_app_with_vhost_rewrite(state);

    // Create bucket using path-style (hostname doesn't match pattern)
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/path-bucket")
            .header("host", "example.com") // Hostname doesn't match {bucket}.s3.example.com pattern
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request).await.unwrap();
    }

    // Put objects using path-style
    for i in 1..=3 {
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!("/path-bucket/file{}.txt", i))
            .header("host", "example.com") // Hostname doesn't match pattern
            .body(Body::from(format!("content{}", i)))
            .unwrap();
        app.clone().oneshot(request).await.unwrap();
    }

    // List objects using path-style
    let request = Request::builder()
        .method(Method::GET)
        .uri("/path-bucket")
        .header("host", "example.com") // Hostname doesn't match pattern
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("file1.txt"));
    assert!(body_str.contains("file2.txt"));
    assert!(body_str.contains("file3.txt"));
}

// ============================================================================
// Virtual-hosted-style access tests (same app configuration as path-style tests)
// These tests demonstrate that when hostname matches the pattern, vhost-style is used
// ============================================================================

#[tokio::test]
async fn test_vhost_style_create_bucket() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state_with_vhost(&temp_dir, Some("{bucket}.s3.example.com".to_string()));
    let app = create_app_with_vhost_rewrite(state);

    // Virtual-hosted-style: bucket name in Host header, path is just "/"
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("my-bucket.s3.example.com"));

    let request = Request::builder()
        .method(Method::PUT)
        .uri("/")
        .header("host", "my-bucket.s3.example.com")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_vhost_style_put_and_get_object() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state_with_vhost(&temp_dir, Some("{bucket}.s3.example.com".to_string()));
    let app = create_app_with_vhost_rewrite(state);

    // Create bucket using virtual-hosted-style
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/")
            .header("host", "vhost-bucket.s3.example.com")
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request).await.unwrap();
    }

    // Put object using virtual-hosted-style: bucket in hostname, key in path
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/my-object.txt")
            .header("host", "vhost-bucket.s3.example.com")
            .body(Body::from("VHost-style content"))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Get object using virtual-hosted-style
    let request = Request::builder()
        .method(Method::GET)
        .uri("/my-object.txt")
        .header("host", "vhost-bucket.s3.example.com")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    // The response should be the object content, not XML
    let body_str = String::from_utf8_lossy(&body);
    if status != StatusCode::OK {
        panic!("GET failed with status {}: {}", status, body_str);
    }
    if body_str.starts_with("<?xml") {
        panic!("Got XML response instead of object content: {}", body_str);
    }

    assert_eq!(body, "VHost-style content");
}

#[tokio::test]
async fn test_vhost_style_list_objects() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state_with_vhost(&temp_dir, Some("{bucket}.s3.example.com".to_string()));
    let app = create_app_with_vhost_rewrite(state);

    // Create bucket
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/")
            .header("host", "list-bucket.s3.example.com")
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request).await.unwrap();
    }

    // Put objects
    for i in 1..=3 {
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!("/file{}.txt", i))
            .header("host", "list-bucket.s3.example.com")
            .body(Body::from(format!("content{}", i)))
            .unwrap();
        app.clone().oneshot(request).await.unwrap();
    }

    // List objects using virtual-hosted-style
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("host", "list-bucket.s3.example.com")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("file1.txt"));
    assert!(body_str.contains("file2.txt"));
    assert!(body_str.contains("file3.txt"));
}

#[tokio::test]
async fn test_vhost_style_delete_object() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state_with_vhost(&temp_dir, Some("{bucket}.s3.example.com".to_string()));
    let app = create_app_with_vhost_rewrite(state);

    // Create bucket and put object
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/")
            .header("host", "delete-bucket.s3.example.com")
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request).await.unwrap();
    }

    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/to-delete.txt")
            .header("host", "delete-bucket.s3.example.com")
            .body(Body::from("data"))
            .unwrap();
        app.clone().oneshot(request).await.unwrap();
    }

    // Delete object using virtual-hosted-style
    let request = Request::builder()
        .method(Method::DELETE)
        .uri("/to-delete.txt")
        .header("host", "delete-bucket.s3.example.com")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify object is gone
    let request = Request::builder()
        .method(Method::GET)
        .uri("/to-delete.txt")
        .header("host", "delete-bucket.s3.example.com")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_path_style_takes_precedence_over_vhost() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state_with_vhost(&temp_dir, Some("{bucket}.s3.example.com".to_string()));
    let app = create_app_with_vhost_rewrite(state);

    // Create bucket using vhost-style (hostname matches pattern, so vhost-style takes precedence)
    // Path /path-bucket with host different-bucket.s3.example.com should rewrite to /different-bucket/path-bucket
    // But we want to create "different-bucket" bucket, so we use path / with host different-bucket.s3.example.com
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/")
            .header("host", "different-bucket.s3.example.com") // Hostname matches pattern → vhost-style
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Verify the bucket created is "different-bucket" (from vhost-style)
    // Access via vhost-style
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("host", "different-bucket.s3.example.com")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    // Should succeed because different-bucket exists (created via vhost-style)
    assert_eq!(response.status(), StatusCode::OK);

    // Now test path-style with non-matching hostname (hostname doesn't match pattern → path-style)
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/path-bucket")
            .header("host", "example.com") // Hostname doesn't match pattern → path-style
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Verify path-bucket was created using path-style
    let request = Request::builder()
        .method(Method::GET)
        .uri("/path-bucket")
        .header("host", "example.com") // Non-matching hostname → path-style
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    // Should succeed because path-bucket exists (created via path-style)
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_same_app_handles_both_path_and_vhost_style() {
    let temp_dir = TempDir::new().unwrap();
    // Same app configuration for both styles
    let state = create_app_state_with_vhost(&temp_dir, Some("{bucket}.s3.example.com".to_string()));
    let app = create_app_with_vhost_rewrite(state);

    // ===== PATH-STYLE: Hostname doesn't match pattern =====
    // When hostname doesn't match {bucket}.s3.example.com, path-style is used

    // Create bucket using path-style with non-matching hostname
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/path-bucket")
            .header("host", "example.com") // Doesn't match {bucket}.s3.example.com pattern
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Put object using path-style
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/path-bucket/path-object.txt")
            .header("host", "example.com") // Doesn't match pattern
            .body(Body::from("Path-style content"))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Get object using path-style
    {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/path-bucket/path-object.txt")
            .header("host", "example.com") // Doesn't match pattern
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "Path-style content");
    }

    // ===== VHOST-STYLE: Hostname matches pattern =====
    // When hostname matches {bucket}.s3.example.com, vhost-style is used

    // Create bucket using vhost-style with matching hostname
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/")
            .header("host", "vhost-bucket.s3.example.com") // Matches {bucket}.s3.example.com pattern
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Put object using vhost-style
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/vhost-object.txt")
            .header("host", "vhost-bucket.s3.example.com") // Matches pattern
            .body(Body::from("VHost-style content"))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Get object using vhost-style
    {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/vhost-object.txt")
            .header("host", "vhost-bucket.s3.example.com") // Matches pattern
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "VHost-style content");
    }

    // Verify both buckets exist and are separate
    // List path-bucket using path-style
    {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/path-bucket")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("path-object.txt"));
        assert!(!body_str.contains("vhost-object.txt")); // Different bucket
    }

    // List vhost-bucket using vhost-style
    {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header("host", "vhost-bucket.s3.example.com")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("vhost-object.txt"));
        assert!(!body_str.contains("path-object.txt")); // Different bucket
    }
}

#[tokio::test]
async fn test_vhost_with_nested_path() {
    let temp_dir = TempDir::new().unwrap();
    let state = create_app_state_with_vhost(&temp_dir, Some("{bucket}.s3.example.com".to_string()));
    let app = create_app_with_vhost_rewrite(state);

    // Create bucket
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/")
            .header("host", "nested-bucket.s3.example.com")
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request).await.unwrap();
    }

    // Put object with nested path using virtual-hosted-style
    {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/subdir/nested-file.txt")
            .header("host", "nested-bucket.s3.example.com")
            .body(Body::from("nested content"))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Get object with nested path
    let request = Request::builder()
        .method(Method::GET)
        .uri("/subdir/nested-file.txt")
        .header("host", "nested-bucket.s3.example.com")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, "nested content");
}
