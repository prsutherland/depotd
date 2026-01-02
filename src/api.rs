use crate::auth::{authenticate_request, error_response, AuthConfig};
use crate::storage::Storage;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{delete, get, put},
    Router,
};
use axum::body::to_bytes;
use serde::Deserialize;
use std::sync::Arc;

pub struct AppState<S> {
    pub storage: Arc<S>,
    pub auth_config: Option<Arc<AuthConfig>>,
}

impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        AppState {
            storage: Arc::clone(&self.storage),
            auth_config: self.auth_config.clone(),
        }
    }
}

pub fn router<S: Storage + 'static>(
    storage: Arc<S>,
    auth_config: Option<Arc<AuthConfig>>,
) -> Router {
    let app_state = AppState {
        storage,
        auth_config: auth_config.clone(),
    };

    Router::new()
        .route("/", get(list_buckets))
        .route("/:bucket", get(list_objects).put(create_bucket).delete(delete_bucket))
        .route("/:bucket/*key", get(get_object).put(put_object).delete(delete_object))
        .with_state(app_state)
}

async fn list_buckets<S: Storage>(
    State(state): State<AppState<S>>,
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

async fn create_bucket<S: Storage>(
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

async fn delete_bucket<S: Storage>(
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

async fn list_objects<S: Storage>(
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

    match storage.list_objects(&bucket, params.prefix.as_deref()).await {
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

async fn get_object<S: Storage>(
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

async fn put_object<S: Storage>(
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

async fn delete_object<S: Storage>(
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

