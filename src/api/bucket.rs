use super::{AppState, xml};
use crate::auth::authenticate_request;
use crate::storage::Storage;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ListObjectsQuery {
    prefix: Option<String>,
}

pub async fn list_buckets<S: Storage>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> impl IntoResponse {
    // After middleware rewriting, "/" route only matches when there's no bucket in hostname
    // If bucket was in hostname, middleware rewrote "/" to "/bucket" which matches "/:bucket" route

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
                return xml::error_response(code, &e.to_string(), StatusCode::FORBIDDEN);
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    match storage.list_buckets().await {
        Ok(buckets) => xml::list_buckets_response(&buckets),
        Err(e) => xml::error_response("InternalError", &e.to_string(), StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Handler for creating buckets (path-style, after middleware rewriting)
pub async fn create_bucket<S: Storage>(
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
                return xml::error_response(code, &e.to_string(), StatusCode::FORBIDDEN);
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
        Err(e) => xml::error_response("InternalError", &e.to_string(), StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Handler for deleting buckets (path-style, after middleware rewriting)
pub async fn delete_bucket<S: Storage>(
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
                return xml::error_response(code, &e.to_string(), StatusCode::FORBIDDEN);
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
        Err(e) => xml::error_response("InternalError", &e.to_string(), StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Handler for listing objects (path-style, after middleware rewriting)
pub async fn list_objects<S: Storage>(
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
                return xml::error_response(code, &e.to_string(), StatusCode::FORBIDDEN);
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    if !storage.bucket_exists(&bucket).await {
        return xml::error_response("NoSuchBucket", "The specified bucket does not exist", StatusCode::NOT_FOUND);
    }

    match storage.list_objects(&bucket, params.prefix.as_deref()).await {
        Ok(objects) => xml::list_objects_response(&bucket, &objects),
        Err(e) => xml::error_response("InternalError", &e.to_string(), StatusCode::INTERNAL_SERVER_ERROR),
    }
}
