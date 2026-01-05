use super::{AppState, xml};
use crate::auth::authenticate_request;
use crate::storage::Storage;
use axum::{
    body::Body,
    body::to_bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};

/// Handler for getting objects: /:bucket/*key
pub async fn get_object<S: Storage>(
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
                return xml::error_response(code, &e.to_string(), StatusCode::FORBIDDEN);
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    if !storage.bucket_exists(&bucket).await {
        return xml::error_response(
            "NoSuchBucket",
            "The specified bucket does not exist",
            StatusCode::NOT_FOUND,
        );
    }

    match storage.get_object(&bucket, &key).await {
        Ok(data) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(data))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap()
            }),
        Err(_) => xml::error_response(
            "NoSuchKey",
            "The specified key does not exist",
            StatusCode::NOT_FOUND,
        ),
    }
}

/// Handler for putting objects: /:bucket/*key
pub async fn put_object<S: Storage>(
    State(state): State<AppState<S>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Body,
) -> impl IntoResponse {
    // Read body first for authentication with size limit
    let max_size = state.max_body_size;
    let bytes = match to_bytes(body, max_size).await {
        Ok(bytes) => {
            let vec = bytes.to_vec();
            if vec.len() > max_size {
                return xml::error_response(
                    "EntityTooLarge",
                    &format!(
                        "Request entity too large. Maximum size is {} bytes",
                        max_size
                    ),
                    StatusCode::PAYLOAD_TOO_LARGE,
                );
            }
            vec
        }
        Err(e) => {
            // Check if error is due to size limit
            let error_msg = e.to_string();
            if error_msg.contains("too large") || error_msg.contains("limit") {
                return xml::error_response(
                    "EntityTooLarge",
                    &format!(
                        "Request entity too large. Maximum size is {} bytes",
                        max_size
                    ),
                    StatusCode::PAYLOAD_TOO_LARGE,
                );
            }
            return xml::error_response(
                "InternalError",
                &error_msg,
                StatusCode::INTERNAL_SERVER_ERROR,
            );
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
                return xml::error_response(code, &e.to_string(), StatusCode::FORBIDDEN);
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    if !storage.bucket_exists(&bucket).await {
        // Auto-create bucket if it doesn't exist
        if let Err(e) = storage.create_bucket(&bucket).await {
            return xml::error_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    }

    match storage.put_object(&bucket, &key, bytes).await {
        Ok(_) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap()
            }),
        Err(e) => xml::error_response(
            "InternalError",
            &e.to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}

/// Handler for deleting objects: /:bucket/*key
pub async fn delete_object<S: Storage>(
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
                return xml::error_response(code, &e.to_string(), StatusCode::FORBIDDEN);
            }
            Ok(_) => {}
        }
    }

    let storage = &state.storage;
    match storage.delete_object(&bucket, &key).await {
        Ok(_) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap()
            }),
        Err(e) => xml::error_response(
            "InternalError",
            &e.to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}
