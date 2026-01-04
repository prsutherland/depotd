use crate::auth::AuthConfig;
use crate::storage::Storage;
use axum::{
    Router,
    routing::get,
};
use std::sync::Arc;

pub mod bucket;
pub mod object;
pub mod xml;

pub struct AppState<S> {
    pub storage: Arc<S>,
    pub auth_config: Option<Arc<AuthConfig>>,
    pub bucket_hostname_pattern: Option<String>,
    pub max_body_size: usize,
}

impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        AppState {
            storage: Arc::clone(&self.storage),
            auth_config: self.auth_config.clone(),
            bucket_hostname_pattern: self.bucket_hostname_pattern.clone(),
            max_body_size: self.max_body_size,
        }
    }
}


pub fn router<S: Storage + 'static>(
    storage: Arc<S>,
    auth_config: Option<Arc<AuthConfig>>,
    bucket_hostname_pattern: Option<String>,
    max_body_size: usize,
) -> Router {
    let app_state = AppState {
        storage,
        auth_config: auth_config.clone(),
        bucket_hostname_pattern,
        max_body_size,
    };

    Router::new()
        // All routes now use path-style after middleware rewriting
        .route("/", get(bucket::list_buckets))
        .route(
            "/:bucket",
            get(bucket::list_objects)
                .put(bucket::create_bucket)
                .delete(bucket::delete_bucket),
        )
        .route(
            "/:bucket/*key",
            get(object::get_object)
                .put(object::put_object)
                .delete(object::delete_object),
        )
        .with_state(app_state)
}

