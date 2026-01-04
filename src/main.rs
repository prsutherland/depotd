mod api;
mod auth;
mod config;
mod storage;
mod vhost_rewrite;

use anyhow::{Context, Result};
use clap::Parser;
use daemonize::Daemonize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::{Layer, ServiceBuilder};
use tower_http::trace::TraceLayer;
use tracing::{Level, info};
use tracing_subscriber;

use crate::auth::AuthConfig;
use crate::config::Config;
use crate::storage::FileStorage;

#[derive(Parser, Debug)]
#[command(name = "depotd")]
#[command(about = "S3-compatible API server daemon")]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: PathBuf,

    /// Run as daemon
    #[arg(short, long)]
    daemon: bool,

    /// PID file path (used when running as daemon)
    #[arg(short, long, default_value = "/tmp/depotd.pid")]
    pid_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration
    let config = Config::from_file(&args.config)
        .with_context(|| format!("Failed to load config from {:?}", args.config))?;

    // Initialize logging
    init_logging(&config)?;

    if args.daemon {
        info!("Starting depotd as daemon...");

        let daemonize = Daemonize::new()
            .pid_file(args.pid_file)
            .working_directory(".")
            .stdout(std::fs::File::create("/tmp/depotd.out")?)
            .stderr(std::fs::File::create("/tmp/depotd.err")?);

        match daemonize.start() {
            Ok(_) => {
                info!("Daemon started successfully");
            }
            Err(e) => {
                eprintln!("Error starting daemon: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Initialize storage
    let storage = Arc::new(FileStorage::new(&config)?);

    // Initialize auth config
    let auth_config = AuthConfig::from_config(&config)?;
    let auth_config = auth_config.map(Arc::new);

    if auth_config.is_some() {
        info!("Authentication enabled");
    } else {
        info!("Authentication disabled - running in open mode");
    }

    // Create router with tracing middleware (runs after routing)
    let max_body_size = config.server.max_body_size;
    let router = api::router(
        storage.clone(),
        auth_config.clone(),
        config.server.bucket_hostname_pattern.clone(),
        max_body_size,
    )
    .layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .into_inner(),
    );

    // Get state for bucket rewrite middleware
    let bucket_hostname_pattern = config.server.bucket_hostname_pattern.clone();
    let rewrite_state = api::AppState {
        storage,
        auth_config,
        bucket_hostname_pattern,
        max_body_size,
    };

    // Apply virtual-hosted style rewrite middleware around the entire Router
    // This must run BEFORE routing, so we use a custom Layer
    // Following the pattern from: https://docs.rs/axum/latest/axum/middleware/index.html#rewriting-request-uri-in-middleware
    let rewrite_layer = vhost_rewrite::vhost_rewrite_layer(rewrite_state);
    let app_with_rewrite = rewrite_layer.layer(router);

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Starting S3-compatible API server on {}", addr);

    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    info!("Server listening on {}", addr);

    // Convert the wrapped Service into a MakeService
    // Our custom BucketRewriteService implements Clone, so we can use BoxCloneService
    use tower::make::Shared;
    use tower::util::BoxCloneService;
    use axum::http::Request;
    use axum::response::Response;
    use std::convert::Infallible;
    
    // Box the service to make it work with Shared
    let boxed_service: BoxCloneService<Request<axum::body::Body>, Response, Infallible> = 
        BoxCloneService::new(app_with_rewrite);
    
    // Shared makes the service into a MakeService that can be used with axum::serve
    let make_service = Shared::new(boxed_service);
    axum::serve(listener, make_service).await?;

    Ok(())
}

fn init_logging(config: &Config) -> Result<()> {
    let level = config
        .logging
        .as_ref()
        .map(|l| l.level.as_str())
        .unwrap_or("info")
        .to_lowercase();

    let log_level = level.parse::<Level>().unwrap_or(Level::INFO);

    let subscriber_builder = tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false);

    if let Some(logging) = &config.logging {
        if let Some(ref log_file) = logging.file {
            let file = std::fs::File::create(log_file)?;
            subscriber_builder.with_writer(file).init();
        } else {
            subscriber_builder.init();
        }
    } else {
        subscriber_builder.init();
    }

    Ok(())
}
