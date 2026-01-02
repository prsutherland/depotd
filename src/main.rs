mod api;
mod auth;
mod config;
mod storage;

use anyhow::{Context, Result};
use clap::Parser;
use daemonize::Daemonize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
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

    // Create router
    let app = api::router(storage, auth_config).layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .into_inner(),
    );

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Starting S3-compatible API server on {}", addr);

    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    info!("Server listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

fn init_logging(config: &Config) -> Result<()> {
    let level = config
        .logging
        .as_ref()
        .map(|l| l.level.as_str())
        .unwrap_or("info");

    let log_level = match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

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
