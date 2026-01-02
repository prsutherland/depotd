use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub logging: Option<LoggingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    /// Hostname pattern for virtual-hosted-style bucket URLs.
    /// The pattern should contain `{bucket}` placeholder, e.g., `{bucket}.s3.example.com`.
    /// If not set, virtual-hosted-style URLs are disabled.
    pub bucket_hostname_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub root_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<PathBuf>,
}

impl Config {
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 9000,
                access_key: None,
                secret_key: None,
                bucket_hostname_pattern: None,
            },
            storage: StorageConfig {
                root_path: PathBuf::from("./data"),
            },
            logging: Some(LoggingConfig {
                level: "info".to_string(),
                file: None,
            }),
        }
    }
}
