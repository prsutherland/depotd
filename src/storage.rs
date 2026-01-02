use crate::config::Config;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[async_trait]
pub trait Storage: Send + Sync {
    async fn list_buckets(&self) -> Result<Vec<String>>;
    async fn create_bucket(&self, bucket: &str) -> Result<()>;
    async fn delete_bucket(&self, bucket: &str) -> Result<()>;
    async fn bucket_exists(&self, bucket: &str) -> bool;
    async fn put_object(&self, bucket: &str, key: &str, data: Vec<u8>) -> Result<()>;
    async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>>;
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<()>;
    async fn list_objects(&self, bucket: &str, prefix: Option<&str>) -> Result<Vec<String>>;
}

pub struct FileStorage {
    root: PathBuf,
}

impl FileStorage {
    pub fn new(config: &Config) -> Result<Self> {
        let root = config.storage.root_path.clone();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("Failed to create storage root: {:?}", root))?;
        Ok(FileStorage { root })
    }

    fn bucket_path(&self, bucket: &str) -> PathBuf {
        self.root.join(bucket)
    }

    fn object_path(&self, bucket: &str, key: &str) -> PathBuf {
        self.bucket_path(bucket).join(key)
    }
}

#[async_trait]
impl Storage for FileStorage {
    async fn list_buckets(&self) -> Result<Vec<String>> {
        let mut buckets = Vec::new();
        let mut entries = fs::read_dir(&self.root).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    buckets.push(name.to_string());
                }
            }
        }

        Ok(buckets)
    }

    async fn create_bucket(&self, bucket: &str) -> Result<()> {
        let bucket_path = self.bucket_path(bucket);
        fs::create_dir_all(&bucket_path).await?;
        Ok(())
    }

    async fn delete_bucket(&self, bucket: &str) -> Result<()> {
        let bucket_path = self.bucket_path(bucket);
        if bucket_path.exists() {
            fs::remove_dir_all(&bucket_path).await?;
        }
        Ok(())
    }

    async fn bucket_exists(&self, bucket: &str) -> bool {
        self.bucket_path(bucket).exists()
    }

    async fn put_object(&self, bucket: &str, key: &str, data: Vec<u8>) -> Result<()> {
        let object_path = self.object_path(bucket, key);

        // Create parent directories if they don't exist
        if let Some(parent) = object_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut file = fs::File::create(&object_path).await?;
        file.write_all(&data).await?;
        file.sync_all().await?;

        Ok(())
    }

    async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>> {
        let object_path = self.object_path(bucket, key);
        let mut file = fs::File::open(&object_path).await?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).await?;
        Ok(data)
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        let object_path = self.object_path(bucket, key);
        if object_path.exists() {
            fs::remove_file(&object_path).await?;
        }
        Ok(())
    }

    async fn list_objects(&self, bucket: &str, prefix: Option<&str>) -> Result<Vec<String>> {
        let bucket_path = self.bucket_path(bucket);
        if !bucket_path.exists() {
            return Ok(Vec::new());
        }

        let mut objects = Vec::new();
        let prefix_path = prefix.map(|p| PathBuf::from(p));

        let mut entries = fs::read_dir(&bucket_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() {
                let relative_path = path.strip_prefix(&bucket_path)?;
                let key = relative_path.to_string_lossy().to_string();

                if let Some(ref prefix) = prefix_path {
                    if key.starts_with(prefix.to_string_lossy().as_ref()) {
                        objects.push(key);
                    }
                } else {
                    objects.push(key);
                }
            }
        }

        Ok(objects)
    }
}
