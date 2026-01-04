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

    /// Validate that a key doesn't contain path traversal attempts
    fn validate_key(key: &str) -> Result<()> {
        // Prevent path traversal attacks
        if key.contains("..") || key.contains("//") || key.starts_with('/') {
            return Err(anyhow::anyhow!("Invalid key: path traversal detected"));
        }
        // Prevent absolute paths
        if PathBuf::from(key).is_absolute() {
            return Err(anyhow::anyhow!("Invalid key: absolute path not allowed"));
        }
        Ok(())
    }

    /// Validate bucket name according to S3 rules
    fn validate_bucket_name(bucket: &str) -> Result<()> {
        if bucket.is_empty() {
            return Err(anyhow::anyhow!("Bucket name cannot be empty"));
        }
        if bucket.len() < 3 || bucket.len() > 63 {
            return Err(anyhow::anyhow!("Bucket name must be 3-63 characters"));
        }
        // S3 bucket naming rules
        if !bucket.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'
        }) {
            return Err(anyhow::anyhow!("Bucket name contains invalid characters"));
        }
        if bucket.starts_with('.') || bucket.ends_with('.') {
            return Err(anyhow::anyhow!("Bucket name cannot start or end with '.'"));
        }
        if bucket.contains("..") {
            return Err(anyhow::anyhow!("Bucket name cannot contain '..'"));
        }
        Ok(())
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
        Self::validate_bucket_name(bucket)?;
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
        match fs::metadata(self.bucket_path(bucket)).await {
            Ok(metadata) => metadata.is_dir(),
            Err(_) => false,
        }
    }

    async fn put_object(&self, bucket: &str, key: &str, data: Vec<u8>) -> Result<()> {
        Self::validate_key(key)?;
        
        let object_path = self.object_path(bucket, key);
        
        // Ensure the resolved path is still within the bucket directory
        let bucket_path = self.bucket_path(bucket);
        if !object_path.starts_with(&bucket_path) {
            return Err(anyhow::anyhow!("Invalid key: path traversal detected"));
        }

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
        Self::validate_key(key)?;
        
        let object_path = self.object_path(bucket, key);
        
        // Ensure the resolved path is still within the bucket directory
        let bucket_path = self.bucket_path(bucket);
        if !object_path.starts_with(&bucket_path) {
            return Err(anyhow::anyhow!("Invalid key: path traversal detected"));
        }
        
        let mut file = fs::File::open(&object_path).await?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).await?;
        Ok(data)
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        Self::validate_key(key)?;
        
        let object_path = self.object_path(bucket, key);
        
        // Ensure the resolved path is still within the bucket directory
        let bucket_path = self.bucket_path(bucket);
        if !object_path.starts_with(&bucket_path) {
            return Err(anyhow::anyhow!("Invalid key: path traversal detected"));
        }
        
        match fs::metadata(&object_path).await {
            Ok(metadata) if metadata.is_file() => {
                fs::remove_file(&object_path).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn list_objects(&self, bucket: &str, prefix: Option<&str>) -> Result<Vec<String>> {
        let bucket_path = self.bucket_path(bucket);
        
        // Check if bucket exists using async
        match fs::metadata(&bucket_path).await {
            Ok(metadata) if metadata.is_dir() => {}
            _ => return Ok(Vec::new()),
        }

        let mut objects = Vec::new();
        let prefix_str = prefix.map(|p| p.to_string());

        // Iteratively walk the directory tree using a stack
        let mut stack = vec![bucket_path.clone()];
        
        while let Some(current) = stack.pop() {
            let mut entries = fs::read_dir(&current).await?;
            
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let metadata = fs::metadata(&path).await?;
                
                if metadata.is_file() {
                    let relative_path = path.strip_prefix(&bucket_path)?;
                    let key = relative_path.to_string_lossy().to_string();

                    if let Some(ref prefix_str) = prefix_str {
                        if key.starts_with(prefix_str) {
                            objects.push(key);
                        }
                    } else {
                        objects.push(key);
                    }
                } else if metadata.is_dir() {
                    // Add subdirectory to stack for processing
                    stack.push(path);
                }
            }
        }

        Ok(objects)
    }
}
