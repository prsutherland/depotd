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
        if !bucket
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        {
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
        // sync_all may fail in some environments (e.g., tests), so we ignore errors
        let _ = file.sync_all().await;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ServerConfig, StorageConfig};
    use tempfile::TempDir;

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

    #[tokio::test]
    async fn test_validate_bucket_name() {
        // Valid bucket names
        assert!(FileStorage::validate_bucket_name("my-bucket").is_ok());
        assert!(FileStorage::validate_bucket_name("my.bucket").is_ok());
        assert!(FileStorage::validate_bucket_name("bucket123").is_ok());
        assert!(FileStorage::validate_bucket_name(&"a".repeat(3)).is_ok());
        assert!(FileStorage::validate_bucket_name(&"a".repeat(63)).is_ok());

        // Invalid bucket names
        assert!(FileStorage::validate_bucket_name("").is_err());
        assert!(FileStorage::validate_bucket_name("ab").is_err()); // too short
        assert!(FileStorage::validate_bucket_name(&"a".repeat(64)).is_err()); // too long
        assert!(FileStorage::validate_bucket_name("MyBucket").is_err()); // uppercase
        assert!(FileStorage::validate_bucket_name(".bucket").is_err()); // starts with dot
        assert!(FileStorage::validate_bucket_name("bucket.").is_err()); // ends with dot
        assert!(FileStorage::validate_bucket_name("bucket..name").is_err()); // contains ..
    }

    #[tokio::test]
    async fn test_validate_key() {
        // Valid keys
        assert!(FileStorage::validate_key("my-key").is_ok());
        assert!(FileStorage::validate_key("path/to/file.txt").is_ok());
        assert!(FileStorage::validate_key("file.txt").is_ok());

        // Invalid keys - path traversal
        assert!(FileStorage::validate_key("../etc/passwd").is_err());
        assert!(FileStorage::validate_key("..").is_err());
        assert!(FileStorage::validate_key("path/../file").is_err());
        assert!(FileStorage::validate_key("//etc/passwd").is_err());
        assert!(FileStorage::validate_key("/absolute/path").is_err());
    }

    #[tokio::test]
    async fn test_create_and_list_buckets() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);
        let storage = FileStorage::new(&config).unwrap();

        // Initially no buckets
        let buckets = storage.list_buckets().await.unwrap();
        assert_eq!(buckets.len(), 0);

        // Create buckets
        storage.create_bucket("bucket1").await.unwrap();
        storage.create_bucket("bucket2").await.unwrap();

        // List buckets
        let mut buckets = storage.list_buckets().await.unwrap();
        buckets.sort();
        assert_eq!(buckets, vec!["bucket1", "bucket2"]);
    }

    #[tokio::test]
    async fn test_bucket_exists() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);
        let storage = FileStorage::new(&config).unwrap();

        assert!(!storage.bucket_exists("nonexistent").await);

        storage.create_bucket("test-bucket").await.unwrap();
        assert!(storage.bucket_exists("test-bucket").await);
    }

    #[tokio::test]
    async fn test_delete_bucket() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);
        let storage = FileStorage::new(&config).unwrap();

        storage.create_bucket("to-delete").await.unwrap();
        assert!(storage.bucket_exists("to-delete").await);

        storage.delete_bucket("to-delete").await.unwrap();
        assert!(!storage.bucket_exists("to-delete").await);
    }

    #[tokio::test]
    async fn test_put_and_get_object() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);
        let storage = FileStorage::new(&config).unwrap();

        storage.create_bucket("test-bucket").await.unwrap();

        let data = b"Hello, World!".to_vec();
        storage
            .put_object("test-bucket", "test-key", data.clone())
            .await
            .unwrap();

        let retrieved = storage.get_object("test-bucket", "test-key").await.unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_delete_object() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);
        let storage = FileStorage::new(&config).unwrap();

        storage.create_bucket("test-bucket").await.unwrap();
        storage
            .put_object("test-bucket", "to-delete", b"data".to_vec())
            .await
            .unwrap();

        storage
            .delete_object("test-bucket", "to-delete")
            .await
            .unwrap();

        assert!(
            storage
                .get_object("test-bucket", "to-delete")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_list_objects() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);
        let storage = FileStorage::new(&config).unwrap();

        storage.create_bucket("test-bucket").await.unwrap();

        storage
            .put_object("test-bucket", "file1.txt", b"data1".to_vec())
            .await
            .unwrap();
        storage
            .put_object("test-bucket", "subdir/file2.txt", b"data2".to_vec())
            .await
            .unwrap();
        storage
            .put_object("test-bucket", "file3.txt", b"data3".to_vec())
            .await
            .unwrap();

        let mut objects = storage.list_objects("test-bucket", None).await.unwrap();
        objects.sort();
        assert_eq!(objects, vec!["file1.txt", "file3.txt", "subdir/file2.txt"]);
    }

    #[tokio::test]
    async fn test_list_objects_with_prefix() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);
        let storage = FileStorage::new(&config).unwrap();

        storage.create_bucket("test-bucket").await.unwrap();

        storage
            .put_object("test-bucket", "prefix1/file1.txt", b"data1".to_vec())
            .await
            .unwrap();
        storage
            .put_object("test-bucket", "prefix1/file2.txt", b"data2".to_vec())
            .await
            .unwrap();
        storage
            .put_object("test-bucket", "prefix2/file3.txt", b"data3".to_vec())
            .await
            .unwrap();

        let mut objects = storage
            .list_objects("test-bucket", Some("prefix1"))
            .await
            .unwrap();
        objects.sort();
        assert_eq!(objects, vec!["prefix1/file1.txt", "prefix1/file2.txt"]);
    }

    #[tokio::test]
    async fn test_path_traversal_protection() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);
        let storage = FileStorage::new(&config).unwrap();

        storage.create_bucket("test-bucket").await.unwrap();

        // Attempt path traversal
        assert!(
            storage
                .put_object("test-bucket", "../etc/passwd", b"evil".to_vec())
                .await
                .is_err()
        );
        assert!(
            storage
                .get_object("test-bucket", "../etc/passwd")
                .await
                .is_err()
        );
        assert!(
            storage
                .delete_object("test-bucket", "../etc/passwd")
                .await
                .is_err()
        );
    }
}
