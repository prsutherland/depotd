# depotd

An S3-compatible API server daemon.

## Features

- S3-compatible REST API endpoints
- AWS Signature Version 4 (SigV4) authentication support
- File-based storage backend
- Daemon mode support
- Configurable via TOML configuration file
- Logging support

## Building

```bash
cargo build --release
```

## Configuration

Create a configuration file (see `depotd.toml.example` for reference):

```toml
[server]
host = "127.0.0.1"
port = 9000
# Optional: If not provided, server runs in open mode (no authentication)
access_key = "your-access-key"
secret_key = "your-secret-key"

[storage]
root_path = "./data"

[logging]
level = "info"
```

## Usage

### Run in foreground:

```bash
./target/release/depotd --config depotd.toml
```

### Run as daemon:

```bash
./target/release/depotd --config depotd.toml --daemon --pid-file /tmp/depotd.pid
```

## API Endpoints

The server implements the following S3-compatible endpoints:

- `GET /` - List all buckets
- `PUT /:bucket` - Create a bucket
- `DELETE /:bucket` - Delete a bucket
- `GET /:bucket` - List objects in a bucket (supports `?prefix=` query parameter)
- `GET /:bucket/*key` - Get an object
- `PUT /:bucket/*key` - Put an object
- `DELETE /:bucket/*key` - Delete an object

## Storage

Objects are stored in the filesystem under the `root_path` specified in the
configuration. Each bucket is a directory, and objects are files within those
directories.

## Authentication

The server supports AWS Signature Version 4 (SigV4) authentication. If
`access_key` and `secret_key` are configured, all requests must be
authenticated. If not configured, the server runs in open mode without
authentication.

## Example Usage with AWS CLI

```bash
# Configure AWS CLI to use depotd
aws configure set endpoint-url http://127.0.0.1:9000
aws configure set aws_access_key_id your-access-key
aws configure set aws_secret_access_key your-secret-key

# Create a bucket
aws s3 mb s3://my-bucket

# Upload a file
aws s3 cp myfile.txt s3://my-bucket/

# List objects
aws s3 ls s3://my-bucket/

# Download a file
aws s3 cp s3://my-bucket/myfile.txt ./

# Delete an object
aws s3 rm s3://my-bucket/myfile.txt
```

