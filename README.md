# Crypto WebDAV

A WebDAV server with **server-side encryption**. File contents are encrypted with AES-256-CTR, supporting streaming encryption/decryption and random access for large files. Logical file and directory metadata are stored in a per-user encrypted index file.

## Security Architecture

### Key Derivation

- **Method**: SHA-256
- **Input**: `SHA256(username + password)`
- **Output**: 32-byte encryption key (256 bits)
- **Isolation**: Each user has an independent symmetric key derived from their own credentials

> **Note**: An `Argon2` helper exists in code, but the current login flow uses SHA-256 as shown above.

### File Content Encryption

- **Algorithm**: AES-256-CTR (Counter Mode)
- **Key length**: 256 bits (32 bytes)
- **Nonce generation**: For each physical file, a 16-byte random nonce is generated using `crypto/rand`
- **Nonce storage**: The first 16 bytes at the beginning of each physical file
- **IV calculation**: `IV = nonce + (position / 16)` using big-integer addition
- **Streaming support**: CTR mode supports streaming encryption/decryption without padding and enables random access to any position

**Technical implementation** (from `crypto/file.go`):

```go
offset := position / BlockSize   // BlockSize == 16
iv := nonce + offset             // big.Int addition
stream := cipher.NewCTR(block, iv)
```

### Logical File System

- **Logical names**: User-visible path segments in WebDAV are stored only inside the encrypted index file
- **Physical storage**: Encrypted file data is stored under a per-user `files/` directory using random UUIDv4 identifiers
- **Node ID**: Each file node is assigned a random 128-bit UUIDv4 (36-character hex string) used as the physical filename
- **Privacy**: The on-disk layout reveals no information about original file or directory names
- **Sharding**: Physical files are organized in a two-level bucket structure based on the last 4 characters of the UUID (e.g., `files/ab/cd/uuid-string`) to reduce single-directory file count

### Index Encryption

The system uses a **single encrypted index file per user** containing the entire logical directory tree.

- **Index file**: `index.meta.enc`
- **Location**: `upload/{username}/index.meta.enc`
- **Content**: JSON document describing the complete logical directory tree
- **Encryption**: AES-256-CTR with a 16-byte random nonce
- **On-disk format**: `nonce (16 bytes) + encrypted_json_data`
- **Atomic updates**: Index writes use a temporary file followed by atomic rename to prevent corruption
- **Concurrency**: Read-write locks protect index operations, allowing concurrent reads but exclusive writes

**Index structure** (from `crypto/index.go`):

```json
{
  "version": 1,
  "root": {
    "id": "",
    "name": "",
    "size": 0,
    "modTime": "2024-01-01T00:00:00Z",
    "isDir": true,
    "children": {
      "file-or-dir-name": {
        "id": "uuid-v4-for-files",
        "name": "file-or-dir-name",
        "size": 1234,
        "modTime": "2024-01-01T00:00:00Z",
        "isDir": false,
        "children": null
      }
    }
  }
}
```

Each logical node is either:
- A **directory** (`isDir == true`) with `children` populated, or
- A **file** (`isDir == false`) with `id` set to the UUIDv4 physical NodeID and `size`/`modTime` describing the logical file.

### Storage Layout

Per-user storage structure:

```
upload/
└── {username}/
    ├── index.meta.enc        # Encrypted logical index (AES-256-CTR)
    └── files/                # Physical encrypted file blobs
        ├── ab/
        │   └── cd/
        │       └── xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxabcd
        └── index.meta.enc.bak   # Automatic backup of index
```

The WebDAV layer (`FileCrypto`) exposes a logical tree based on `index.meta.enc`, while physical files under `files/` contain only encrypted content plus a per-file nonce.

### Security Guarantees

1. **Server-side encryption**: All file contents and logical metadata are encrypted on disk
2. **Key isolation**: Each user has an independent symmetric key; users cannot decrypt or list each other's data
3. **No plaintext names**: Logical file and directory names exist only inside the encrypted index
4. **Timestamp erasure**: Physical file creation and modification timestamps are erased (set to Unix epoch) to prevent metadata leakage
5. **Streaming decryption**: Large files can be accessed via HTTP Range requests without full decryption
6. **Nonce-bound security**: Even if a key leaks, decryption requires the corresponding nonce stored with each file/index

### Index Backup and Recovery

**Automatic backup**:  
Every time `index.meta.enc` is successfully written, the server asynchronously creates a backup copy at `files/index.meta.enc.bak`. The backup is a byte-for-byte copy, encrypted with the same per-user key.

**Manual recovery** (when index is corrupted or deleted):

1. Stop the Crypto WebDAV service
2. Navigate to the affected user's directory: `upload/{username}`
3. Restore from backup:
   ```bash
   cd upload/{username}
   cp files/index.meta.enc.bak index.meta.enc
   ```
4. Restart the service

**Notes**:
- Only the latest backup is kept
- Regular backups of the entire `upload/` directory and `htpasswd` file are still recommended

## Usage

### Environment Variables

All environment variable configurations are managed by the `config` package (`config/config.go`). The following are all available environment variables:

| Environment Variable | Description | Default Value | Example |
|---------------------|-------------|---------------|---------|
| `WEBDAV_ADDRESS` | WebDAV server listening address | `127.0.0.1:4043` | `0.0.0.0:8080` |
| `WEBDAV_HTPASSWD_FILE` | htpasswd authentication file path | `./htpasswd` | `/etc/webdav/htpasswd` |
| `LOG_LEVEL` | Log level | `warn` | `debug`, `info`, `warn`, `error`, `fatal`, `panic`, `trace` |
| `ENV` | Runtime environment | - | `development` (enables colored log output) |
| `HTTPS_DISABLED` | Whether to disable HTTPS | `false` | `true` (disables HTTPS, uses HTTP) |

**Detailed description:**

- **WEBDAV_ADDRESS**: Sets the IP address and port that the WebDAV server binds to. Format is `IP:PORT`, for example `0.0.0.0:8080` means listening on all network interfaces on port 8080.
- **WEBDAV_HTPASSWD_FILE**: Specifies the full path to the htpasswd file. This file is used for HTTP Basic Authentication.
- **LOG_LEVEL**: Controls the verbosity of log output. Valid values: `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic`.
- **ENV**: When set to `development`, logs will be output to the console in a colored, human-friendly format.
- **HTTPS_DISABLED**: When set to `true`, disables HTTPS and the server will use HTTP protocol. By default, the server enables HTTPS using a self-signed certificate.

### Running

**Linux/macOS**:
```bash
export WEBDAV_ADDRESS=0.0.0.0:8080
export WEBDAV_HTPASSWD_FILE=/path/to/htpasswd
export LOG_LEVEL=info
export HTTPS_DISABLED=false
./crypto-webdav
```

**Windows**:
```powershell
$env:WEBDAV_ADDRESS="0.0.0.0:8080"
$env:WEBDAV_HTPASSWD_FILE="C:\path\to\htpasswd"
$env:LOG_LEVEL="info"
$env:HTTPS_DISABLED="false"
.\crypto-webdav.exe
```

### Docker Deployment

**Build**:
```bash
docker build -t crypto-webdav .
```

**Run**:
```bash
docker run --restart always \
  -v /path/to/storage:/upload \
  -v /path/to/htpasswd:/htpasswd \
  -e WEBDAV_ADDRESS=0.0.0.0:8080 \
  -e WEBDAV_HTPASSWD_FILE=/htpasswd \
  -e LOG_LEVEL=info \
  -e HTTPS_DISABLED=false \
  -p 8080:8080 \
  --name crypto-webdav \
  -d crypto-webdav
```

**Creating an `htpasswd` file**:
```bash
# Using htpasswd tool
htpasswd -c /path/to/htpasswd username

# Or using OpenSSL
echo "username:$(openssl passwd -apr1 password)" >> /path/to/htpasswd
```

## Security Recommendations

1. **Use HTTPS**: Terminate TLS via a reverse proxy (Nginx, Caddy, etc.)
2. **Strong passwords**: User password strength directly affects derived key strength
3. **Regular backups**: Back up encrypted data under `upload/` and the `htpasswd` file
4. **Access control**: Restrict access to the WebDAV port using a firewall or reverse proxy ACLs
5. **Credential protection**: Keep the `htpasswd` file secret; if it leaks, attackers can authenticate and derive user keys

## Technical Architecture

- **WebDAV protocol**: Based on `golang.org/x/net/webdav`
- **HTTP server**: Go's standard `net/http` (fully compatible with WebDAV methods)
- **Authentication**: HTTP Basic Authentication with `htpasswd` verification
- **Encryption**: AES-256-CTR for both file content and index
- **Key derivation**: SHA-256 (current login flow)
- **Indexing**: Custom logical index (`index.meta.enc`) describing the entire tree, loaded and saved per user with read-write lock protection

## Performance Characteristics

- **Streaming I/O**: Supports streaming upload/download of large files
- **Random access**: Works with HTTP Range requests, suitable for video seeking and online preview
- **Low overhead**: CTR mode uses XOR operations on blocks with minimal CPU overhead
- **Memory efficiency**: File contents are processed in chunks; no need to load whole files into RAM
- **Index-based listing**: Directory listings and metadata are served from the in-memory index tree without scanning the `files/` directory

## Limitations

- The per-user index (`index.meta.enc`) contains the full logical tree; very large trees may increase index size and update cost
- File contents cannot be updated incrementally at the encryption layer; rewriting a file rewrites its encrypted content
- No built-in content-hash deduplication; each logical file corresponds to its own encrypted blob

## Development

```bash
# Build
go build .

# Run tests
go test ./...

# Run
go run main.go
```
