## Crypto WebDAV

A WebDAV server with **server-side encryption**.  
File contents are encrypted with AES in CTR mode, supporting streaming encryption/decryption and random access for large files (such as videos).  
Logical file and directory metadata are stored in a per‑user encrypted index file.  

### Security Features

#### 1. Key derivation
- **Method**: SHA‑256
- **Input**: `SHA256(username + password)`
- **Output**: 32‑byte encryption key
- **Usage**: Each user has an independent symmetric key derived from their own username and password

> Note: There is also an `Argon2` helper in code, but the current login flow uses SHA‑256 as shown above.

#### 2. File content encryption
- **Algorithm**: AES‑256‑CTR (Counter Mode)
- **Key length**: 256 bits (32 bytes)
- **Nonce generation**: For each physical file, a 16‑byte random nonce is generated with `crypto/rand`
- **Nonce storage**: The first 16 bytes at the beginning of the physical file
- **IV calculation**: `IV = nonce + (position / 16)` (big‑integer addition)
- **Streaming property**: CTR mode naturally supports streaming encryption/decryption without padding and allows random access to any position

Technical detail (simplified from `crypto/file.go`):

```go
// Each 16‑byte block uses a different counter value
offset := position / BlockSize   // BlockSize == 16
iv := nonce + offset             // big.Int addition
stream := cipher.NewCTR(block, iv)
```

#### 3. Logical file and directory names
- **Logical names** (user‑visible path segments in WebDAV) are stored only inside the encrypted index file.
- **Physical storage**: Encrypted file data is stored under a per‑user `files/` directory using random IDs, not hashes of content or names.
- **Node ID**: For each file node, a random 128‑bit ID is generated (16 random bytes encoded as lower‑case hex) and used as the physical filename.
- **Privacy**: From the on‑disk layout it is not possible to infer original file or directory names.

#### 4. Metadata and index encryption

Instead of per‑file `.meta` sidecar files, the current implementation uses a **single encrypted index file per user** that contains the entire logical tree.

- **Index file name**: `index.meta.enc`
- **Location**: In each user’s root directory under `upload/{username}`
- **Content**: JSON document describing the full logical directory tree
- **Encryption algorithm**: AES‑256‑CTR
- **Nonce**: 16‑byte random nonce generated for the index file
- **On‑disk format**: `nonce (16 bytes) + encrypted_json_data`

JSON structures (simplified from `crypto/index.go`):

```json
{
  "version": 1,
  "root": {
    "id": "optional-file-id-or-empty-for-dir",
    "name": "",
    "size": 0,
    "modTime": "2024-01-01T00:00:00Z",
    "isDir": true,
    "children": {
      "file-or-dir-name": {
        "id": "hex-node-id-for-files",
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

Each logical node corresponds either to:
- a **directory** (`isDir == true`), with `children` populated; or  
- a **file** (`isDir == false`), with `id` set to the random physical NodeID and `size` / `modTime` describing the logical file.

### On‑disk storage layout

Per‑user storage is organized as follows:

```text
upload/
└── {username}/
    ├── index.meta.enc        # Encrypted logical index (JSON + AES‑CTR)
    └── files/                # Physical encrypted file blobs
        ├── {nodeID1}         # Random hex NodeID, contains nonce + ciphertext
        └── {nodeID2}
```

The WebDAV layer (`FileCrypto`) exposes a logical tree based on `index.meta.enc`, while physical files under `files/` hold only encrypted content plus a per‑file nonce.

### Security guarantees

1. **Server‑side encryption**: All file contents and logical metadata are stored encrypted on disk.
2. **Key isolation**: Each user has an independent symmetric key; users cannot decrypt or list each other’s data.
3. **No plaintext names**: Logical file and directory names exist only inside the encrypted index, not in the raw filesystem layout.
4. **Streaming decryption**: Large files can be accessed via HTTP Range requests and streamed without full decryption.
5. **Nonce‑bound security**: Even if a key leaks, decryption of data still requires the corresponding nonce stored with each file / index.

## Usage

### Environment variables

- `WEBDAV_ADDRESS`: WebDAV listen address (default: `0.0.0.0:4043`)
- `WEBDAV_HTPASSWD_FILE`: path to the `htpasswd` file (default: `./htpasswd`)
- `LOG_LEVEL`: log level for `zerolog` (e.g. `debug`, `info`, `warn`, `error`)
- `ENV`: when set to `development`, logs are printed in colored, human‑friendly format

### Linux

```bash
export WEBDAV_ADDRESS=0.0.0.0:8080
export WEBDAV_HTPASSWD_FILE=/path/to/htpasswd
./crypto-webdav
```

### Windows

```powershell
$env:WEBDAV_ADDRESS="0.0.0.0:8080"
$env:WEBDAV_HTPASSWD_FILE="C:\path\to\htpasswd"
.\crypto-webdav.exe
```

## Docker deployment

### Build image

```bash
docker build -t crypto-webdav .
```

### Run container

```bash
docker run --restart always \
  -v /path/to/storage:/upload \
  -v /path/to/htpasswd:/htpasswd \
  -e WEBDAV_ADDRESS=0.0.0.0:8080 \
  -e WEBDAV_HTPASSWD_FILE=/htpasswd \
  -p 8080:8080 \
  --name crypto-webdav \
  -d crypto-webdav
```

### Parameter explanation

- `-v /path/to/storage:/upload`: mount persistent storage for encrypted data
- `-v /path/to/htpasswd:/htpasswd`: mount `htpasswd` file for authentication
- `-p 8080:8080`: map container port to host
- `--restart always`: automatically restart container

### Creating an `htpasswd` file

```bash
# Using the 'htpasswd' tool
htpasswd -c /path/to/htpasswd username

# Or using OpenSSL
echo "username:$(openssl passwd -apr1 password)" >> /path/to/htpasswd
```

## Security recommendations

1. **Use HTTPS**: It is strongly recommended to terminate TLS via a reverse proxy (Nginx, Caddy, etc.).
2. **Strong passwords**: User password strength directly affects derived key strength.
3. **Regular backups**: Back up encrypted data under `upload/` and the `htpasswd` file.
4. **Access control**: Restrict access to the WebDAV port using a firewall or reverse proxy ACLs.
5. **Credential protection**: Keep the `htpasswd` file secret; if it leaks, attackers can authenticate and derive user keys.

## Technical architecture

- **WebDAV protocol**: based on `golang.org/x/net/webdav`
- **HTTP server**: Go’s standard `net/http` (fully compatible with WebDAV methods)
- **Authentication**: HTTP Basic Authentication with `htpasswd` verification
- **Encryption**: AES‑256‑CTR for both file content and the index
- **Hashing**: SHA‑256 for key derivation (current login flow)
- **Indexing**: Custom logical index (`index.meta.enc`) describing the entire tree, loaded and saved per user

## Performance characteristics

- **Streaming I/O**: Supports streaming upload/download of large files.
- **Random access**: Works with HTTP Range requests, suitable for video seeking and online preview.
- **Low overhead per block**: CTR mode uses XOR operations on blocks, with minimal CPU overhead.
- **Memory efficiency**: File contents are processed in chunks; no need to load whole files into RAM.
- **Index‑based listing**: Directory listings and metadata are served from the in‑memory index tree without scanning the `files/` directory.

## Limitations

- The per‑user index (`index.meta.enc`) contains the full logical tree; very large trees may increase index size and update cost.
- File contents cannot be updated incrementally at the encryption layer; rewriting a file rewrites its encrypted content.
- There is no built‑in content‑hash deduplication; each logical file corresponds to its own encrypted blob.

## Futures

- [x] Hash‑based sharding and hierarchical directory layout

## Development

```bash
# Build
go build .

# Run tests
go test ./...

# Run
go run main.go
```
