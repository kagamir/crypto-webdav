# Crypto WebDAV

一个支持端到端加密的 WebDAV 服务器，使用 AES-CTR 模式实现文件内容和元信息的全面加密，支持流式解密以应对大文件（如视频）的在线预览需求。

## 安全特性

### 密码学实现

#### 1. 密钥派生
- **方法**: SHA-256 哈希
- **输入**: `SHA256(username + password)`
- **输出**: 32 字节加密密钥
- **用途**: 每个用户拥有独立的加密密钥，基于用户名和密码派生

#### 2. 文件内容加密
- **算法**: AES-256-CTR (Counter Mode)
- **密钥长度**: 256 位 (32 字节)
- **Nonce 生成**: 每个文件使用 `crypto/rand` 生成 16 字节随机 nonce
- **Nonce 存储**: 文件头部前 16 字节
- **IV 计算**: `IV = nonce + (position / 16)`，支持任意位置的分块解密
- **流式特性**: CTR 模式天然支持流式加密/解密，无需填充，可随机访问任意位置

**技术细节**:
```go
// IV 计算确保每个 16 字节块使用不同的计数器
offset := position / BlockSize
IV = nonce + offset  // 大整数加法
```

#### 3. 文件名和目录名加密
- **存储方式**: 文件/目录在文件系统中以哈希值命名
- **文件命名**: `SHA256(文件内容)` - 基于文件内容的哈希值
- **目录命名**: `SHA256(目录名)` - 基于原始目录名的哈希值
- **哈希算法**: SHA-256
- **优势**: 相同内容文件自动去重，无法从文件名推断内容

#### 4. 元信息加密
- **存储位置**: 每个文件/目录对应一个 `.meta` 加密文件
- **元信息内容**:
  - 原始文件名/目录名
  - 文件原始大小（目录为 0）
  - 修改时间
  - 类型标识（文件/目录）
- **加密方式**: AES-256-CTR
- **Nonce**: 每个元信息文件独立生成 16 字节随机 nonce
- **格式**: `nonce(16字节) + encrypted_json_data`

**元信息结构**:
```json
{
  "name": "原始文件名",
  "size": 文件大小,
  "modTime": "2024-01-01T00:00:00Z",
  "isDir": false
}
```

### 存储结构

```
upload/
└── {username}/
    ├── {hash1}/              # 目录（哈希名）
    │   ├── {hash1}.meta      # 目录元信息（加密）
    │   └── {hash2}            # 文件（哈希名）
    │       └── {hash2}.meta   # 文件元信息（加密）
    └── {hash3}                # 根目录下的文件
        └── {hash3}.meta
```

### 安全保证

1. **服务端加密**: 所有文件内容和元信息在服务器端加密存储
2. **密钥隔离**: 每个用户拥有独立的加密密钥，无法访问其他用户数据
3. **无明文存储**: 文件名、目录名、文件内容均以加密形式存储
4. **流式解密**: 支持大文件的随机访问和流式传输，无需完整解密
5. **前向安全**: 即使密钥泄露，已加密数据仍受保护（需要 nonce）

## 使用方法

### 环境变量

- `WEBDAV_ADDRESS`: WebDAV 服务器监听地址（默认: `0.0.0.0:4043`）
- `WEBDAV_HTPASSWD_FILE`: htpasswd 文件路径（默认: `./htpasswd`）

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

## Docker 部署

### 构建镜像

```bash
docker build -t crypto-webdav .
```

### 运行容器

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

### 参数说明

- `-v /path/to/storage:/upload`: 挂载存储目录（持久化数据）
- `-v /path/to/htpasswd:/htpasswd`: 挂载 htpasswd 认证文件
- `-p 8080:8080`: 映射端口
- `--restart always`: 自动重启

### 创建 htpasswd 文件

```bash
# 使用 htpasswd 工具创建用户
htpasswd -c /path/to/htpasswd username

# 或使用 openssl
echo "username:$(openssl passwd -apr1 password)" >> /path/to/htpasswd
```

## 安全建议

1. **使用 HTTPS**: 建议通过反向代理（如 Nginx、Caddy）启用 HTTPS
2. **强密码策略**: 确保用户使用强密码，密钥强度直接影响加密安全性
3. **定期备份**: 备份加密数据文件和 htpasswd 文件
4. **访问控制**: 使用防火墙限制 WebDAV 端口的访问
5. **密钥管理**: 妥善保管 htpasswd 文件，泄露会导致数据可被解密

## 技术架构

- **WebDAV 协议**: 基于 `golang.org/x/net/webdav`
- **HTTP 服务器**: 原生 `net/http` (完全兼容 WebDAV 标准方法)
- **认证方式**: HTTP Basic Authentication
- **加密算法**: AES-256-CTR
- **哈希算法**: SHA-256

## 性能特性

- **流式处理**: 支持大文件的流式上传/下载
- **随机访问**: 支持视频文件的 Range 请求和在线预览
- **零拷贝**: 使用 CTR 模式的 XOR 操作，性能开销低
- **内存效率**: 分块处理，无需将整个文件加载到内存

## 限制

- 文件内容哈希计算需要完整读取文件，大文件创建时会有额外开销
- 目录遍历需要读取所有 `.meta` 文件，目录项过多时可能影响性能
- 不支持文件内容的增量更新（修改文件会重新计算哈希）

## 开发

```bash
# 构建
go build .

# 运行测试
go test ./...

# 运行
go run main.go
```
