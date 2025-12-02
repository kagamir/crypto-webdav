package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Metadata 存储文件或目录的元信息
type Metadata struct {
	Name    string    `json:"name"`    // 原始文件名或目录名
	Size    int64     `json:"size"`    // 文件原始大小（仅文件，目录为0）
	ModTime time.Time `json:"modTime"` // 修改时间
	IsDir   bool      `json:"isDir"`   // 是否为目录
}

// EncryptMetadata 使用 AES-CTR 加密元信息
func EncryptMetadata(metadata *Metadata, key []byte) ([]byte, error) {
	// 序列化为 JSON
	jsonData, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	// 生成 nonce
	nonce := make([]byte, BlockSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// 创建 AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建 CTR stream
	stream := cipher.NewCTR(block, nonce)

	// 加密数据
	ciphertext := make([]byte, len(jsonData))
	stream.XORKeyStream(ciphertext, jsonData)

	// 返回: nonce + ciphertext
	result := append(nonce, ciphertext...)
	return result, nil
}

// DecryptMetadata 解密元信息
func DecryptMetadata(encryptedData []byte, key []byte) (*Metadata, error) {
	if len(encryptedData) < BlockSize {
		return nil, os.ErrInvalid
	}

	// 提取 nonce 和 ciphertext
	nonce := encryptedData[:BlockSize]
	ciphertext := encryptedData[BlockSize:]

	// 创建 AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建 CTR stream
	stream := cipher.NewCTR(block, nonce)

	// 解密数据
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	// 反序列化 JSON
	var metadata Metadata
	if err := json.Unmarshal(plaintext, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

// WriteMetadataFile 写入加密的元信息文件
func WriteMetadataFile(metaPath string, metadata *Metadata, key []byte) error {
	encryptedData, err := EncryptMetadata(metadata, key)
	if err != nil {
		return err
	}

	return os.WriteFile(metaPath, encryptedData, 0600)
}

// ReadMetadataFile 读取并解密元信息文件
func ReadMetadataFile(metaPath string, key []byte) (*Metadata, error) {
	encryptedData, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	return DecryptMetadata(encryptedData, key)
}

// GetMetadataFilePath 获取元信息文件路径
func GetMetadataFilePath(filePath string) string {
	return filepath.Join(filepath.Dir(filePath), filepath.Base(filePath)+".meta")
}

// GetHashFromPath 从文件路径提取哈希值（去掉 .meta 后缀）
func GetHashFromPath(metaPath string) string {
	base := filepath.Base(metaPath)
	if len(base) > 5 && base[len(base)-5:] == ".meta" {
		return base[:len(base)-5]
	}
	return base
}

// GetHashString 将字节哈希转换为十六进制字符串
func GetHashString(hash []byte) string {
	return hex.EncodeToString(hash)
}

// GetHashFromString 从十六进制字符串解析哈希值
func GetHashFromString(hashStr string) ([]byte, error) {
	return hex.DecodeString(hashStr)
}

// CalculateFileContentHash 计算文件内容的 SHA256 哈希
func CalculateFileContentHash(filePath string, key []byte) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 读取 nonce（前16字节）
	nonce := make([]byte, BlockSize)
	if _, err := file.ReadAt(nonce, 0); err != nil {
		return "", err
	}

	// 创建解密器
	aesCtr := &AesCtr{nonce: nonce, key: key}

	// 读取并解密整个文件内容来计算哈希
	hasher := sha256.New()
	buffer := make([]byte, 64*1024) // 64KB buffer

	file.Seek(BlockSize, io.SeekStart) // 跳过 nonce
	position := int64(0)
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			decrypted, err := aesCtr.Decrypt(buffer[:n], position)
			if err != nil {
				return "", err
			}
			hasher.Write(decrypted)
			position += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}

	hash := hasher.Sum(nil)
	return GetHashString(hash), nil
}

