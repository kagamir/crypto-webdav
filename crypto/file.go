package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
)

const BlockSize = 16

func handleError(err error) {
	if err != nil {
		log.Panic().Err(err).Msg("File operation error")
	}
}

type AesCtr struct {
	key   []byte
	nonce []byte
}

func (a *AesCtr) getIV(position int64) (iv []byte, err error) {
	offset := position / BlockSize

	iv = make([]byte, len(a.nonce))
	copy(iv, a.nonce)

	bigIntA := new(big.Int).SetBytes(iv)
	bigIntB := big.NewInt(offset)
	bigIntResult := new(big.Int).Add(bigIntA, bigIntB)
	iv = bigIntResult.Bytes()
	return
}

func (a *AesCtr) Decrypt(ciphertext []byte, position int64) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}
	iv, err := a.getIV(position)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)

	offset := position % BlockSize
	textLength := int64(len(ciphertext))

	padding := make([]byte, offset)
	ciphertext = append(padding, ciphertext...)

	plaintext := make([]byte, textLength+offset)

	stream.XORKeyStream(plaintext, ciphertext)

	value := make([]byte, textLength)
	copy(value, plaintext[offset:])
	return value, nil
}

func (a *AesCtr) Encrypt(plaintext []byte, position int64) ([]byte, error) {
	ciphertext, err := a.Decrypt(plaintext, position)
	return ciphertext, err
}

type EncryptedFileInfo struct {
	fs.FileInfo
}

func (i *EncryptedFileInfo) Size() int64 {
	size := i.FileInfo.Size() - BlockSize
	if size < 0 {
		size = 0
	}
	return size
}

type EncryptedFile struct {
	filePointer *os.File
	aes         *AesCtr
	ptrPos      int64
	// 新文件相关字段
	originalName string // 原始文件名
	parentDir    string // 父目录路径
	isNewFile    bool   // 是否为新文件
	actualPath   string // 实际文件路径
	key          []byte // 加密密钥
	fileSize     int64  // 文件大小（用于元信息）
}

func (e *EncryptedFile) Open(name string, flag int, perm os.FileMode, key []byte) (err error) {
	e.actualPath = name
	e.key = key

	fp, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return
	}
	fileInfo, err := fp.Stat()
	if err != nil {
		return err
	}

	if !fileInfo.IsDir() {
		fileLen := fileInfo.Size()
		nonce := make([]byte, BlockSize)
		if fileLen == 0 {
			log.Debug().Str("file", name).Msg("Opening new file")
			_, err = rand.Read(nonce)
			if handleError(err); err != nil {
				return err
			}
			_, err = fp.Write(nonce)
			if handleError(err); err != nil {
				return err
			}
			e.isNewFile = true

		} else {
			_, err = fp.ReadAt(nonce, 0)
			if handleError(err); err != nil {
				return err
			}
		}
		e.filePointer = fp
		_, _ = e.Seek(0, io.SeekStart)
		e.aes = &AesCtr{nonce: nonce, key: key}

	} else {
		e.filePointer = fp
	}
	return
}

func (e *EncryptedFile) Write(b []byte) (n int, err error) {
	plaintextLen := len(b)
	b, err = e.aes.Encrypt(b, e.ptrPos)
	if handleError(err); err != nil {
		return
	}
	n, err = e.filePointer.Write(b)
	if handleError(err); err != nil {
		return
	}
	e.ptrPos += int64(n)
	e.fileSize += int64(plaintextLen) // 记录原始文件大小
	return plaintextLen, nil // 返回原始数据长度
}

func (e *EncryptedFile) Read(b []byte) (n int, err error) {
	buffer := make([]byte, len(b))
	n, err = e.filePointer.Read(buffer)
	if err != nil {
		log.Error().
			Str("file", e.actualPath).
			Err(err).
			Msg("Error reading file")
		return
	}
	buffer, err = e.aes.Decrypt(buffer, e.ptrPos)
	if handleError(err); err != nil {
		return
	}
	copy(b, buffer)
	e.ptrPos += int64(n)
	return
}

func (e *EncryptedFile) Seek(offset int64, whence int) (ret int64, err error) {
	if whence == io.SeekStart {
		offset += BlockSize
	}
	ret, err = e.filePointer.Seek(offset, whence)
	if err != nil {
		return 0, err
	}
	ret -= BlockSize
	e.ptrPos = ret
	return
}

func (e *EncryptedFile) Close() (err error) {
	// 关闭文件指针
	err = e.filePointer.Close()
	if err != nil {
		return err
	}

	// 如果是新文件，需要计算哈希并重命名，创建元信息
	if e.isNewFile && e.originalName != "" {
		return e.finalizeNewFile()
	}

	return nil
}

// finalizeNewFile 完成新文件的创建：计算哈希、重命名、创建元信息
func (e *EncryptedFile) finalizeNewFile() error {
	// 计算文件内容哈希
	hash, err := CalculateFileContentHash(e.actualPath, e.key)
	if err != nil {
		return err
	}

	// 构建新的文件路径
	newPath := filepath.Join(e.parentDir, hash)

	// 如果临时文件名已经是正确的哈希，不需要重命名
	if filepath.Base(e.actualPath) != hash {
		// 重命名文件
		if err := os.Rename(e.actualPath, newPath); err != nil {
			return err
		}
		e.actualPath = newPath
	}

	// 创建元信息文件
	metaPath := GetMetadataFilePath(newPath)
	metadata := &Metadata{
		Name:    e.originalName,
		Size:    e.fileSize,
		ModTime: time.Now(),
		IsDir:   false,
	}

	if err := WriteMetadataFile(metaPath, metadata, e.key); err != nil {
		// 如果元信息写入失败，尝试恢复
		os.Remove(newPath)
		return err
	}

	return nil
}

func (e *EncryptedFile) Readdir(n int) (infos []fs.FileInfo, err error) {
	// 如果是目录，使用 ListDirectory 来获取解密后的文件信息
	if e.filePointer != nil && e.key != nil {
		fileInfo, err := e.filePointer.Stat()
		if err == nil && fileInfo.IsDir() {
			dirPath := e.actualPath
			if dirPath != "" {
				return ListDirectory(dirPath, e.key)
			}
		}
	}
	// 非目录或无法获取密钥时，使用底层实现
	infos, err = e.filePointer.Readdir(n)
	return
}

func (e *EncryptedFile) Stat() (fs.FileInfo, error) {
	fileInfo, err := e.filePointer.Stat()
	fileStat := &EncryptedFileInfo{fileInfo}
	return fileStat, err
}
