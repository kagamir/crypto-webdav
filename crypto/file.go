package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/fs"
	"math/big"
	"os"
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
	// 下列字段在新索引结构中不再用于重命名或写入元信息，但保留以兼容现有逻辑
	isNewFile  bool   // 是否为新文件
	actualPath string // 实际文件路径
	key        []byte // 加密密钥
	fileSize   int64  // 文件大小（用于元信息）
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
	return plaintextLen, nil          // 返回原始数据长度
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

// eraseFileTimestamps 抹除文件的创建和修改时间，设置为固定值（Unix 时间 0）
func eraseFileTimestamps(filePath string) error {
	// 使用 Unix 时间 0 (1970-01-01 00:00:00 UTC) 作为固定时间
	fixedTime := time.Unix(0, 0)
	return eraseFileTimestampsImpl(filePath, fixedTime)
}

func (e *EncryptedFile) Close() (err error) {
	// 关闭文件指针
	err = e.filePointer.Close()
	if err != nil {
		return err
	}

	// 抹除物理文件的创建和修改时间
	if e.actualPath != "" {
		if err := eraseFileTimestamps(e.actualPath); err != nil {
			log.Warn().
				Str("file", e.actualPath).
				Err(err).
				Msg("Failed to erase file timestamps")
		}
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
