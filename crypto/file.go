package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/fs"
	"log"
	"math/big"
	"os"
)

const BlockSize = 16

func handleError(err error) {
	if err != nil {
		log.Panicf("%s: %v\n", "[FILE]", err)
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
}

func (e *EncryptedFile) Open(name string, flag int, perm os.FileMode, key []byte) (err error) {
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
			log.Println("[Open] New", name)
			_, err = rand.Read(nonce)
			if handleError(err); err != nil {
				return err
			}
			_, err = fp.Write(nonce)
			if handleError(err); err != nil {
				return err
			}

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
	b, err = e.aes.Encrypt(b, e.ptrPos)
	if handleError(err); err != nil {
		return
	}
	n, err = e.filePointer.Write(b)
	if handleError(err); err != nil {
		return
	}
	e.ptrPos += int64(n)
	return
}

func (e *EncryptedFile) Read(b []byte) (n int, err error) {
	buffer := make([]byte, len(b))
	n, err = e.filePointer.Read(buffer)
	if err != nil {
		log.Println("[Read Error]", err)
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
	err = e.filePointer.Close()
	return
}

func (e *EncryptedFile) Readdir(n int) (infos []fs.FileInfo, err error) {
	infos, err = e.filePointer.Readdir(n)
	return
}

func (e *EncryptedFile) Stat() (fs.FileInfo, error) {
	fileInfo, err := e.filePointer.Stat()
	fileStat := &EncryptedFileInfo{fileInfo}
	return fileStat, err
}
