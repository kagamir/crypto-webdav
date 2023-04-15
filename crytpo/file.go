package crytpo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"golang.org/x/net/webdav"
	"io"
	"io/fs"
	"log"
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
	offset := uint64((position+BlockSize-1)/BlockSize - 1)

	iv = make([]byte, len(a.nonce))
	copy(iv, a.nonce)

	var ivNum uint64
	buf := bytes.NewReader(iv)
	err = binary.Read(buf, binary.BigEndian, &ivNum)
	if handleError(err); err != nil {
		return
	}

	ivNum += offset

	buf2 := new(bytes.Buffer)
	err = binary.Write(buf2, binary.BigEndian, ivNum)
	if handleError(err); err != nil {
		return
	}

	iv = buf2.Bytes()

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
	padding := make([]byte, offset)
	ciphertext = append(padding, ciphertext...)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext[offset:], nil
}

func (a *AesCtr) Encrypt(plaintext []byte, position int64) ([]byte, error) {
	ciphertext, err := a.Decrypt(plaintext, position)
	return ciphertext, err
}

type EncryptedFile struct {
	webdav.File
	path        string
	filePointer *os.File
	aes         *AesCtr
	ptrPos      int64
}

func (e *EncryptedFile) Open(name string, flag int, perm os.FileMode, key []byte) (err error) {
	fp, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return
	}
	fileLen, err := fp.Seek(0, io.SeekEnd)
	if handleError(err); err != nil {
		return
	}
	nonce := make([]byte, BlockSize)
	if fileLen == 0 {
		_, err = rand.Read(nonce)
		if handleError(err); err != nil {
			return
		}
		_, err = fp.Write(nonce)
		if handleError(err); err != nil {
			return
		}

	} else {
		_, err = fp.Seek(0, io.SeekStart)
		if handleError(err); err != nil {
			return
		}

		_, err = fp.Read(nonce)
		if handleError(err); err != nil {
			return
		}
	}
	_, _ = fp.Seek(0, io.SeekStart)
	e.filePointer = fp
	e.aes = &AesCtr{nonce: nonce, key: key}
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
	return
}

func (e *EncryptedFile) Read(b []byte) (n int, err error) {
	position := e.ptrPos
	n, err = e.filePointer.Read(b)
	if handleError(err); err != nil {
		return
	}
	b, err = e.aes.Decrypt(b, position)
	if handleError(err); err != nil {
		return
	}
	return
}

func (e *EncryptedFile) Seek(offset int64, whence int) (ret int64, err error) {
	ret, err = e.filePointer.Seek(offset, whence)
	if err != nil {
		return 0, err
	}
	e.ptrPos = offset
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
	fileStat, err := e.filePointer.Stat()
	return fileStat, err
}
