package crytpo

import (
	"context"
	"crypto/sha256"
	"golang.org/x/net/webdav"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func Sha256(s string) (hash []byte) {
	h := sha256.New()
	h.Write([]byte(s))
	hash = h.Sum(nil)
	return
}

type CryptoFS struct {
	webdav.Dir
}

func slashClean(name string) string {
	if name == "" || name[0] != '/' {
		name = "/" + name
	}
	return path.Clean(name)
}

func (c CryptoFS) resolve(name string) string {
	// This implementation is based on Dir.Open's code in the standard net/http package.
	if filepath.Separator != '/' && strings.IndexRune(name, filepath.Separator) >= 0 ||
		strings.Contains(name, "\x00") {
		return ""
	}
	dir := string(c.Dir)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, filepath.FromSlash(slashClean(name)))
}

func (c CryptoFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	name = c.resolve(name)
	if name == "" {
		return nil, os.ErrNotExist
	}
	var key []byte
	if ctx != nil {
		key = ctx.Value("crypto.Key").([]byte)
	} else {
		key = nil
	}

	f := &EncryptedFile{}
	err := f.Open(name, flag, perm, key)
	//f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
}
