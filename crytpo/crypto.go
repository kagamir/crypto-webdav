package crytpo

import (
	"context"
	"crypto/sha1"
	"golang.org/x/net/webdav"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func Sha256(s string) (hash []byte) {
	h := sha1.New()
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
	log.Printf("[OpenFile] %s %d %d", name, flag, perm)

	if name == "" {
		return nil, os.ErrNotExist
	}
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
}
