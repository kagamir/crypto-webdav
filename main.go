package main

import (
	"crypto-webdav/crytpo"
	"golang.org/x/net/webdav"
	"log"
	"net/http"
)

const (
	address        = "0.0.0.0:8080"
	fileSystemRoot = "./upload" // 修改为实际的共享文件夹路径
)

type Handler struct {
	writer  http.ResponseWriter
	request *http.Request
	fs      *webdav.Handler
}

func (h *Handler) login() {
	username, password, ok := h.request.BasicAuth()
	if !ok {
		h.writer.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		h.writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	// 验证用户名/密码
	if username != "user" || password != "1" {
		http.Error(h.writer, "WebDAV: need authorized!", http.StatusUnauthorized)
		return
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.writer = w
	h.request = req
	h.login()
	h.fs.ServeHTTP(w, req)
}

func main() {
	// 设置WebDAV文件系统和锁定系统
	fileSystem := &webdav.Handler{
		//FileSystem: upload.Dir(fileSystemRoot),
		FileSystem: crytpo.CryptoFS{Dir: webdav.Dir(fileSystemRoot)},
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				log.Printf("WEBDAV [%s]: %s, ERROR: %s", r.Method, r.URL, err)
			} else {
				log.Printf("WEBDAV %s [%s]: %s", r.RemoteAddr, r.Method, r.URL)
			}
		},
	}

	http.Handle("/", &Handler{fs: fileSystem})

	// 启动HTTP服务
	log.Printf("WebDAV server running at %s, serving %s", address, fileSystemRoot)
	log.Fatal(http.ListenAndServe(address, nil))
}
