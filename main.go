package main

import (
	"context"
	"crypto-webdav/crypto"
	"crypto-webdav/frontend"
	"errors"
	"log"
	"net/http"

	auth "github.com/abbot/go-http-auth"
	"golang.org/x/net/webdav"

	//_ "net/http/pprof"
	"os"
)

func getAddress() string {
	address := os.Getenv("WEBDAV_ADDRESS")
	if address == "" {
		address = "0.0.0.0:8080"
	}
	return address
}

type Handler struct {
	writer   http.ResponseWriter
	request  *http.Request
	username string
	handler  *webdav.Handler
	htpasswd *crypto.Htpasswd
}

func (h *Handler) login() bool {
	authenticator := auth.NewBasicAuthenticator("Restricted", h.htpasswd.GetSecret)
	username := authenticator.CheckAuth(h.request)
	if username == "" {
		log.Println("login failed")
		authenticator.RequireAuth(h.writer, h.request)
		return false
	}
	h.username = username

	_, password, _ := h.request.BasicAuth()
	cryptoKey := crypto.Sha256(username + password)
	ctx := h.request.Context()
	ctx = context.WithValue(ctx, "crypto.Key", cryptoKey)
	h.request = h.request.WithContext(ctx)

	return true
}

func (h *Handler) makeWebdav() {
	dirPath := "./upload/" + h.username
	h.handler = &webdav.Handler{
		FileSystem: crypto.FileCrypto{Dir: webdav.Dir(dirPath)},
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				log.Printf("WEBDAV [%s]: %s, ERROR: %s", r.Method, r.URL, err)
			} else {
				log.Printf("WEBDAV %s [%s]: %s", r.RemoteAddr, r.Method, r.URL)
			}
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.writer = w
	h.request = r
	ok := h.login()
	if !ok {
		return
	}
	h.makeWebdav()

	if r.Method == http.MethodGet {
		stat, err := h.handler.FileSystem.Stat(context.TODO(), r.URL.Path)
		if err != nil {
			var pathError *os.PathError
			if errors.As(err, &pathError) {
				http.NotFound(w, r)
			} else {
				log.Println("[STAT]", err)
			}
			return
		}
		if stat.IsDir() {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			bd := frontend.BrowserDir{FS: h.handler.FileSystem, Name: r.URL.Path, UserName: h.username}
			err = bd.MakeHTML(w)
			if err != nil {
				return
			}
			return
		}
	}
	h.handler.ServeHTTP(h.writer, h.request)
}

func main() {
	myHtpasswd := &crypto.Htpasswd{}
	err := myHtpasswd.Init()
	if err != nil {
		return
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handler := Handler{htpasswd: myHtpasswd}
		handler.ServeHTTP(w, r)
	})

	address := getAddress()
	log.Printf("WebDAV server running at %s", address)
	log.Fatal("[FATAL] ", http.ListenAndServe(address, nil))
}
