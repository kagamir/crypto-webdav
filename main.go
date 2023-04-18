package main

import (
	"context"
	"crypto-webdav/crytpo"
	auth "github.com/abbot/go-http-auth"
	"github.com/foomo/htpasswd"
	"golang.org/x/net/webdav"
	"log"
	"net/http"
	"os"
)

const (
	address = "0.0.0.0:8080"
)

type Htpasswd struct {
	HtpasswdPath string
	passwords    map[string]string
}

func (h *Htpasswd) Init() {
	htpasswdPath, ok := os.LookupEnv("WEBDAV_HTPASSWD_FILE")
	if !ok {
		htpasswdPath = "./htpasswd"
	}
	passwords, err := htpasswd.ParseHtpasswdFile(htpasswdPath)
	if err != nil {
		log.Fatal(err)
		return
	}
	h.passwords = passwords
	h.makeDir()
}

func (h *Htpasswd) getUsers() []string {
	users := make([]string, 0, len(h.passwords))
	for k := range h.passwords {
		users = append(users, k)
	}
	return users
}

func (h *Htpasswd) makeDir() {
	users := h.getUsers()
	for _, user := range users {
		dirPath := "./upload/" + user
		err := os.MkdirAll(dirPath, 0777)
		if err != nil {
			log.Fatal(err)
			return
		}
	}
}

func (h *Htpasswd) GetSecret(user string, realm string) string {
	secret, ok := h.passwords[user]
	if !ok {
		return ""
	}
	return secret
}

type Handler struct {
	writer   http.ResponseWriter
	request  *http.Request
	username string
	handler  *webdav.Handler
	htpasswd *Htpasswd
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
	cryptoKey := crytpo.Sha256(username + password)
	ctx := h.request.Context()
	ctx = context.WithValue(ctx, "crypto.Key", cryptoKey)
	h.request = h.request.WithContext(ctx)

	return true
}

func (h *Handler) makeWebdav() {
	dirPath := "./upload/" + h.username
	h.handler = &webdav.Handler{
		FileSystem: crytpo.CryptoFS{Dir: webdav.Dir(dirPath)},
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

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.writer = w
	h.request = req
	ok := h.login()
	if !ok {
		return
	}
	h.makeWebdav()
	h.handler.ServeHTTP(h.writer, h.request)
}

func main() {
	myHtpasswd := &Htpasswd{}
	myHtpasswd.Init()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handler := Handler{htpasswd: myHtpasswd}
		handler.ServeHTTP(w, r)
	})

	log.Printf("WebDAV server running at %s", address)
	log.Fatal("[FATAL] ", http.ListenAndServe(address, nil))
}
