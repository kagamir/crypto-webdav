package main

import (
	"context"
	"crypto-webdav/crypto"
	"crypto-webdav/frontend"
	"errors"
	"net/http"
	"os"
	"time"

	auth "github.com/abbot/go-http-auth"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/webdav"
)

func init() {
	// 配置 zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// 如果环境变量设置了日志级别，则使用该级别
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		if l, err := zerolog.ParseLevel(level); err == nil {
			zerolog.SetGlobalLevel(l)
		}
	}

	// 在开发环境中使用彩色输出
	if os.Getenv("ENV") == "development" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	}
}

func getAddress() string {
	address := os.Getenv("WEBDAV_ADDRESS")
	if address == "" {
		address = "0.0.0.0:4043"
	}
	return address
}

type Handler struct {
	htpasswd *crypto.Htpasswd
}

func (h *Handler) login(r *http.Request) (string, []byte, bool) {
	authenticator := auth.NewBasicAuthenticator("Restricted", h.htpasswd.GetSecret)
	username := authenticator.CheckAuth(r)
	if username == "" {
		return "", nil, false
	}

	_, password, _ := r.BasicAuth()
	cryptoKey := crypto.Sha256(username + password)
	return username, cryptoKey, true
}

func (h *Handler) makeWebdavHandler(username string, cryptoKey []byte) *webdav.Handler {
	dirPath := "./upload/" + username
	return &webdav.Handler{
		FileSystem: crypto.FileCrypto{Dir: webdav.Dir(dirPath)},
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				log.Error().
					Str("method", r.Method).
					Str("url", r.URL.String()).
					Str("remote_addr", r.RemoteAddr).
					Err(err).
					Msg("WebDAV request error")
			} else {
				log.Info().
					Str("method", r.Method).
					Str("url", r.URL.String()).
					Str("remote_addr", r.RemoteAddr).
					Msg("WebDAV request")
			}
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 直接处理所有请求为 WebDAV 请求
	h.handleWebDAV(w, r)
}

func (h *Handler) handleWebDAV(w http.ResponseWriter, r *http.Request) {
	// 登录验证
	username, cryptoKey, ok := h.login(r)
	if !ok {
		authenticator := auth.NewBasicAuthenticator("Restricted", h.htpasswd.GetSecret)
		authenticator.RequireAuth(w, r)
		return
	}

	// 创建 WebDAV handler
	webdavHandler := h.makeWebdavHandler(username, cryptoKey)

	// 将加密密钥添加到 context
	ctx := r.Context()
	ctx = context.WithValue(ctx, "crypto.Key", cryptoKey)
	r = r.WithContext(ctx)

	// 处理 GET 请求 - 目录浏览
	if r.Method == http.MethodGet {
		stat, err := webdavHandler.FileSystem.Stat(ctx, r.URL.Path)
		if err != nil {
			log.Error().
				Str("path", r.URL.Path).
				Str("username", username).
				Err(err).
				Msg("Failed to stat path")
			var pathError *os.PathError
			if errors.As(err, &pathError) {
				http.NotFound(w, r)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if stat.IsDir() {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			bd := frontend.BrowserDir{
				FS:       webdavHandler.FileSystem,
				Name:     r.URL.Path,
				UserName: username,
				Key:      cryptoKey,
			}
			err = bd.MakeHTML(w)
			if err != nil {
				log.Error().
					Str("path", r.URL.Path).
					Str("username", username).
					Err(err).
					Msg("Error rendering directory")
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
	}

	// 其他 WebDAV 方法（MKCOL, PUT, DELETE, PROPFIND, etc.）
	webdavHandler.ServeHTTP(w, r)
}

func main() {
	myHtpasswd := &crypto.Htpasswd{}
	err := myHtpasswd.Init()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize htpasswd")
	}

	handler := &Handler{htpasswd: myHtpasswd}

	server := &http.Server{
		Addr:    getAddress(),
		Handler: handler,
	}

	log.Warn().
		Str("address", getAddress()).
		Msg("Starting WebDAV server")
	log.Fatal().Err(server.ListenAndServe()).Msg("WebDAV server stopped")
}
