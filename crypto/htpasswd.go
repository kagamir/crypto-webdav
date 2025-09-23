package crypto

import (
	"github.com/foomo/htpasswd"
	"log"
	"os"
)

type Htpasswd struct {
	HtpasswdPath string
	passwords    map[string]string
}

func (h *Htpasswd) Init() (err error) {
	htpasswdPath := os.Getenv("WEBDAV_HTPASSWD_FILE")
	if htpasswdPath == "" {
		htpasswdPath = "./htpasswd"
	}
	passwords, err := htpasswd.ParseHtpasswdFile(htpasswdPath)
	if err != nil {
		log.Fatal(err)
		return
	}
	h.passwords = passwords
	h.makeDir()
	return
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
