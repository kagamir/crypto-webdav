package crypto

import (
	"crypto-webdav/config"
	"os"

	"github.com/foomo/htpasswd"
	"github.com/rs/zerolog/log"
)

type Htpasswd struct {
	HtpasswdPath string
	passwords    map[string]string
}

func (h *Htpasswd) Init() (err error) {
	htpasswdPath := config.GetHtpasswdFile()
	passwords, err := htpasswd.ParseHtpasswdFile(htpasswdPath)
	if err != nil {
		log.Fatal().
			Str("htpasswd_path", htpasswdPath).
			Err(err).
			Msg("Failed to parse htpasswd file")
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
			log.Fatal().
				Str("user", user).
				Str("dir_path", dirPath).
				Err(err).
				Msg("Failed to create user directory")
			return
		}
		log.Info().
			Str("user", user).
			Str("dir_path", dirPath).
			Msg("Created user directory")
	}
}

func (h *Htpasswd) GetSecret(user string, realm string) string {
	secret, ok := h.passwords[user]
	if !ok {
		return ""
	}
	return secret
}
