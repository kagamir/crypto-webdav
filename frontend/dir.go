package frontend

import (
	"crypto-webdav/crypto"
	"embed"
	"fmt"
	"golang.org/x/net/webdav"
	"html/template"
	"io"
	"net/url"
	"strconv"

	"github.com/rs/zerolog/log"
)

//go:embed templates
var embeddedFiles embed.FS

type TemplateItem struct {
	Name    string
	Path    string
	Size    string
	Mode    string
	ModTime string
	IsDir   string
}

type TemplateData struct {
	UserName string
	Items    []TemplateItem
}

func formatBytes(bytes int64) string {
	const (
		K = 1024
		M = K * 1024
		G = M * 1024
		T = G * 1024
	)

	var unit string
	value := float64(bytes)

	switch {
	case bytes >= T:
		unit = "TiB"
		value = value / T
	case bytes >= G:
		unit = "GiB"
		value = value / G
	case bytes >= M:
		unit = "MiB"
		value = value / M
	case bytes >= K:
		unit = "KiB"
		value = value / K
	default:
		return fmt.Sprintf("%d B", bytes)
	}

	return fmt.Sprintf("%.2f %s", value, unit)
}

type BrowserDir struct {
	FS       webdav.FileSystem
	Name     string
	UserName string
	Key      []byte // 加密密钥
}

func (b *BrowserDir) MakeHTML(w io.Writer) (err error) {
	tmpl, err := template.ParseFS(embeddedFiles, "templates/browser.html")
	if err != nil {
		log.Error().
			Err(err).
			Msg("Failed to parse template")
		return err
	}

	// 解析目录路径获取实际路径
	fileCrypto, ok := b.FS.(crypto.FileCrypto)
	if !ok {
		return fmt.Errorf("FileSystem is not FileCrypto")
	}

	// 解析路径
	resolvedPath, err := crypto.ResolvePath(b.Name, string(fileCrypto.Dir), b.Key)
	if err != nil {
		return err
	}

	// 使用 ListDirectory 获取目录内容
	fileInfos, err := crypto.ListDirectory(resolvedPath, b.Key)
	if err != nil {
		return err
	}

	var items []TemplateItem
	for _, fileInfo := range fileInfos {
		// fileInfo 已经是 MetadataFileInfo，包含原始名称
		var isDir string
		var mode string
		var size string
		name := fileInfo.Name()
		if fileInfo.IsDir() {
			isDir = "Dir"
			mode = "-"
			size = "-"
			name += "/"
		} else {
			isDir = "File"
			mode = strconv.FormatUint(uint64(fileInfo.Mode()), 10)
			size = formatBytes(fileInfo.Size())
		}

		path, innerErr := url.JoinPath(b.Name, name)
		if innerErr != nil {
			log.Warn().
				Str("base_path", b.Name).
				Str("name", name).
				Err(innerErr).
				Msg("Failed to join URL path")
			continue
		}
		items = append(items, TemplateItem{
			Name:    name,
			Path:    path,
			Size:    size,
			Mode:    mode,
			ModTime: fileInfo.ModTime().Format("2006-01-02 15:04:05"),
			IsDir:   isDir,
		})
	}
	data := TemplateData{UserName: b.UserName, Items: items}
	err = tmpl.Execute(w, data)
	if err != nil {
		return err
	}

	return nil
}
