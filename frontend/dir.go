package frontend

import (
	"crypto-webdav/crytpo"
	"embed"
	"fmt"
	"golang.org/x/net/webdav"
	"html/template"
	"io"
	"log"
	"os"
	"strconv"
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
	Items []TemplateItem
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
	FS   webdav.FileSystem
	Name string
}

func (b *BrowserDir) MakeHTML(w io.Writer) (err error) {
	tmpl, err := template.ParseFS(embeddedFiles, "templates/browser.html")
	if err != nil {
		log.Println(err)
	}

	dir, err := b.FS.OpenFile(nil, b.Name, os.O_RDONLY, os.ModeDir)
	if err != nil {
		return
	}
	defer dir.Close()

	fileInfos, err := dir.Readdir(0)
	if err != nil {
		return
	}

	var items []TemplateItem
	for _, fileInfo := range fileInfos {
		fileStat := crytpo.EncryptedFileInfo{FileInfo: fileInfo}
		var isDir string
		var mode string
		var size string
		if fileStat.IsDir() {
			isDir = "Dir"
			mode = "-"
			size = "-"
		} else {
			isDir = "File"
			mode = strconv.FormatUint(uint64(fileStat.Mode()), 10)
			size = formatBytes(fileStat.Size())
		}

		items = append(items, TemplateItem{
			Name:    fileStat.Name(),
			Path:    "/" + fileStat.Name(),
			Size:    size,
			Mode:    mode,
			ModTime: fileStat.ModTime().Format("2006-01-02 15:04:05"),
			IsDir:   isDir,
		})
	}
	data := TemplateData{Items: items}
	err = tmpl.Execute(w, data)
	if err != nil {
		return
	}

	return
}
