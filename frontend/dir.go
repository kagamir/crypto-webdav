package frontend

import (
	"crypto-webdav/frontend/templates"
	"golang.org/x/net/webdav"
	"html/template"
	"io"
	"log"
	"os"
	"strconv"
)

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

type BrowserDir struct {
	FS   webdav.FileSystem
	Name string
}

func (b *BrowserDir) MakeHTML(w io.Writer) (err error) {
	tmpl, err := template.New("dir template").Parse(templates.BrowserDirHtml)
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
		var isDir string
		if fileInfo.IsDir() {
			isDir = "Dir"
		} else {
			isDir = "File"
		}

		items = append(items, TemplateItem{
			Name:    fileInfo.Name(),
			Path:    "/" + fileInfo.Name(),
			Size:    strconv.FormatInt(fileInfo.Size(), 10),
			Mode:    strconv.Itoa(int(fileInfo.Mode())),
			ModTime: fileInfo.ModTime().Format("2006-01-02 15:04:05"),
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
