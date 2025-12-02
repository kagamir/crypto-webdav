package crypto

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/argon2"
	"golang.org/x/net/webdav"
)

func Sha256(s string) (hash []byte) {
	h := sha256.New()
	h.Write([]byte(s))
	hash = h.Sum(nil)
	return
}

func Argon2(password string, salt string) (hash []byte) {
	hash = argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return
}

type FileCrypto struct {
	webdav.Dir
}

func slashClean(name string) string {
	if name == "" || name[0] != '/' {
		name = "/" + name
	}
	return path.Clean(name)
}

// getKey 从 context 获取加密密钥
func (c FileCrypto) getKey(ctx context.Context) []byte {
	if ctx == nil {
		return nil
	}
	key, ok := ctx.Value("crypto.Key").([]byte)
	if !ok {
		return nil
	}
	return key
}

// resolve 将原始路径解析为实际文件系统路径
func (c FileCrypto) resolve(ctx context.Context, name string) (string, error) {
	log.Debug().Str("path", name).Msg("Resolving path")

	// 清理路径
	if name == "" {
		name = "/"
	}

	// 安全检查
	if filepath.Separator != '/' && strings.ContainsRune(name, filepath.Separator) ||
		strings.Contains(name, "\x00") {
		return "", os.ErrNotExist
	}

	baseDir := string(c.Dir)
	if baseDir == "" {
		baseDir = "."
	}

	// 获取加密密钥
	key := c.getKey(ctx)
	if key == nil {
		return "", os.ErrPermission
	}

	// 使用新的路径解析
	return ResolvePath(name, baseDir, key)
}

func (c FileCrypto) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	// 使用逻辑索引进行 Stat，而不是实际目录结构
	// 逻辑根目录
	if name == "" {
		name = "/"
	}

	key := c.getKey(ctx)
	if key == nil {
		return nil, os.ErrPermission
	}

	baseDir := filepath.Clean(string(c.Dir))
	index, err := LoadIndex(baseDir, key)
	if err != nil {
		return nil, err
	}

	node, err := findNodeByPath(index, name)
	if err != nil {
		return nil, err
	}

	if node.IsDir {
		return dirNodeFileInfo(node), nil
	}

	// 文件：读取物理文件信息来补充大小/时间
	physicalPath := fileNodePhysicalPath(baseDir, node)
	physicalInfo, err := os.Stat(physicalPath)
	if err != nil {
		return nil, err
	}

	return fileNodeFileInfo(node, physicalInfo), nil
}

func (c FileCrypto) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	log.Info().Str("path", name).Msg("Creating logical directory")

	if name == "" {
		name = "/"
	}

	key := c.getKey(ctx)
	if key == nil {
		return os.ErrPermission
	}

	baseDir := filepath.Clean(string(c.Dir))
	index, err := LoadIndex(baseDir, key)
	if err != nil {
		return err
	}

	// WebDAV 语义：父目录必须存在
	parent, dirName, err := findParentAndName(index, name)
	if err != nil {
		return err
	}
	if !parent.IsDir {
		return os.ErrInvalid
	}

	if parent.Children == nil {
		parent.Children = make(map[string]*FileNode)
	}
	if _, exists := parent.Children[dirName]; exists {
		return os.ErrExist
	}

	now := time.Now()
	parent.Children[dirName] = &FileNode{
		Name:     dirName,
		IsDir:    true,
		Children: make(map[string]*FileNode),
		ModTime:  now,
	}
	parent.ModTime = now

	return SaveIndex(index, baseDir, key)
}

func (c FileCrypto) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	if name == "" {
		name = "/"
	}

	key := c.getKey(ctx)
	if key == nil {
		return nil, os.ErrPermission
	}

	baseDir := filepath.Clean(string(c.Dir))
	index, err := LoadIndex(baseDir, key)
	if err != nil {
		return nil, err
	}

	// 处理根目录
	if name == "/" {
		return newDirFile(index.Root, baseDir), nil
	}

	// 先查找是否已经存在节点
	node, err := findNodeByPath(index, name)
	if err != nil {
		// 不存在
		if !os.IsNotExist(err) && err != os.ErrNotExist {
			return nil, err
		}
		// 仅在 O_CREATE 时允许创建新文件
		if flag&os.O_CREATE == 0 {
			return nil, err
		}

		// 创建新文件节点（父目录必须存在且为目录）
		parent, fileName, err := findParentAndName(index, name)
		if err != nil {
			return nil, err
		}
		if !parent.IsDir {
			return nil, os.ErrInvalid
		}
		if parent.Children == nil {
			parent.Children = make(map[string]*FileNode)
		}
		if existing, ok := parent.Children[fileName]; ok && existing.IsDir {
			// 目标是目录
			return nil, os.ErrInvalid
		}

		newID, err := randomNodeID()
		if err != nil {
			return nil, err
		}

		now := time.Now()
		node = &FileNode{
			ID:      newID,
			Name:    fileName,
			IsDir:   false,
			Size:    0,
			ModTime: now,
		}
		parent.Children[fileName] = node
		parent.ModTime = now

		if err := SaveIndex(index, baseDir, key); err != nil {
			return nil, err
		}
	}

	// 目录：返回逻辑目录文件
	if node.IsDir {
		return newDirFile(node, baseDir), nil
	}

	// 文件：打开物理加密文件
	physicalPath := fileNodePhysicalPath(baseDir, node)

	// 确保 files 目录存在
	if err := ensureBaseLayout(baseDir); err != nil {
		return nil, err
	}

	// 创建物理文件（若需要）
	if flag&os.O_CREATE != 0 {
		if _, err := os.Stat(physicalPath); errors.Is(err, os.ErrNotExist) {
			f, err := os.OpenFile(physicalPath, os.O_CREATE|os.O_WRONLY, perm)
			if err != nil {
				return nil, err
			}
			_ = f.Close()
		}
	}

	enc := &EncryptedFile{}
	if err := enc.Open(physicalPath, flag, perm, key); err != nil {
		return nil, err
	}

	// 使用 LogicalFile 包装，在 Close 时更新索引
	return &LogicalFile{
		EncryptedFile: enc,
		index:         index,
		node:          node,
		baseDir:       baseDir,
		key:           key,
	}, nil
}

func (c FileCrypto) RemoveAll(ctx context.Context, name string) error {
	log.Info().Str("path", name).Msg("Removing logical path")

	if name == "" || name == "/" || name == "." {
		// 禁止删除虚拟根目录
		return os.ErrInvalid
	}

	key := c.getKey(ctx)
	if key == nil {
		return os.ErrPermission
	}

	baseDir := filepath.Clean(string(c.Dir))
	index, err := LoadIndex(baseDir, key)
	if err != nil {
		return err
	}

	// 删除索引中的节点，并收集需要删除的物理文件 ID
	node, err := deleteNode(index, name)
	if err != nil {
		return err
	}

	var ids []NodeID
	collectFileIDs(node, &ids)

	if err := SaveIndex(index, baseDir, key); err != nil {
		return err
	}

	// 删除对应的物理加密文件
	for _, id := range ids {
		p := filepath.Join(baseDir, filesDirName, string(id))
		if err := os.RemoveAll(p); err != nil && !os.IsNotExist(err) {
			log.Warn().
				Str("resolved_path", p).
				Err(err).
				Msg("Failed to remove physical file")
		}
	}

	log.Info().Str("path", name).Msg("Successfully removed logical path")
	return nil
}

func (c FileCrypto) Rename(ctx context.Context, oldName, newName string) error {
	key := c.getKey(ctx)
	if key == nil {
		return os.ErrPermission
	}

	if oldName == "" {
		oldName = "/"
	}
	if newName == "" {
		newName = "/"
	}

	baseDir := filepath.Clean(string(c.Dir))
	index, err := LoadIndex(baseDir, key)
	if err != nil {
		return err
	}

	// 查找旧节点及其父目录
	oldParent, oldBase, err := findParentAndName(index, oldName)
	if err != nil {
		return err
	}
	if oldParent.Children == nil {
		return os.ErrNotExist
	}
	node, ok := oldParent.Children[oldBase]
	if !ok {
		return os.ErrNotExist
	}

	// 新父目录
	newParent, newBase, err := findParentAndName(index, newName)
	if err != nil {
		return err
	}
	if !newParent.IsDir {
		return os.ErrInvalid
	}
	if newParent.Children == nil {
		newParent.Children = make(map[string]*FileNode)
	}

	// 如果目标已存在，先删除（简单覆盖语义）
	if existing, ok := newParent.Children[newBase]; ok {
		var ids []NodeID
		collectFileIDs(existing, &ids)
		delete(newParent.Children, newBase)
		for _, id := range ids {
			p := filepath.Join(baseDir, filesDirName, string(id))
			if err := os.RemoveAll(p); err != nil && !os.IsNotExist(err) {
				log.Warn().
					Str("resolved_path", p).
					Err(err).
					Msg("Failed to remove physical file during rename overwrite")
			}
		}
	}

	// 从旧父目录移除并插入到新父目录
	delete(oldParent.Children, oldBase)
	node.Name = newBase
	now := time.Now()
	node.ModTime = now
	newParent.Children[newBase] = node
	oldParent.ModTime = now
	newParent.ModTime = now

	return SaveIndex(index, baseDir, key)
}
