package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// NodeID 表示物理文件 ID（加密文件名）或逻辑节点 ID
type NodeID string

// FileNode 表示逻辑文件树中的一个节点
type FileNode struct {
	ID       NodeID               `json:"id"`                 // 对于文件：物理文件名；目录可以为空
	Name     string               `json:"name"`               // 逻辑名（单个路径组件）
	Size     int64                `json:"size"`               // 逻辑文件大小（字节），主要用于展示
	ModTime  time.Time            `json:"modTime"`            // 修改时间
	IsDir    bool                 `json:"isDir"`              // 是否为目录
	Children map[string]*FileNode `json:"children,omitempty"` // 仅目录节点使用，key 为子项 Name
}

// IndexRoot 是整棵逻辑文件树的根
type IndexRoot struct {
	Version int       `json:"version"`
	Root    *FileNode `json:"root"`
}

const (
	indexFileName    = "index.meta.enc"
	indexFileTmpName = "index.meta.enc.tmp"
	filesDirName     = "files"
	indexVersion     = 1
)

// LogicalFileInfo 实现 fs.FileInfo，用于逻辑节点
type LogicalFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
}

func (i *LogicalFileInfo) Name() string       { return i.name }
func (i *LogicalFileInfo) Size() int64        { return i.size }
func (i *LogicalFileInfo) Mode() fs.FileMode  { return i.mode }
func (i *LogicalFileInfo) ModTime() time.Time { return i.modTime }
func (i *LogicalFileInfo) IsDir() bool        { return i.isDir }
func (i *LogicalFileInfo) Sys() any           { return nil }

// 加密任意 JSON 数据（用于索引文件）
func encryptIndexData(plain []byte, key []byte) ([]byte, error) {
	nonce := make([]byte, BlockSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, nonce)
	ciphertext := make([]byte, len(plain))
	stream.XORKeyStream(ciphertext, plain)

	return append(nonce, ciphertext...), nil
}

func decryptIndexData(encrypted []byte, key []byte) ([]byte, error) {
	if len(encrypted) < BlockSize {
		return nil, os.ErrInvalid
	}

	nonce := encrypted[:BlockSize]
	ciphertext := encrypted[BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, nonce)
	plain := make([]byte, len(ciphertext))
	stream.XORKeyStream(plain, ciphertext)
	return plain, nil
}

// ensureBaseLayout 确保用户根目录及 files 子目录存在
func ensureBaseLayout(baseDir string) error {
	if baseDir == "" {
		baseDir = "."
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return err
	}
	filesDir := filepath.Join(baseDir, filesDirName)
	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		return err
	}
	return nil
}

// LoadIndex 读取并解密索引文件，如不存在则创建一个空根目录索引
func LoadIndex(baseDir string, key []byte) (*IndexRoot, error) {
	if err := ensureBaseLayout(baseDir); err != nil {
		return nil, err
	}

	indexPath := filepath.Join(baseDir, indexFileName)
	data, err := os.ReadFile(indexPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// 创建默认根索引
			root := &FileNode{
				Name:     "",
				IsDir:    true,
				Children: make(map[string]*FileNode),
				ModTime:  time.Now(),
			}
			return &IndexRoot{
				Version: indexVersion,
				Root:    root,
			}, nil
		}
		return nil, err
	}

	plain, err := decryptIndexData(data, key)
	if err != nil {
		return nil, err
	}

	var idx IndexRoot
	if err := json.Unmarshal(plain, &idx); err != nil {
		return nil, err
	}

	if idx.Root == nil {
		idx.Root = &FileNode{
			Name:     "",
			IsDir:    true,
			Children: make(map[string]*FileNode),
			ModTime:  time.Now(),
		}
	}
	return &idx, nil
}

// SaveIndex 原子性写回索引文件
func SaveIndex(idx *IndexRoot, baseDir string, key []byte) error {
	if err := ensureBaseLayout(baseDir); err != nil {
		return err
	}

	idx.Version = indexVersion

	plain, err := json.Marshal(idx)
	if err != nil {
		return err
	}

	encrypted, err := encryptIndexData(plain, key)
	if err != nil {
		return err
	}

	tmpPath := filepath.Join(baseDir, indexFileTmpName)
	finalPath := filepath.Join(baseDir, indexFileName)

	if err := os.WriteFile(tmpPath, encrypted, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, finalPath)
}

// splitPathComponents 将 WebDAV 路径分割为逻辑组件
func splitPathComponents(p string) []string {
	if p == "" || p == "/" || p == "." {
		return nil
	}
	p = filepath.ToSlash(p)
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	parts := strings.Split(p, "/")
	return parts
}

// findNodeByPath 在索引树中查找指定路径的节点
func findNodeByPath(idx *IndexRoot, logicalPath string) (*FileNode, error) {
	if idx == nil || idx.Root == nil {
		return nil, os.ErrNotExist
	}
	components := splitPathComponents(logicalPath)
	if len(components) == 0 {
		return idx.Root, nil
	}

	cur := idx.Root
	for _, comp := range components {
		if !cur.IsDir {
			return nil, os.ErrNotExist
		}
		if cur.Children == nil {
			return nil, os.ErrNotExist
		}
		child, ok := cur.Children[comp]
		if !ok {
			return nil, os.ErrNotExist
		}
		cur = child
	}
	return cur, nil
}

// findParentAndName 查找父目录节点以及最后一个组件名称
func findParentAndName(idx *IndexRoot, logicalPath string) (*FileNode, string, error) {
	components := splitPathComponents(logicalPath)
	if len(components) == 0 {
		// 根目录没有父节点
		return nil, "", os.ErrInvalid
	}
	if len(components) == 1 {
		return idx.Root, components[0], nil
	}

	parentPath := "/" + strings.Join(components[:len(components)-1], "/")
	parent, err := findNodeByPath(idx, parentPath)
	if err != nil {
		return nil, "", err
	}
	if !parent.IsDir {
		return nil, "", os.ErrInvalid
	}
	return parent, components[len(components)-1], nil
}

// ensureDirNode 确保路径对应的目录节点存在（可递归创建）
func ensureDirNode(idx *IndexRoot, logicalPath string, now time.Time) (*FileNode, error) {
	if idx == nil {
		return nil, os.ErrInvalid
	}
	if logicalPath == "" || logicalPath == "/" || logicalPath == "." {
		if idx.Root == nil {
			idx.Root = &FileNode{
				Name:     "",
				IsDir:    true,
				Children: make(map[string]*FileNode),
				ModTime:  now,
			}
		}
		return idx.Root, nil
	}

	components := splitPathComponents(logicalPath)
	cur := idx.Root
	if cur == nil {
		cur = &FileNode{
			Name:     "",
			IsDir:    true,
			Children: make(map[string]*FileNode),
			ModTime:  now,
		}
		idx.Root = cur
	}

	for _, comp := range components {
		if cur.Children == nil {
			cur.Children = make(map[string]*FileNode)
		}
		child, ok := cur.Children[comp]
		if !ok {
			child = &FileNode{
				Name:     comp,
				IsDir:    true,
				Children: make(map[string]*FileNode),
				ModTime:  now,
			}
			cur.Children[comp] = child
		}
		cur = child
	}
	return cur, nil
}

// deleteNode 删除指定路径的节点，返回被删除的节点
func deleteNode(idx *IndexRoot, logicalPath string) (*FileNode, error) {
	parent, name, err := findParentAndName(idx, logicalPath)
	if err != nil {
		return nil, err
	}
	if parent.Children == nil {
		return nil, os.ErrNotExist
	}
	node, ok := parent.Children[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	delete(parent.Children, name)
	parent.ModTime = time.Now()
	return node, nil
}

// collectFileIDs 收集某个子树下所有文件节点的 ID
func collectFileIDs(node *FileNode, ids *[]NodeID) {
	if node == nil {
		return
	}
	if !node.IsDir && node.ID != "" {
		*ids = append(*ids, node.ID)
	}
	if node.IsDir {
		for _, child := range node.Children {
			collectFileIDs(child, ids)
		}
	}
}

// randomNodeID 生成随机 NodeID（十六进制字符串）
func randomNodeID() (NodeID, error) {
	const idBytes = 16 // 128bit
	buf := make([]byte, idBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return NodeID(fmtBytesToHex(buf)), nil
}

// fmtBytesToHex 将字节数组转换为十六进制字符串
func fmtBytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexChars[v>>4]
		out[i*2+1] = hexChars[v&0x0f]
	}
	return string(out)
}

// 文件节点对应的物理路径
func fileNodePhysicalPath(baseDir string, node *FileNode) string {
	return filepath.Join(baseDir, filesDirName, string(node.ID))
}

// 目录节点的 LogicalFileInfo
func dirNodeFileInfo(node *FileNode) fs.FileInfo {
	name := node.Name
	if name == "" {
		name = "/"
	}
	return &LogicalFileInfo{
		name:    name,
		size:    0,
		mode:    fs.ModeDir | 0o755,
		modTime: node.ModTime,
		isDir:   true,
	}
}

// 文件节点的 LogicalFileInfo，size/modTime 可依据物理文件
func fileNodeFileInfo(node *FileNode, physical fs.FileInfo) fs.FileInfo {
	size := node.Size
	modTime := node.ModTime
	if physical != nil {
		// 物理文件大小包含前置 nonce，需要减去 BlockSize
		decryptedSize := physical.Size() - BlockSize
		if decryptedSize < 0 {
			decryptedSize = 0
		}
		size = decryptedSize
		modTime = physical.ModTime()
	}
	if size < 0 {
		size = 0
	}
	return &LogicalFileInfo{
		name:    node.Name,
		size:    size,
		mode:    0o644,
		modTime: modTime,
		isDir:   false,
	}
}

// DirFile 是纯逻辑目录的 webdav.File 实现
type DirFile struct {
	node      *FileNode
	children  []fs.FileInfo
	readIndex int
}

func newDirFile(node *FileNode, baseDir string) *DirFile {
	infos := make([]fs.FileInfo, 0, len(node.Children))
	for _, child := range node.Children {
		if child.IsDir {
			infos = append(infos, dirNodeFileInfo(child))
		} else {
			// 对文件我们在 Readdir 里不访问物理文件，只用索引中的信息
			infos = append(infos, &LogicalFileInfo{
				name:    child.Name,
				size:    child.Size,
				mode:    0o644,
				modTime: child.ModTime,
				isDir:   false,
			})
		}
	}

	// 为了在前端展示时有稳定顺序，这里按“先目录后文件，再按名称字典序”进行排序。
	sort.Slice(infos, func(i, j int) bool {
		di := infos[i].IsDir()
		dj := infos[j].IsDir()
		if di != dj {
			// 目录排在文件前面
			return di && !dj
		}
		return infos[i].Name() < infos[j].Name()
	})

	return &DirFile{
		node:      node,
		children:  infos,
		readIndex: 0,
	}
}

// Read 实现 io.Reader，但目录不支持读
func (d *DirFile) Read(p []byte) (int, error) {
	return 0, os.ErrInvalid
}

// Write 实现 io.Writer，但目录不支持写
func (d *DirFile) Write(p []byte) (int, error) {
	return 0, os.ErrInvalid
}

// Seek 实现 io.Seeker，对目录无意义
func (d *DirFile) Seek(offset int64, whence int) (int64, error) {
	return 0, os.ErrInvalid
}

// Readdir 返回目录子项
func (d *DirFile) Readdir(count int) ([]fs.FileInfo, error) {
	if count <= 0 {
		// 返回所有剩余
		if d.readIndex >= len(d.children) {
			return nil, io.EOF
		}
		res := d.children[d.readIndex:]
		d.readIndex = len(d.children)
		return res, nil
	}

	if d.readIndex >= len(d.children) {
		return nil, io.EOF
	}

	remain := len(d.children) - d.readIndex
	if count > remain {
		count = remain
	}
	res := d.children[d.readIndex : d.readIndex+count]
	d.readIndex += count
	return res, nil
}

// Stat 返回目录本身的 FileInfo
func (d *DirFile) Stat() (fs.FileInfo, error) {
	return dirNodeFileInfo(d.node), nil
}

// Close 目录文件无资源需要释放
func (d *DirFile) Close() error {
	return nil
}

// LogicalFile 包装 EncryptedFile，在 Close 时更新索引中的 size/modTime 并持久化
type LogicalFile struct {
	*EncryptedFile
	index   *IndexRoot
	node    *FileNode
	baseDir string
	key     []byte
}

func (f *LogicalFile) Close() error {
	// 在关闭前先获取物理文件信息
	if f.node != nil && f.index != nil && f.EncryptedFile != nil {
		if info, err := os.Stat(f.EncryptedFile.actualPath); err == nil {
			size := info.Size() - BlockSize
			if size < 0 {
				size = 0
			}
			f.node.Size = size
			f.node.ModTime = info.ModTime()
			_ = SaveIndex(f.index, f.baseDir, f.key)
		}
	}

	// 最后关闭底层文件
	return f.EncryptedFile.Close()
}
