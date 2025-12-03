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
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
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
	indexFileName       = "index.meta.enc"
	indexFileTmpName    = "index.meta.enc.tmp"
	filesDirName        = "files"
	indexVersion        = 1
	indexBackupFileName = "index.meta.enc.bak"

	// indexBackupQueueSize 异步备份任务队列长度
	indexBackupQueueSize = 16
)

var (
	// indexLocks 为每个用户的索引文件提供读写锁保护
	// key: baseDir (用户目录路径), value: *sync.RWMutex
	indexLocks sync.Map

	// indexBackupJobs 为索引备份任务提供异步队列
	indexBackupJobs chan string

	// indexBackupOnce 确保备份 worker 只启动一次
	indexBackupOnce sync.Once
)

// getIndexLock 获取指定 baseDir 的读写锁
func getIndexLock(baseDir string) *sync.RWMutex {
	// 规范化路径以确保一致性
	baseDir = filepath.Clean(baseDir)
	if baseDir == "" {
		baseDir = "."
	}

	// 使用 LoadOrStore 确保每个 baseDir 只有一个锁
	lock, _ := indexLocks.LoadOrStore(baseDir, &sync.RWMutex{})
	return lock.(*sync.RWMutex)
}

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

// initIndexBackupWorker 初始化索引备份 worker（只会执行一次）
func initIndexBackupWorker() {
	indexBackupOnce.Do(func() {
		indexBackupJobs = make(chan string, indexBackupQueueSize)
		go indexBackupWorker()
	})
}

// scheduleIndexBackup 调度一次异步索引备份
// 仅负责将任务放入队列，不做实际 I/O，避免阻塞主写路径
func scheduleIndexBackup(baseDir string) {
	if baseDir == "" {
		baseDir = "."
	}
	baseDir = filepath.Clean(baseDir)

	initIndexBackupWorker()

	select {
	case indexBackupJobs <- baseDir:
	default:
		log.Warn().
			Str("baseDir", baseDir).
			Msg("Index backup queue is full, dropping backup request")
	}
}

// indexBackupWorker 持续从队列中读取任务并执行实际备份
func indexBackupWorker() {
	for baseDir := range indexBackupJobs {
		if err := doIndexBackup(baseDir); err != nil {
			log.Error().
				Str("baseDir", baseDir).
				Err(err).
				Msg("Failed to backup index file")
		}
	}
}

// doIndexBackup 执行一次实际的索引文件备份
// 在 baseDir 下将 index.meta.enc 复制到 files/index.meta.enc.bak
func doIndexBackup(baseDir string) error {
	if err := ensureBaseLayout(baseDir); err != nil {
		return err
	}

	indexPath := filepath.Join(baseDir, indexFileName)

	// 若索引文件不存在（比如刚初始化），直接跳过备份
	if _, err := os.Stat(indexPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Debug().
				Str("baseDir", baseDir).
				Msg("Index file not found, skip backup")
			return nil
		}
		return err
	}

	backupDir := filepath.Join(baseDir, filesDirName)
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return err
	}
	backupPath := filepath.Join(backupDir, indexBackupFileName)

	src, err := os.Open(indexPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(backupPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}

	return nil
}

// LoadIndex 读取并解密索引文件，如不存在则创建一个空根目录索引
// 使用读锁保护，允许多个并发读取
func LoadIndex(baseDir string, key []byte) (*IndexRoot, error) {
	if err := ensureBaseLayout(baseDir); err != nil {
		return nil, err
	}

	// 获取读锁，允许多个 goroutine 同时读取
	lock := getIndexLock(baseDir)
	lock.RLock()
	defer lock.RUnlock()

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
// 使用写锁保护，确保写入时不会有其他读取或写入操作
func SaveIndex(idx *IndexRoot, baseDir string, key []byte) error {
	if err := ensureBaseLayout(baseDir); err != nil {
		return err
	}

	// 获取写锁，确保写入时不会有其他读取或写入操作
	lock := getIndexLock(baseDir)
	lock.Lock()
	defer lock.Unlock()

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

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return err
	}

	// 索引写入成功后，调度一次异步备份
	scheduleIndexBackup(baseDir)

	return nil
}

// UpdateIndex 原子性地读取、修改并保存索引文件
// 这个函数确保整个"读取-修改-写入"操作在写锁保护下执行，避免丢失更新
// updateFn 是一个函数，接收当前的索引并修改它，返回修改后的索引和错误
func UpdateIndex(baseDir string, key []byte, updateFn func(*IndexRoot) (*IndexRoot, error)) error {
	if err := ensureBaseLayout(baseDir); err != nil {
		return err
	}

	// 获取写锁，确保整个操作期间不会有其他读取或写入操作
	lock := getIndexLock(baseDir)
	lock.Lock()
	defer lock.Unlock()

	// 在写锁保护下读取索引
	indexPath := filepath.Join(baseDir, indexFileName)
	data, err := os.ReadFile(indexPath)
	var idx *IndexRoot

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// 创建默认根索引
			root := &FileNode{
				Name:     "",
				IsDir:    true,
				Children: make(map[string]*FileNode),
				ModTime:  time.Now(),
			}
			idx = &IndexRoot{
				Version: indexVersion,
				Root:    root,
			}
		} else {
			return err
		}
	} else {
		plain, err := decryptIndexData(data, key)
		if err != nil {
			return err
		}

		var indexRoot IndexRoot
		if err := json.Unmarshal(plain, &indexRoot); err != nil {
			return err
		}

		if indexRoot.Root == nil {
			indexRoot.Root = &FileNode{
				Name:     "",
				IsDir:    true,
				Children: make(map[string]*FileNode),
				ModTime:  time.Now(),
			}
		}
		idx = &indexRoot
	}

	// 执行用户提供的更新函数
	updatedIdx, err := updateFn(idx)
	if err != nil {
		return err
	}
	if updatedIdx == nil {
		updatedIdx = idx
	}

	// 保存更新后的索引
	updatedIdx.Version = indexVersion

	plain, err := json.Marshal(updatedIdx)
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

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return err
	}

	// 索引更新成功后，调度一次异步备份
	scheduleIndexBackup(baseDir)

	return nil
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

// randomNodeID 生成随机 NodeID（UUIDv4格式）
func randomNodeID() (NodeID, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return NodeID(id.String()), nil
}

// FilePathFromID 根据 NodeID 生成物理文件路径。
// 为了降低单目录文件数量，这里按 UUIDv4 的尾部4个字符（去掉连字符）进行两级分桶：
//
//	upload/user/files/ab/cd/xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxabcd
//
// UUIDv4格式：xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx（36字符）
// 分桶策略：使用尾部4个字符（去掉连字符后的最后4个字符）的前2个字符和后2个字符进行两级分桶
// 例如：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxabcd → 使用 ab 和 cd 进行分桶
func FilePathFromID(baseDir string, id NodeID) string {
	baseDir = filepath.Clean(baseDir)
	if baseDir == "" {
		baseDir = "."
	}

	idStr := string(id)
	// UUIDv4格式：xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx
	// 去掉连字符，取尾部4个字符进行分桶
	idWithoutHyphens := strings.ReplaceAll(idStr, "-", "")

	if len(idWithoutHyphens) >= 4 {
		// 使用尾部4个字符的前2个字符和后2个字符进行两级分桶
		// 例如：...abcd -> bucket1=ab, bucket2=cd
		last4 := idWithoutHyphens[len(idWithoutHyphens)-4:]
		bucket1 := last4[:2]
		bucket2 := last4[2:4]
		return filepath.Join(baseDir, filesDirName, bucket1, bucket2, idStr)
	}

	if len(idWithoutHyphens) >= 2 {
		// 如果长度不足4，使用最后2个字符进行一级分桶
		last2 := idWithoutHyphens[len(idWithoutHyphens)-2:]
		return filepath.Join(baseDir, filesDirName, last2, idStr)
	}
	return filepath.Join(baseDir, filesDirName, idStr)
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
		// 返回所有剩余；即使目录为空也视为成功
		if d.readIndex >= len(d.children) {
			return nil, nil
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
	// 在关闭前先获取物理文件信息并更新索引
	if f.node != nil && f.EncryptedFile != nil {
		if info, err := os.Stat(f.EncryptedFile.actualPath); err == nil {
			size := info.Size() - BlockSize
			if size < 0 {
				size = 0
			}
			// 使用当前时间作为真实修改时间，而不是物理文件的时间（物理文件时间已被抹除）
			realModTime := time.Now()

			// 使用 UpdateIndex 原子性地更新索引，避免丢失其他并发更新
			// 需要根据节点的 ID 或路径来查找并更新节点
			err := UpdateIndex(f.baseDir, f.key, func(idx *IndexRoot) (*IndexRoot, error) {
				// 在写锁保护下重新查找节点（可能索引已被其他线程更新）
				// 通过遍历树来查找具有相同 ID 的节点
				var targetNode *FileNode
				var findNode func(*FileNode)
				findNode = func(n *FileNode) {
					if n != nil && n.ID == f.node.ID {
						targetNode = n
						return
					}
					if n != nil && n.IsDir && n.Children != nil {
						for _, child := range n.Children {
							if targetNode != nil {
								return
							}
							findNode(child)
						}
					}
				}
				findNode(idx.Root)

				if targetNode != nil {
					targetNode.Size = size
					// 使用真实时间（当前时间）而不是物理文件时间
					targetNode.ModTime = realModTime
				}
				return idx, nil
			})
			if err != nil {
				// 记录错误但不阻止文件关闭
				log.Error().
					Str("baseDir", f.baseDir).
					Err(err).
					Msg("Failed to update index on file close")
			}
		}
	}

	// 最后关闭底层文件（这会抹除物理文件的时间戳）
	return f.EncryptedFile.Close()
}
