package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// GetNameHash 计算文件/目录名的 SHA256 哈希
func GetNameHash(name string) string {
	hash := sha256.Sum256([]byte(name))
	return hex.EncodeToString(hash[:])
}

// ResolveHashToName 通过哈希值查找原始文件名（读取元信息文件）
func ResolveHashToName(dirPath string, hash string, key []byte) (string, bool, error) {
	metaPath := filepath.Join(dirPath, hash+".meta")
	metadata, err := ReadMetadataFile(metaPath, key)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return metadata.Name, metadata.IsDir, nil
}

// ResolveNameToHash 通过原始文件名查找哈希值（遍历目录查找匹配的元信息）
func ResolveNameToHash(dirPath string, name string, key []byte) (string, bool, error) {
	// 读取目录中的所有文件
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		log.Error().
			Str("dir_path", dirPath).
			Str("name", name).
			Err(err).
			Msg("Failed to read directory for name resolution")
		return "", false, err
	}

	// 遍历所有 .meta 文件
	for _, entry := range entries {
		if entry.IsDir() {
			// 目录也可能有元信息文件
			metaPath := filepath.Join(dirPath, entry.Name()+".meta")
			if _, err := os.Stat(metaPath); err == nil {
				metadata, err := ReadMetadataFile(metaPath, key)
				if err != nil {
					log.Warn().
						Str("meta_path", metaPath).
						Err(err).
						Msg("Error reading metadata for directory entry")
					continue
				}
				if metadata.Name == name {
					hash := entry.Name()
					return hash, metadata.IsDir, nil
				}
			}
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}

		metaPath := filepath.Join(dirPath, entry.Name())
		metadata, err := ReadMetadataFile(metaPath, key)
		if err != nil {
			log.Warn().
				Str("meta_path", metaPath).
				Err(err).
				Msg("Error reading metadata file")
			continue
		}

		// 检查名称是否匹配
		if metadata.Name == name {
			hash := strings.TrimSuffix(entry.Name(), ".meta")
			return hash, metadata.IsDir, nil
		}
	}

	log.Debug().
		Str("name", name).
		Str("dir_path", dirPath).
		Msg("Name not found in directory")
	return "", false, nil
}

// ResolvePath 将原始路径转换为实际文件系统路径
// 输入: /path/to/file.txt
// 输出: ./upload/user/{hash} 或 ./upload/user/{hash1}/{hash2}/{hash3}
func ResolvePath(originalPath string, baseDir string, key []byte) (string, error) {
	log.Debug().
		Str("original_path", originalPath).
		Str("base_dir", baseDir).
		Msg("Resolving path")

	// 清理路径
	if originalPath == "" {
		originalPath = "/"
	}
	originalPath = filepath.Clean(originalPath)

	// 如果是根目录
	if originalPath == "/" || originalPath == "." {
		log.Debug().
			Str("base_dir", baseDir).
			Msg("Root directory, returning base directory")
		return baseDir, nil
	}

	// 分割路径组件
	components := strings.Split(strings.Trim(originalPath, "/"), "/")
	log.Debug().
		Strs("components", components).
		Msg("Path components")
	currentDir := baseDir

	// 逐级解析路径
	for i, component := range components {
		log.Debug().
			Int("index", i).
			Str("component", component).
			Str("current_dir", currentDir).
			Msg("Resolving path component")
		hash, isDir, err := ResolveNameToHash(currentDir, component, key)
		if err != nil {
			log.Error().
				Str("component", component).
				Str("current_dir", currentDir).
				Err(err).
				Msg("Error resolving path component")
			return "", err
		}
		if hash == "" {
			log.Debug().
				Str("component", component).
				Str("current_dir", currentDir).
				Msg("Component not found in directory")
			return "", os.ErrNotExist
		}

		log.Debug().
			Str("hash", hash).
			Bool("is_dir", isDir).
			Msg("Found hash for component")
		currentDir = filepath.Join(currentDir, hash)

		// 检查最后一项是否为目录（如果不是最后一项，必须是目录）
		if i < len(components)-1 {
			if !isDir {
				log.Error().
					Str("component", component).
					Msg("Component is not a directory but path continues")
				return "", os.ErrNotExist
			}
		}
	}

	log.Debug().
		Str("resolved_path", currentDir).
		Msg("Final resolved path")
	return currentDir, nil
}

// ListDirectory 列出目录内容，返回原始名称和对应的哈希值
func ListDirectory(dirPath string, key []byte) ([]fs.FileInfo, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	var fileInfos []fs.FileInfo

	for _, entry := range entries {
		// 跳过 .meta 文件本身
		if strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}

		// 读取对应的元信息文件
		metaPath := filepath.Join(dirPath, entry.Name()+".meta")
		metadata, err := ReadMetadataFile(metaPath, key)
		if err != nil {
			// 如果元信息文件不存在，跳过（可能是旧文件或损坏）
			log.Warn().
				Str("entry_name", entry.Name()).
				Str("meta_path", metaPath).
				Err(err).
				Msg("Metadata not found for directory entry")
			continue
		}

		// 获取实际文件信息
		actualPath := filepath.Join(dirPath, entry.Name())
		actualInfo, err := os.Stat(actualPath)
		if err != nil {
			log.Warn().
				Str("actual_path", actualPath).
				Err(err).
				Msg("Cannot stat file in directory")
			continue
		}

		// 创建包含原始信息的 FileInfo
		fileInfo := &MetadataFileInfo{
			FileInfo: actualInfo,
			metadata: metadata,
		}

		fileInfos = append(fileInfos, fileInfo)
	}

	return fileInfos, nil
}

// EnsureDirectoryExists 确保目录存在，如果不存在则创建（使用哈希名）
func EnsureDirectoryExists(dirPath string, dirName string, key []byte) (string, error) {
	// 计算目录名哈希
	hash := GetNameHash(dirName)
	hashPath := filepath.Join(dirPath, hash)

	// 检查目录是否已存在
	if _, err := os.Stat(hashPath); err == nil {
		// 目录已存在，检查元信息文件
		metaPath := filepath.Join(dirPath, hash+".meta")
		if _, err := os.Stat(metaPath); err == nil {
			// 元信息文件存在，返回路径
			return hashPath, nil
		}
		// 元信息文件不存在，创建它
		metadata := &Metadata{
			Name:    dirName,
			Size:    0,
			ModTime: getCurrentTime(),
			IsDir:   true,
		}
		if err := WriteMetadataFile(metaPath, metadata, key); err != nil {
			return "", err
		}
		return hashPath, nil
	}

	// 创建目录
	if err := os.MkdirAll(hashPath, 0755); err != nil {
		return "", err
	}

	// 创建元信息文件
	metaPath := filepath.Join(dirPath, hash+".meta")
	metadata := &Metadata{
		Name:    dirName,
		Size:    0,
		ModTime: getCurrentTime(),
		IsDir:   true,
	}
	if err := WriteMetadataFile(metaPath, metadata, key); err != nil {
		os.RemoveAll(hashPath) // 清理
		return "", err
	}

	return hashPath, nil
}

// getCurrentTime 获取当前时间
func getCurrentTime() time.Time {
	return time.Now()
}
