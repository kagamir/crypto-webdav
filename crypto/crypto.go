package crypto

import (
	"context"
	"crypto/sha256"
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
	resolvedPath, err := c.resolve(ctx, name)
	if err != nil {
		return nil, err
	}

	// 获取实际文件信息
	actualInfo, err := os.Stat(resolvedPath)
	if err != nil {
		return nil, err
	}

	// 如果是目录，直接返回（目录的元信息在 ListDirectory 中处理）
	if actualInfo.IsDir() {
		// 读取目录元信息
		key := c.getKey(ctx)
		metaPath := GetMetadataFilePath(resolvedPath)
		metadata, err := ReadMetadataFile(metaPath, key)
		if err != nil {
			// 如果元信息不存在，返回基本文件信息
			return actualInfo, nil
		}
		return &MetadataFileInfo{
			FileInfo: actualInfo,
			metadata: metadata,
		}, nil
	}

	// 读取文件元信息
	key := c.getKey(ctx)
	metaPath := GetMetadataFilePath(resolvedPath)
	metadata, err := ReadMetadataFile(metaPath, key)
	if err != nil {
		// 如果元信息不存在，返回基本文件信息
		return actualInfo, nil
	}

	return &MetadataFileInfo{
		FileInfo: actualInfo,
		metadata: metadata,
	}, nil
}

func (c FileCrypto) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	log.Info().Str("path", name).Msg("Creating directory")

	// 解析父目录路径
	parentPath := filepath.Dir(name)
	if parentPath == "." || parentPath == "/" {
		parentPath = "/"
	}

	// 获取目录名
	dirName := filepath.Base(name)
	if dirName == "." || dirName == "/" {
		dirName = ""
	}

	// 解析父目录
	resolvedParent, err := c.resolve(ctx, parentPath)
	if err != nil {
		return err
	}

	// 获取加密密钥
	key := c.getKey(ctx)
	if key == nil {
		return os.ErrPermission
	}

	// 确保目录存在（使用哈希名）
	_, err = EnsureDirectoryExists(resolvedParent, dirName, key)
	return err
}

func (c FileCrypto) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	// 解析路径
	resolvedPath, err := c.resolve(ctx, name)
	if err != nil {
		// 如果文件不存在且是创建模式，需要创建新文件
		if os.IsNotExist(err) && (flag&os.O_CREATE != 0) {
			// 解析父目录
			parentPath := filepath.Dir(name)
			if parentPath == "." || parentPath == "/" {
				parentPath = "/"
			}
			fileName := filepath.Base(name)

			resolvedParent, err := c.resolve(ctx, parentPath)
			if err != nil {
				return nil, err
			}

			key := c.getKey(ctx)
			if key == nil {
				return nil, os.ErrPermission
			}

			// 创建临时文件，稍后计算哈希后重命名
			// 使用临时文件名
			tempHash := GetNameHash(fileName + time.Now().String())
			tempPath := filepath.Join(resolvedParent, tempHash)

			f := &EncryptedFile{originalName: fileName, parentDir: resolvedParent, isNewFile: true}
			err = f.Open(tempPath, flag, perm, key)
			if err != nil {
				return nil, err
			}
			return f, nil
		}
		return nil, err
	}

	// 获取加密密钥
	key := c.getKey(ctx)
	if key == nil {
		return nil, os.ErrPermission
	}

	// 打开现有文件
	f := &EncryptedFile{actualPath: resolvedPath}
	err = f.Open(resolvedPath, flag, perm, key)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (c FileCrypto) RemoveAll(ctx context.Context, name string) error {
	log.Info().Str("path", name).Msg("Removing path")

	resolvedPath, err := c.resolve(ctx, name)
	if err != nil {
		log.Error().
			Str("path", name).
			Err(err).
			Msg("Failed to resolve path for removal")
		return err
	}

	log.Debug().Str("resolved_path", resolvedPath).Msg("Resolved path for removal")

	baseDir := filepath.Clean(string(c.Dir))
	if resolvedPath == baseDir {
		// Prohibit removing the virtual root directory.
		return os.ErrInvalid
	}

	// 删除实际文件和元信息文件
	if err := os.RemoveAll(resolvedPath); err != nil {
		log.Error().
			Str("resolved_path", resolvedPath).
			Err(err).
			Msg("Failed to remove path")
		return err
	}

	metaPath := GetMetadataFilePath(resolvedPath)
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		log.Warn().
			Str("meta_path", metaPath).
			Err(err).
			Msg("Failed to remove metadata file")
		// 继续执行，不返回错误
	}

	log.Info().Str("resolved_path", resolvedPath).Msg("Successfully removed path")
	return nil
}

func (c FileCrypto) Rename(ctx context.Context, oldName, newName string) error {
	oldPath, err := c.resolve(ctx, oldName)
	if err != nil {
		return err
	}

	newPath, err := c.resolve(ctx, newName)
	if err != nil {
		// 如果新路径不存在，可能是重命名到新位置
		// 解析新路径的父目录和文件名
		newParentPath := filepath.Dir(newName)
		if newParentPath == "." || newParentPath == "/" {
			newParentPath = "/"
		}
		newFileName := filepath.Base(newName)

		key := c.getKey(ctx)
		if key == nil {
			return os.ErrPermission
		}

		// 解析新父目录
		newResolvedParent, err := c.resolve(ctx, newParentPath)
		if err != nil {
			return err
		}

		// 读取旧文件的元信息
		oldMetaPath := GetMetadataFilePath(oldPath)
		oldMetadata, err := ReadMetadataFile(oldMetaPath, key)
		if err != nil {
			return err
		}

		// 更新元信息中的名称
		oldMetadata.Name = newFileName
		oldMetadata.ModTime = time.Now()

		// 如果是文件，需要重新计算哈希（因为内容可能改变，但这里只是重命名，内容不变）
		// 对于重命名，我们保持相同的哈希，只更新元信息
		hash := filepath.Base(oldPath)

		// 移动文件
		newActualPath := filepath.Join(newResolvedParent, hash)
		if err := os.Rename(oldPath, newActualPath); err != nil {
			return err
		}

		// 更新元信息文件
		newMetaPath := GetMetadataFilePath(newActualPath)
		if err := WriteMetadataFile(newMetaPath, oldMetadata, key); err != nil {
			return err
		}

		// 删除旧元信息文件
		os.Remove(oldMetaPath)

		return nil
	}

	baseDir := filepath.Clean(string(c.Dir))
	if oldPath == baseDir || newPath == baseDir {
		// Prohibit renaming from or to the virtual root directory.
		return os.ErrInvalid
	}

	// 简单重命名（这种情况应该不会发生，因为路径已经解析为哈希）
	return os.Rename(oldPath, newPath)
}
