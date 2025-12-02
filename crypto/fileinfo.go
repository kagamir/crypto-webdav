package crypto

import (
	"os"
	"time"
)

// MetadataFileInfo 实现 os.FileInfo 接口，包含从元信息中获取的原始文件名等信息
type MetadataFileInfo struct {
	os.FileInfo
	metadata *Metadata
}

// Name 返回原始文件名或目录名
func (m *MetadataFileInfo) Name() string {
	return m.metadata.Name
}

// Size 返回原始文件大小（目录返回0）
func (m *MetadataFileInfo) Size() int64 {
	if m.metadata.IsDir {
		return 0
	}
	return m.metadata.Size
}

// ModTime 返回修改时间
func (m *MetadataFileInfo) ModTime() time.Time {
	return m.metadata.ModTime
}

// IsDir 返回是否为目录
func (m *MetadataFileInfo) IsDir() bool {
	return m.metadata.IsDir
}

// Mode 返回文件模式（从底层 FileInfo 获取）
func (m *MetadataFileInfo) Mode() os.FileMode {
	return m.FileInfo.Mode()
}

// Sys 返回底层数据源
func (m *MetadataFileInfo) Sys() interface{} {
	return m.FileInfo.Sys()
}

