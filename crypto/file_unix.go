//go:build !windows

package crypto

import (
	"os"
	"time"
)

// eraseFileTimestampsImpl Unix/Linux 实现：使用 os.Chtimes 修改访问时间和修改时间
// 注意：Unix 系统通常不存储创建时间，只存储修改时间和访问时间
func eraseFileTimestampsImpl(filePath string, fixedTime time.Time) error {
	return os.Chtimes(filePath, fixedTime, fixedTime)
}
