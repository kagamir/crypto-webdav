//go:build !windows

package crypto

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// eraseFileTimestampsImpl 针对 Unix/Linux：
// - 优先使用 unix.UtimesNano 精确写入访问/修改时间
// - 若内核或文件系统不支持，再回退到 os.Chtimes
// - 注意：Unix 内核不允许用户态修改创建时间（birth time）
func eraseFileTimestampsImpl(filePath string, fixedTime time.Time) error {
	ts := unix.NsecToTimespec(fixedTime.UnixNano())
	times := []unix.Timespec{ts, ts}

	if err := unix.UtimesNano(filePath, times); err != nil {
		if err := os.Chtimes(filePath, fixedTime, fixedTime); err != nil {
			return fmt.Errorf("unix.UtimesNano fallback failed: %w", err)
		}
	}
	return nil
}
