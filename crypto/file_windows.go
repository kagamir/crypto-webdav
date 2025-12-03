//go:build windows

package crypto

import (
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// eraseFileTimestampsImpl Windows 实现：使用 SetFileTime API 修改创建时间、访问时间和修改时间
func eraseFileTimestampsImpl(filePath string, fixedTime time.Time) error {
	// 将文件路径转换为 UTF-16
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return err
	}

	// 打开文件句柄
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	// 将 time.Time 转换为 Windows FILETIME 结构
	// FILETIME 是从 1601-01-01 00:00:00 UTC 开始的 100 纳秒间隔数
	windowsEpoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)

	// 计算从 Windows 纪元到目标时间的差值（纳秒）
	diff := fixedTime.Sub(windowsEpoch)
	// 转换为 100 纳秒单位
	fileTimeNs := diff.Nanoseconds() / 100

	// FILETIME 是 64 位整数，需要分割为 LowDateTime (低32位) 和 HighDateTime (高32位)
	var fileTime windows.Filetime
	fileTime.LowDateTime = uint32(fileTimeNs & 0xFFFFFFFF)
	fileTime.HighDateTime = uint32(fileTimeNs >> 32)

	// 使用 SetFileTime 设置创建时间、访问时间和修改时间
	// 参数：句柄, 创建时间, 访问时间, 修改时间
	return windows.SetFileTime(handle, &fileTime, &fileTime, &fileTime)
}
