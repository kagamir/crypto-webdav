package config

import (
	"os"
	"strings"
)

// Settings 存储所有环境变量配置
type Settings struct {
	// WebDAV 监听地址，默认: "127.0.0.1:4043"
	WebDAVAddress string
	// htpasswd 文件路径，默认: "./htpasswd"
	HtpasswdFile string
	// 日志级别，可选值: "debug", "info", "warn", "error", "fatal", "panic", "trace"
	LogLevel string
	// 运行环境，设置为 "development" 时启用彩色日志输出
	Env string
	// 是否禁用 HTTPS，设置为 "true" 时禁用 HTTPS
	HTTPSDisabled bool
}

var settings *Settings

// init 初始化配置，从环境变量读取
func init() {
	settings = &Settings{
		WebDAVAddress: getEnvWithDefault("WEBDAV_ADDRESS", "127.0.0.1:4043"),
		HtpasswdFile:  getEnvWithDefault("WEBDAV_HTPASSWD_FILE", "./htpasswd"),
		LogLevel:      os.Getenv("LOG_LEVEL"),
		Env:           os.Getenv("ENV"),
		HTTPSDisabled: strings.ToLower(os.Getenv("HTTPS_DISABLED")) == "true",
	}
}

// getEnvWithDefault 获取环境变量，如果为空则返回默认值
func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// GetSettings 返回全局配置实例
func GetSettings() *Settings {
	return settings
}

// GetWebDAVAddress 获取 WebDAV 监听地址
func GetWebDAVAddress() string {
	return settings.WebDAVAddress
}

// GetHtpasswdFile 获取 htpasswd 文件路径
func GetHtpasswdFile() string {
	return settings.HtpasswdFile
}

// GetEnv 获取运行环境
func GetEnv() string {
	return settings.Env
}

// GetLogLevel 获取日志级别
func GetLogLevel() string {
	if GetEnv() == "development" {
		return "debug"
	}
	return settings.LogLevel
}

// IsHTTPSDisabled 检查是否禁用 HTTPS
func IsHTTPSDisabled() bool {
	return settings.HTTPSDisabled
}

// IsSSLEnabled 检查是否启用 SSL（与 IsHTTPSDisabled 相反）
func IsSSLEnabled() bool {
	return !settings.HTTPSDisabled
}
