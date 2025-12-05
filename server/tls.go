package server

import (
	"crypto-webdav/config"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// IsSSLEnabled 检查是否启用 SSL
func IsSSLEnabled() bool {
	return config.IsSSLEnabled()
}

// generateSelfSignedCert 生成自签证书
func generateSelfSignedCert(address string) (tls.Certificate, error) {
	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Crypto WebDAV"},
			Country:       []string{"Global"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 有效期1年
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 从地址中提取主机名
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = "localhost"
	}

	// 添加主机名和IP到证书
	if host != "" && host != "0.0.0.0" {
		template.DNSNames = []string{host, "localhost"}
	} else {
		template.DNSNames = []string{"localhost"}
	}
	template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

	// 创建证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 转换为 PEM 格式并创建 tls.Certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	return cert, nil
}

// ConfigureTLS 配置服务器的 TLS 设置
func ConfigureTLS(server *http.Server, address string) error {
	cert, err := generateSelfSignedCert(address)
	if err != nil {
		return err
	}

	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	return nil
}

// StartServer 启动 HTTP 或 HTTPS 服务器
func StartServer(server *http.Server, address string) error {
	if IsSSLEnabled() {
		if err := ConfigureTLS(server, address); err != nil {
			return err
		}

		log.Warn().
			Str("address", address).
			Msg("Starting WebDAV server with HTTPS (self-signed certificate)")
		return server.ListenAndServeTLS("", "")
	}

	log.Warn().
		Str("address", address).
		Msg("Starting WebDAV server")
	return server.ListenAndServe()
}
