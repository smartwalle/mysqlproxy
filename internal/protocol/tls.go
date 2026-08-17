package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"
)

// serverTLSConfig 代理作为服务端（对客户端提供 TLS）使用的 TLS 配置。
// 使用内置自签证书，生成一次并复用，避免每次连接都生成证书（开销较大）。
//
// 说明：客户端（如 MariaDB JDBC）使用 trustServerCertificate=true 时不会
// 校验证书链，因此自签证书即可满足。若客户端需要校验证书，可将证书
// 导出并配置到客户端信任库。
var (
	serverTLSConfigOnce sync.Once
	serverTLSConfig     *tls.Config
	serverTLSConfigErr  error
)

// GetServerTLSConfig 返回代理作为服务端使用的 TLS 配置（懒加载，仅生成一次）。
func GetServerTLSConfig() (*tls.Config, error) {
	serverTLSConfigOnce.Do(func() {
		serverTLSConfig, serverTLSConfigErr = buildServerTLSConfig()
	})
	return serverTLSConfig, serverTLSConfigErr
}

// buildServerTLSConfig 生成自签 ECDSA 证书并构造 TLS 配置。
func buildServerTLSConfig() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "mysqlproxy",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(100 * 365 * 24 * time.Hour), // 100 年
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{der},
				PrivateKey:  priv,
			},
		},
		MinVersion: tls.VersionTLS12,
	}, nil
}
