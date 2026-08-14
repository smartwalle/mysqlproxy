package protocol

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
)

// 认证插件名。
const (
	AuthNativePassword      = "mysql_native_password"
	AuthCachingSHA2Password = "caching_sha2_password"
)

// caching_sha2_password 认证中的响应类型。
const (
	// CachingSHA2AuthMoreData 认证协议中的 AuthMoreData 头字节。
	CachingSHA2AuthMoreData = 0x01
	// CachingSHA2PerformFullAuth full auth 标记：AuthMoreData(0x01) 后跟 0x04。
	CachingSHA2PerformFullAuth = 0x04
	// CachingSHA2FastAuthSuccess fast auth 成功标记：AuthMoreData(0x01) 后跟 0x03。
	CachingSHA2FastAuthSuccess = 0x03
	// CachingSHA2RequestPublicKey 客户端请求服务端返回 RSA 公钥。
	CachingSHA2RequestPublicKey = 0x02
)

// ComputeCachingSHA2Token 计算 caching_sha2_password 的 fast auth token。
//
// 算法（与 MySQL 源码 sha2_password 一致）：
//
//	stage1 = SHA256(password)
//	stage2 = SHA256(stage1)
//	stage3 = SHA256(stage2 + scramble)
//	token  = XOR(stage1, stage3)
//
// 长度为 32 字节。
func ComputeCachingSHA2Token(password string, scramble []byte) []byte {
	pass := []byte(password)

	stage1 := sha256.Sum256(pass)
	stage2 := sha256.Sum256(stage1[:])

	// stage3 = SHA256(stage2 + scramble)
	h := sha256.New()
	h.Write(stage2[:])
	h.Write(scramble)
	stage3 := h.Sum(nil)

	token := make([]byte, 32)
	for i := 0; i < 32; i++ {
		token[i] = stage1[i] ^ stage3[i]
	}
	return token
}

// CachingSHA2EncryptPassword 对密码做 XOR 混淆后使用 RSA 公钥加密。
//
// 用于 full auth：明文 = XOR(password + 0x00, scramble)，再用公钥加密。
func CachingSHA2EncryptPassword(password string, scramble []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	// 明文 = XOR(password + 0x00, scramble 重复填充)
	pass := []byte(password)
	plain := make([]byte, len(pass)+1)
	for i := 0; i < len(pass); i++ {
		plain[i] = pass[i] ^ scramble[i%len(scramble)]
	}
	plain[len(pass)] = 0x00 ^ scramble[len(pass)%len(scramble)]

	return rsa.EncryptPKCS1v15(rand.Reader, pubKey, plain)
}

// ParsePublicKey 解析 PEM 格式的 RSA 公钥（后端返回的公钥）。
func ParsePublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("protocol: failed to decode PEM public key")
	}

	if block.Type == "PUBLIC KEY" {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("protocol: parse PKIX public key: %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("protocol: public key is not RSA")
		}
		return rsaPub, nil
	}

	// 部分实现返回 PKCS#1 格式（RSA PUBLIC KEY）。
	if block.Type == "RSA PUBLIC KEY" {
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}

	return nil, fmt.Errorf("protocol: unsupported public key type %q", block.Type)
}

// EncodePublicKey 将 RSA 公钥编码为 PEM 格式（服务端返回给客户端的公钥）。
func EncodePublicKey(pub *rsa.PublicKey) []byte {
	der := x509.MarshalPKCS1PublicKey(pub)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}

// CachingSHA2DecryptPassword 使用 RSA 私钥解密客户端发来的密码密文，
// 再做 XOR 去混淆还原明文密码。
func CachingSHA2DecryptPassword(ciphertext []byte, scramble []byte, privKey *rsa.PrivateKey) (string, error) {
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, ciphertext)
	if err != nil {
		return "", fmt.Errorf("protocol: rsa decrypt: %w", err)
	}

	// 去 XOR 混淆：明文 = XOR(password + 0x00, scramble)
	n := len(plain)
	if n == 0 {
		return "", errors.New("protocol: empty decrypted password")
	}
	// 最后一个字节为 0x00 终止符（去混淆后）。
	passLen := n - 1
	pass := make([]byte, passLen)
	for i := 0; i < passLen; i++ {
		pass[i] = plain[i] ^ scramble[i%len(scramble)]
	}
	return string(pass), nil
}

// serverRSAKey 代理作为服务端（校验客户端认证）使用的 RSA 密钥对。
// 生成一次并复用，避免每次连接都生成密钥（开销较大）。
var (
	serverRSAKeyOnce sync.Once
	serverRSAKey     *rsa.PrivateKey
	serverRSAKeyErr  error
)

// GetServerRSAKey 返回代理作为服务端使用的 RSA 私钥（懒加载，仅生成一次）。
func GetServerRSAKey() (*rsa.PrivateKey, error) {
	serverRSAKeyOnce.Do(func() {
		serverRSAKey, serverRSAKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	return serverRSAKey, serverRSAKeyErr
}
