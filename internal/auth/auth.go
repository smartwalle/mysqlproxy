package auth

import (
	"crypto/subtle"
	"errors"

	"github.com/smartwalle/mysqlproxy/internal/config"
	"github.com/smartwalle/mysqlproxy/internal/protocol"
)

// Authenticator 代理认证接口。
//
// 由于客户端发送的是基于 scramble 计算的 token，无法还原出明文密码，
// 因此认证器接收客户端提供的用户名、认证响应（token）与本次握手生成的
// scramble，由实现内部计算期望 token 并比较。authPlugin 指示客户端使用的
// 认证插件，用于选择 token 计算算法。
type Authenticator interface {
	Authenticate(username string, authResponse, scramble []byte, authPlugin string) error
	// VerifyUsername 仅校验用户名是否合法。
	VerifyUsername(username string) error
	// VerifyPassword 校验明文密码（用于 caching_sha2 full auth 解密后）。
	VerifyPassword(username, password string) error
}

// StaticAuthenticator 基于配置文件的静态账号认证。
type StaticAuthenticator struct {
	cfg config.AuthConfig
}

// NewStaticAuthenticator 创建基于配置的认证器。
func NewStaticAuthenticator(cfg config.AuthConfig) *StaticAuthenticator {
	return &StaticAuthenticator{cfg: cfg}
}

// Authenticate 校验用户名与密码 token 是否与配置一致。
// 使用常数时间比较避免时序侧信道攻击。
func (a *StaticAuthenticator) Authenticate(username string, authResponse, scramble []byte, authPlugin string) error {
	if err := a.VerifyUsername(username); err != nil {
		return err
	}

	// 客户端发送的是对 scramble 计算的 token，反向无法还原明文密码，
	// 因此这里用代理配置的密码按相同算法计算 token 后比较。
	var expected []byte
	if authPlugin == protocol.AuthCachingSHA2Password {
		expected = protocol.ComputeCachingSHA2Token(a.cfg.Password, scramble)
	} else {
		expected = protocol.ComputePasswordToken(a.cfg.Password, scramble)
	}
	passOK := subtle.ConstantTimeCompare(authResponse, expected)

	if passOK != 1 {
		return errors.New("auth: invalid password")
	}
	return nil
}

// VerifyUsername 校验用户名是否与配置一致。
func (a *StaticAuthenticator) VerifyUsername(username string) error {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.cfg.Username))
	if userOK != 1 {
		return errors.New("auth: invalid username")
	}
	return nil
}

// VerifyPassword 校验明文密码是否与配置一致（full auth 场景）。
func (a *StaticAuthenticator) VerifyPassword(username, password string) error {
	if err := a.VerifyUsername(username); err != nil {
		return err
	}
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(a.cfg.Password))
	if passOK != 1 {
		return errors.New("auth: invalid password")
	}
	return nil
}
