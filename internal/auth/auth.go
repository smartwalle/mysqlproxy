package auth

import (
	"crypto/subtle"
	"errors"

	"mysqlproxy/internal/config"
)

// Authenticator 代理认证接口。
type Authenticator interface {
	Authenticate(username string, password string) error
}

// StaticAuthenticator 基于配置文件的静态账号认证。
type StaticAuthenticator struct {
	cfg config.AuthConfig
}

// NewStaticAuthenticator 创建基于配置的认证器。
func NewStaticAuthenticator(cfg config.AuthConfig) *StaticAuthenticator {
	return &StaticAuthenticator{cfg: cfg}
}

// Authenticate 校验用户名密码是否与配置一致。
// 使用常数时间比较避免时序侧信道攻击。
func (a *StaticAuthenticator) Authenticate(username, password string) error {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.cfg.Username))
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(a.cfg.Password))

	if userOK != 1 || passOK != 1 {
		return errors.New("auth: invalid username or password")
	}
	return nil
}
