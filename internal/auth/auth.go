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
// scramble，由实现内部计算期望 token 并比较。
type Authenticator interface {
	Authenticate(username string, authResponse, scramble []byte) error
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
func (a *StaticAuthenticator) Authenticate(username string, authResponse, scramble []byte) error {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.cfg.Username))

	// 客户端发送的是对 scramble 计算的 token，反向无法还原明文密码，
	// 因此这里用代理配置的密码同样计算 token 后比较。
	expected := protocol.ComputePasswordToken(a.cfg.Password, scramble)
	passOK := subtle.ConstantTimeCompare(authResponse, expected)

	if userOK != 1 || passOK != 1 {
		return errors.New("auth: invalid username or password")
	}
	return nil
}
