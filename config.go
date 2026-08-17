package mysqlproxy

import (
	"fmt"
	"time"

	"github.com/smartwalle/dotenv"
)

// Config 顶层配置，代理监听、代理认证、后端 MySQL、连接超时四部分分离。
type Config struct {
	Proxy      ProxyConfig
	MySQL      MySQLConfig
	Connection ConnectionConfig
}

// ProxyConfig 代理自己的监听与访问账号。
type ProxyConfig struct {
	Addr     string
	Username string
	Password string
}

// MySQLConfig 后端真实 MySQL 连接信息。
type MySQLConfig struct {
	Addr          string
	Username      string
	Password      string
	TLSCA         string // 后端 TLS 的 CA 证书文件路径（有值时严格校验，优先级高于 TLSSkipVerify）
	TLSSkipVerify bool   // 后端启用 TLS 时，是否跳过证书验证（仅在 TLSCA 为空时生效）
}

// ConnectionConfig 连接相关超时配置。
type ConnectionConfig struct {
	ConnectTimeout time.Duration
	AuthTimeout    time.Duration
}

// LoadConfig 从 .env 文件读取配置，缺失必要项时返回错误。
func LoadConfig(env *dotenv.Env) (*Config, error) {
	if env == nil {
		var err error
		env, err = dotenv.Load()
		if err != nil {
			return nil, fmt.Errorf("load .env: %w", err)
		}
	}

	cfg := &Config{
		Proxy: ProxyConfig{
			Addr:     env.Get("MYSQL_PROXY_ADDR"),
			Username: env.Get("MYSQL_PROXY_USERNAME"),
			Password: env.Get("MYSQL_PROXY_PASSWORD"),
		},
		MySQL: MySQLConfig{
			Addr:          env.Get("MYSQL_ADDR"),
			Username:      env.Get("MYSQL_USERNAME"),
			Password:      env.Get("MYSQL_PASSWORD"),
			TLSCA:         env.Get("MYSQL_TLS_CA"),
			TLSSkipVerify: env.EnsureBool("MYSQL_TLS_SKIP_VERIFY", true),
		},
		Connection: ConnectionConfig{
			ConnectTimeout: env.EnsureDuration("MYSQL_CONNECT_TIMEOUT", 5*time.Second),
			AuthTimeout:    env.EnsureDuration("MYSQL_AUTH_TIMEOUT", 5*time.Second),
		},
	}

	if cfg.Proxy.Addr == "" {
		return nil, fmt.Errorf("MYSQL_PROXY_ADDR is required")
	}
	if cfg.Proxy.Username == "" {
		return nil, fmt.Errorf("MYSQL_PROXY_USERNAME is required")
	}
	if cfg.Proxy.Password == "" {
		return nil, fmt.Errorf("MYSQL_PROXY_PASSWORD is required")
	}
	if cfg.MySQL.Addr == "" {
		return nil, fmt.Errorf("MYSQL_ADDR is required")
	}
	if cfg.MySQL.Username == "" {
		return nil, fmt.Errorf("MYSQL_USERNAME is required")
	}

	// 校验超时配置的合法性。
	if cfg.Connection.ConnectTimeout < 0 {
		return nil, fmt.Errorf("MYSQL_CONNECT_TIMEOUT must be >= 0")
	}
	if cfg.Connection.AuthTimeout < 0 {
		return nil, fmt.Errorf("MYSQL_AUTH_TIMEOUT must be >= 0")
	}

	return cfg, nil
}
