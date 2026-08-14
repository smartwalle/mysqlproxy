package config

import (
	"fmt"

	"github.com/smartwalle/dotenv"
)

// Config 顶层配置，代理监听、代理认证、后端 MySQL 三部分分离。
type Config struct {
	Proxy ProxyConfig
	MySQL MySQLConfig
}

// ProxyConfig 代理自己的监听与访问账号。
type ProxyConfig struct {
	Addr     string
	Username string
	Password string
}

// MySQLConfig 后端真实 MySQL 连接信息。
type MySQLConfig struct {
	Addr     string
	Username string
	Password string
}

// Load 从 .env 文件读取配置，缺失必要项时返回错误。
func Load() (*Config, error) {
	env, err := dotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("load .env: %w", err)
	}

	cfg := &Config{
		Proxy: ProxyConfig{
			Addr:     env.Get("MYSQL_PROXY_ADDR"),
			Username: env.Get("MYSQL_PROXY_USERNAME"),
			Password: env.Get("MYSQL_PROXY_PASSWORD"),
		},
		MySQL: MySQLConfig{
			Addr:     env.Get("MYSQL_ADDR"),
			Username: env.Get("MYSQL_USERNAME"),
			Password: env.Get("MYSQL_PASSWORD"),
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
	if cfg.MySQL.Password == "" {
		return nil, fmt.Errorf("MYSQL_PASSWORD is required")
	}

	return cfg, nil
}
