package config

import (
	"fmt"

	"github.com/smartwalle/dotenv"
)

// Config 顶层配置，代理监听、代理认证、后端 MySQL 三部分分离。
type Config struct {
	Listen ListenConfig
	Auth   AuthConfig
	MySQL  MySQLConfig
}

// ListenConfig 代理监听配置。
type ListenConfig struct {
	Addr string
}

// AuthConfig 代理自己的访问账号。
type AuthConfig struct {
	Username string
	Password string
}

// MySQLConfig 后端真实 MySQL 连接信息。
type MySQLConfig struct {
	Host     string
	Port     string
	Username string
	Password string
}

// Load 从 .env 文件读取配置，缺失必要项时返回错误。
func Load() (*Config, error) {
	// 依次尝试多个候选 .env 路径，后面的覆盖前面的同名键。
	// 文件不存在时 dotenv 不会报错。
	env, err := dotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("config: load .env: %w", err)
	}

	cfg := &Config{
		Listen: ListenConfig{
			Addr: getString(env, "LISTEN_ADDR", "0.0.0.0:3307"),
		},
		Auth: AuthConfig{
			Username: env.Get("AUTH_USERNAME"),
			Password: env.Get("AUTH_PASSWORD"),
		},
		MySQL: MySQLConfig{
			Host:     getString(env, "MYSQL_HOST", "127.0.0.1"),
			Port:     getString(env, "MYSQL_PORT", "3306"),
			Username: env.Get("MYSQL_USERNAME"),
			Password: env.Get("MYSQL_PASSWORD"),
		},
	}

	if cfg.Auth.Username == "" {
		return nil, fmt.Errorf("config: AUTH_USERNAME is required")
	}
	if cfg.Auth.Password == "" {
		return nil, fmt.Errorf("config: AUTH_PASSWORD is required")
	}
	if cfg.MySQL.Username == "" {
		return nil, fmt.Errorf("config: MYSQL_USERNAME is required")
	}

	return cfg, nil
}

// getString 读取字符串，键不存在或为空时返回默认值。
func getString(env *dotenv.Env, key, def string) string {
	if v, ok := env.Lookup(key); ok && v != "" {
		return v
	}
	return def
}
