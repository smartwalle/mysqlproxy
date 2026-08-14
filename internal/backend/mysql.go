package backend

import (
	"fmt"
	"net"

	"github.com/smartwalle/mysqlproxy/internal/config"
)

// Connector 负责建立到后端 MySQL 的连接。
type Connector struct {
	Config config.MySQLConfig
}

// NewConnector 创建后端连接器。
func NewConnector(cfg config.MySQLConfig) *Connector {
	return &Connector{Config: cfg}
}

// Connect 建立到后端 MySQL 的 TCP 连接。
func (c *Connector) Connect() (net.Conn, error) {
	addr := net.JoinHostPort(c.Config.Host, c.Config.Port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("backend: connect to %s: %w", addr, err)
	}
	return conn, nil
}
