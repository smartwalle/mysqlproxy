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
	conn, err := net.Dial("tcp", c.Config.Addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", c.Config.Addr, err)
	}
	return conn, nil
}
