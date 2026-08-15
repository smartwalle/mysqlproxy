package backend

import (
	"fmt"
	"net"
)

// Connector 负责建立到后端 MySQL 的连接。
type Connector struct {
	addr     string
	username string
	password string
}

// NewConnector 创建后端连接器。
func NewConnector(addr, username, password string) *Connector {
	return &Connector{
		addr:     addr,
		username: username,
		password: password,
	}
}

// Connect 建立到后端 MySQL 的 TCP 连接。
func (c *Connector) Connect() (net.Conn, error) {
	conn, err := net.Dial("tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", c.addr, err)
	}
	return conn, nil
}
