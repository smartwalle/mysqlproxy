package backend

import (
	"context"
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
//
// 注意：这里仅负责建立 TCP 连接，超时由 ctx 控制（调用方通过
// context.WithTimeout/WithDeadline 设置）。后端的握手认证在 session 层
// 完成，认证阶段的超时由 session 对连接设置 deadline 控制。
func (c *Connector) Connect(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", c.addr, err)
	}

	return conn, nil
}
