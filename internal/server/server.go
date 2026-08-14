package server

import (
	"fmt"
	"log"
	"net"

	"mysqlproxy/internal/config"
	"mysqlproxy/internal/session"
)

// Server TCP 代理服务。
type Server struct {
	Config *config.Config
}

// New 创建服务。
func New(cfg *config.Config) *Server {
	return &Server{Config: cfg}
}

// Listen 监听 TCP 并接收客户端连接，为每个连接创建会话。
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.Config.Listen.Addr)
	if err != nil {
		return fmt.Errorf("server: listen on %s: %w", s.Config.Listen.Addr, err)
	}
	log.Printf("mysql proxy listening on %s", s.Config.Listen.Addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("server: accept failed: %v", err)
			continue
		}

		go func() {
			sess := session.New(conn, s.Config)
			sess.Run()
		}()
	}
}
