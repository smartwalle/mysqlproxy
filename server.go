package mysqlproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Server TCP 代理服务，实现 bootstrap.Server 接口。
type Server struct {
	Config   *Config
	listener net.Listener
	wg       sync.WaitGroup
	mu       sync.Mutex
	closed   bool
}

// New 创建服务。
func New(cfg *Config) *Server {
	return &Server{Config: cfg}
}

// Start 启动服务并阻塞运行，直到 ctx 被取消或发生错误。
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Config.Proxy.Addr)
	if err != nil {
		return fmt.Errorf("mysql proxy server: listen on %s: %w", s.Config.Proxy.Addr, err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	slog.Info("mysql proxy server listening", "addr", s.Config.Proxy.Addr)

	// ctx 取消时关闭 listener，使 Accept 退出。
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		ln := s.listener
		s.mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// 临时错误则短暂等待后继续。
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() {
				time.Sleep(time.Millisecond * 5)
				continue
			}
			return fmt.Errorf("mysql proxy server: accept: %w", err)
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			sess := NewSession(conn, s.Config)
			sess.Run()
		}()
	}
}

// Stop 停止 Accept 并等待已存在的 Session 结束，在 ctx 超时前完成清理。
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	ln := s.listener
	s.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("mysql proxy server: stopped")
		return nil
	case <-ctx.Done():
		return fmt.Errorf("mysql proxy server: stop: %w", ctx.Err())
	}
}
