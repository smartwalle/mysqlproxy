package session

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/smartwalle/mysqlproxy/internal/auth"
	"github.com/smartwalle/mysqlproxy/internal/backend"
	"github.com/smartwalle/mysqlproxy/internal/config"
	"github.com/smartwalle/mysqlproxy/internal/protocol"
)

// Session 代表一次客户端连接。
type Session struct {
	Client   net.Conn
	Backend  net.Conn
	Username string
	Database string

	cfg       *config.Config
	auth      auth.Authenticator
	connector *backend.Connector
	scramble  []byte // 握手阶段生成的随机数，用于认证校验
}

// New 创建会话。
func New(client net.Conn, cfg *config.Config) *Session {
	return &Session{
		Client:    client,
		cfg:       cfg,
		auth:      auth.NewStaticAuthenticator(cfg.Auth),
		connector: backend.NewConnector(cfg.MySQL),
	}
}

// Run 驱动会话完整生命周期：握手 -> 认证 -> 后端连接 -> 双向转发。
func (s *Session) Run() {
	defer s.Close()

	if err := s.handshake(); err != nil {
		log.Printf("session: handshake failed: %v", err)
		return
	}

	if err := s.authenticate(); err != nil {
		log.Printf("session: auth failed for %q: %v", s.Username, err)
		s.sendErr(0x0f28, "28000", "Access denied for proxy")
		return
	}

	if err := s.connectBackend(); err != nil {
		log.Printf("session: backend connect failed: %v", err)
		s.sendErr(0x07d1, "HY000", "Proxy cannot connect to backend")
		return
	}

	// 认证成功，向客户端回 OK 包（sequence 2）。
	s.sendOK()

	s.relay()
}

// handshake 向客户端发送初始握手包，并保存随机数用于认证。
func (s *Session) handshake() error {
	payload, scramble := protocol.BuildHandshakeV10()
	if err := protocol.WritePacket(s.Client, 0, payload); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}
	s.scramble = scramble
	return nil
}

// authenticate 读取客户端握手响应，校验代理账号。
func (s *Session) authenticate() error {
	pkt, err := protocol.ReadPacket(s.Client)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	username, authResponse, database, err := protocol.ParseHandshakeResponse(pkt.Payload)
	if err != nil {
		return err
	}
	s.Username = username
	s.Database = database

	if err = s.auth.Authenticate(username, authResponse, s.scramble); err != nil {
		return err
	}

	return nil
}

// connectBackend 代理作为客户端，用真实 MySQL 账号与后端完成完整握手。
func (s *Session) connectBackend() error {
	conn, err := s.connector.Connect()
	if err != nil {
		return err
	}
	s.Backend = conn

	// 1. 读后端握手包。
	pkt, err := protocol.ReadPacket(s.Backend)
	if err != nil {
		return fmt.Errorf("read backend handshake: %w", err)
	}

	// 2. 从后端握手包解析 scramble。
	scramble, err := protocol.ParseServerHandshake(pkt.Payload)
	if err != nil {
		return fmt.Errorf("parse backend handshake: %w", err)
	}

	// 3. 构造认证响应包，用真实 MySQL 账号密码。
	authResp := protocol.BuildHandshakeResponse(
		s.cfg.MySQL.Username,
		s.cfg.MySQL.Password,
		scramble,
		"",
	)

	// 4. 发送认证响应（sequence 1）。
	if err := protocol.WritePacket(s.Backend, 1, authResp); err != nil {
		return fmt.Errorf("write backend auth response: %w", err)
	}

	// 5. 读后端认证结果（sequence 2），必须为 OK 包。
	result, err := protocol.ReadPacket(s.Backend)
	if err != nil {
		return fmt.Errorf("read backend auth result: %w", err)
	}
	if len(result.Payload) == 0 || result.Payload[0] == 0xff {
		return fmt.Errorf("backend auth failed: %s", string(result.Payload))
	}
	if result.Payload[0] != 0x00 {
		return fmt.Errorf("backend unexpected auth result: 0x%02x", result.Payload[0])
	}

	return nil
}

// relay 双向转发数据。
//
// 客户端与后端的 sequence id 在握手阶段均从 0 开始递增，命令阶段各自重新从
// 0 计数，因此两侧 sequence 天然对齐，直接透传即可，无需重映射。
func (s *Session) relay() {
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 后端。
	go func() {
		defer wg.Done()
		for {
			pkt, err := protocol.ReadPacket(s.Client)
			if err != nil {
				break
			}
			if err = protocol.WritePacket(s.Backend, pkt.Sequence, pkt.Payload); err != nil {
				break
			}
		}
		s.closeWrite(s.Backend)
	}()

	// 后端 -> 客户端。
	go func() {
		defer wg.Done()
		for {
			pkt, err := protocol.ReadPacket(s.Backend)
			if err != nil {
				break
			}
			if err = protocol.WritePacket(s.Client, pkt.Sequence, pkt.Payload); err != nil {
				break
			}
		}
		s.closeWrite(s.Client)
	}()

	wg.Wait()
}

// closeWrite 半关闭连接的写入端，通知对端不再有数据。
func (s *Session) closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

// sendOK 向客户端发送认证成功的 OK 包。
func (s *Session) sendOK() {
	payload := protocol.BuildOKPacket(0, 0, 0x0002, 0)
	_ = protocol.WritePacket(s.Client, 2, payload)
}

// sendErr 向客户端发送错误响应包。
func (s *Session) sendErr(code uint16, state, msg string) {
	payload := protocol.BuildErrPacket(code, state, msg)
	_ = protocol.WritePacket(s.Client, 2, payload)
}

// Close 关闭客户端与后端连接。
func (s *Session) Close() {
	if s.Client != nil {
		_ = s.Client.Close()
	}
	if s.Backend != nil {
		_ = s.Backend.Close()
	}
}
