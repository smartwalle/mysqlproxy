package mysqlproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/smartwalle/mysqlproxy/internal/auth"
	"github.com/smartwalle/mysqlproxy/internal/backend"
	"github.com/smartwalle/mysqlproxy/internal/protocol"
)

// Session 代表一次客户端连接。
type Session struct {
	Client   net.Conn
	Backend  net.Conn
	Username string
	Database string

	cfg       *Config
	auth      auth.Authenticator
	connector *backend.Connector
	scramble  []byte // 握手阶段生成的随机数，用于认证校验
}

// NewSession 创建会话。
func NewSession(client net.Conn, cfg *Config) *Session {
	return &Session{
		Client: client,
		cfg:    cfg,
		auth: auth.NewStaticAuthenticator(
			cfg.Proxy.Username,
			cfg.Proxy.Password,
		),
		connector: backend.NewConnector(
			cfg.MySQL.Addr,
			cfg.MySQL.Username,
			cfg.MySQL.Password,
		),
	}
}

// Run 驱动会话完整生命周期：握手 -> 认证 -> 后端连接 -> 双向转发。
func (s *Session) Run() {
	defer s.Close()

	remote := ""
	if s.Client != nil && s.Client.RemoteAddr() != nil {
		remote = s.Client.RemoteAddr().String()
	}
	slog.Info("mysql session: new connection", "remote", remote)
	defer slog.Info("mysql session: connection closed", "remote", remote)

	if err := s.handshake(); err != nil {
		slog.Error("mysql session: handshake failed", "remote", remote, "error", err)
		return
	}

	if err := s.authenticate(); err != nil {
		slog.Error("mysql session: auth failed", "remote", remote, "user", s.Username, "error", err)
		s.sendErr(0x0f28, "28000", "Access denied for proxy")
		return
	}

	if err := s.connectBackend(); err != nil {
		slog.Error("mysql session: backend connect failed", "remote", remote, "error", err)
		s.sendErr(0x07d1, "HY000", "Proxy cannot connect to backend")
		return
	}

	slog.Info("mysql session: authenticated", "remote", remote, "user", s.Username, "database", s.Database)

	// 认证成功，向客户端回 OK 包（sequence 2）。
	s.sendOK()

	s.relay()
}

// handshake 向客户端发送初始握手包，并保存随机数用于认证。
//
// 对外声明 mysql_native_password 以保持最大兼容性（所有 MySQL 客户端均支持）。
// 代理已同时支持 caching_sha2_password 认证：
//   - 方向 A（代理连后端）：根据后端握手包声明的插件自动选择算法；
//   - 方向 B（客户端连代理）：若客户端握手响应请求 caching_sha2，代理按
//     对应算法校验，并支持 full auth（RSA 公钥交换）。
func (s *Session) handshake() error {
	payload, scramble := protocol.BuildHandshakeV10(protocol.AuthNativePassword)
	if err := protocol.WritePacket(s.Client, 0, payload); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}
	s.scramble = scramble
	return nil
}

// authenticate 读取客户端握手响应，校验代理账号。
//
// 支持 SSL 协商：若客户端握手响应带 CLIENT_SSL 位，则在认证前先将连接
// 升级为 TLS，然后在 TLS 内重新读取真正的握手响应。
func (s *Session) authenticate() error {
	// 设置认证超时 deadline。
	if s.cfg.Connection.AuthTimeout > 0 {
		_ = s.Client.SetReadDeadline(time.Now().Add(s.cfg.Connection.AuthTimeout))
		defer func() { _ = s.Client.SetReadDeadline(time.Time{}) }()
	}

	pkt, err := protocol.ReadPacket(s.Client)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	// 客户端要求 SSL 时，第一个包是 32 字节的 SSL 请求包（仅含 capability
	// 等头字段，无 username/auth response）。此时需先升级 TLS，再在 TLS 内
	// 读取完整的握手响应。判断依据是 capability 的 CLIENT_SSL 位。
	if wantsSSL(pkt.Payload) {
		if err = s.upgradeClientTLS(); err != nil {
			return err
		}
		pkt, err = protocol.ReadPacket(s.Client)
		if err != nil {
			return fmt.Errorf("read handshake response over tls: %w", err)
		}
	}

	username, authResponse, database, authPlugin, _, err := protocol.ParseHandshakeResponse(pkt.Payload)
	if err != nil {
		return err
	}

	s.Username = username
	s.Database = database

	// 先校验用户名（无论插件）。
	if err = s.auth.VerifyUsername(username); err != nil {
		return err
	}

	// 尝试 fast auth：比较 token。
	authErr := s.auth.Authenticate(username, authResponse, s.scramble, authPlugin)
	if authErr == nil {
		return nil
	}

	// fast auth 失败。若客户端使用 caching_sha2，走 full auth（RSA 公钥交换）。
	if authPlugin == protocol.AuthCachingSHA2Password {
		return s.clientFullAuth(username)
	}

	return fmt.Errorf("auth failed: %w", authErr)
}

// wantsSSL 判断客户端握手响应是否要求 SSL 升级。
//
// 客户端要求 SSL 时，第一个包是 32 字节的 SSL 请求包：capability(4) +
// max packet size(4) + charset(1) + reserved(23)，其中 capability 带
// CLIENT_SSL 位，且不包含 username/auth response。因此只需读取前 4 字节
// capability 判断，不能用 ParseHandshakeResponse 完整解析（会因缺少
// username 而报错）。
func wantsSSL(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	capability := binary.LittleEndian.Uint32(payload[:4])
	return capability&protocol.ClientSSL != 0
}

// upgradeClientTLS 将客户端连接升级为 TLS（代理作为服务端）。
func (s *Session) upgradeClientTLS() error {
	tlsConfig, err := protocol.GetServerTLSConfig()
	if err != nil {
		return fmt.Errorf("get server tls config: %w", err)
	}
	tlsConn := tls.Server(s.Client, tlsConfig)
	if err = tlsConn.Handshake(); err != nil {
		return fmt.Errorf("client tls handshake: %w", err)
	}
	s.Client = tlsConn
	slog.Info("mysql session: client TLS established")
	return nil
}

// upgradeBackendTLS 将后端连接升级为 TLS（代理作为客户端）。
//
// 证书校验策略（按优先级）：
//  1. 配置了 MYSQL_TLS_CA：用该 CA 证书严格校验后端证书（忽略 SkipVerify）。
//  2. 未配置 CA 且 MYSQL_TLS_SKIP_VERIFY=true：跳过证书校验。
//  3. 未配置 CA 且 MYSQL_TLS_SKIP_VERIFY=false：用系统默认根证书严格校验。
func (s *Session) upgradeBackendTLS() error {
	serverName := s.cfg.MySQL.Addr
	if host, _, err := net.SplitHostPort(serverName); err == nil {
		serverName = host
	}

	tlsConfig := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}

	switch {
	case s.cfg.MySQL.TLSCA != "":
		pool, err := loadCertPool(s.cfg.MySQL.TLSCA)
		if err != nil {
			return err
		}
		tlsConfig.RootCAs = pool

	case s.cfg.MySQL.TLSSkipVerify:
		tlsConfig.InsecureSkipVerify = true // 由配置显式控制

	default:
		// 用系统默认根证书，RootCAs 与 InsecureSkipVerify 均保持零值。
	}

	tlsConn := tls.Client(s.Backend, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("backend tls handshake: %w", err)
	}
	s.Backend = tlsConn
	slog.Info("mysql session: backend TLS established")
	return nil
}

// loadCertPool 读取 PEM 格式的 CA 证书文件并构造证书池。
func loadCertPool(path string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tls ca cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("tls ca cert contains no valid certificate: %s", path)
	}
	return pool, nil
}

// clientFullAuth 执行 caching_sha2_password 的完整认证（服务端角色）：
// 回 0x01 0x04 要求完整认证，处理客户端请求公钥（0x02），返回 RSA 公钥，
// 解密客户端发来的加密密码并与配置密码比对。
func (s *Session) clientFullAuth(username string) error {
	// 1. 回 0x01 0x04，要求完整认证。
	if err := protocol.WritePacket(s.Client, 2, []byte{protocol.CachingSHA2AuthMoreData, protocol.CachingSHA2PerformFullAuth}); err != nil {
		return fmt.Errorf("write perform full auth: %w", err)
	}

	// 2. 读客户端请求（期望 0x02 请求公钥）。
	req, err := protocol.ReadPacket(s.Client)
	if err != nil {
		return fmt.Errorf("read client request: %w", err)
	}
	if len(req.Payload) == 0 || req.Payload[0] != protocol.CachingSHA2RequestPublicKey {
		return fmt.Errorf("unexpected client request: 0x%x", req.Payload)
	}

	// 3. 返回 RSA 公钥（AuthMoreData 0x01 + PEM 公钥）。
	privKey, err := protocol.GetServerRSAKey()
	if err != nil {
		return fmt.Errorf("get server rsa key: %w", err)
	}
	pubPEM := protocol.EncodePublicKey(&privKey.PublicKey)
	keyPacket := append([]byte{protocol.CachingSHA2AuthMoreData}, pubPEM...)
	if err = protocol.WritePacket(s.Client, 4, keyPacket); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	// 4. 读客户端发来的加密密码。
	enc, err := protocol.ReadPacket(s.Client)
	if err != nil {
		return fmt.Errorf("read encrypted password: %w", err)
	}

	// 5. 解密得到明文密码并校验。
	plainPassword, err := protocol.CachingSHA2DecryptPassword(enc.Payload, s.scramble, privKey)
	if err != nil {
		return fmt.Errorf("decrypt password: %w", err)
	}

	return s.auth.VerifyPassword(username, plainPassword)
}

// connectBackend 代理作为客户端，用真实 MySQL 账号与后端完成完整握手。
//
// 支持 mysql_native_password 与 caching_sha2_password 两种认证插件，
// 根据后端握手包声明的 auth-plugin-name 自动选择算法；caching_sha2 缓存
// 未命中时执行 full auth（请求公钥 + RSA 加密密码）。
func (s *Session) connectBackend() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Connection.ConnectTimeout)
	defer cancel()

	conn, err := s.connector.Connect(ctx)
	if err != nil {
		return err
	}
	s.Backend = conn

	// 后端握手认证阶段使用 AUTH_TIMEOUT 独立起算，覆盖 full auth 的多轮交互，
	// 避免无限等待。认证超时与连接超时相互独立。
	if s.cfg.Connection.AuthTimeout > 0 {
		_ = s.Backend.SetDeadline(time.Now().Add(s.cfg.Connection.AuthTimeout))
		defer func() { _ = s.Backend.SetDeadline(time.Time{}) }()
	}

	// 1. 读后端握手包。
	pkt, err := protocol.ReadPacket(s.Backend)
	if err != nil {
		return fmt.Errorf("read backend handshake: %w", err)
	}

	// 2. 从后端握手包解析 scramble 与认证插件。
	hs, err := protocol.ParseServerHandshake(pkt.Payload)
	if err != nil {
		return fmt.Errorf("parse backend handshake: %w", err)
	}

	authPlugin := hs.AuthPlugin
	if authPlugin == "" {
		authPlugin = protocol.AuthNativePassword
	}

	// 后端声明支持 SSL：先发 32 字节 SSL 请求包，再升级 TLS。
	// 是否真正启用由后端握手包决定（此处据此判断，与客户端侧一致）。
	if hs.Capability&protocol.ClientSSL != 0 {
		if err = protocol.WritePacket(s.Backend, 1, protocol.BuildSSLRequest()); err != nil {
			return fmt.Errorf("write ssl request: %w", err)
		}
		if err = s.upgradeBackendTLS(); err != nil {
			return err
		}
	}

	// 3. 构造认证响应包，用真实 MySQL 账号密码，并透传客户端指定的数据库。
	authResp := protocol.BuildHandshakeResponse(
		s.cfg.MySQL.Username,
		s.cfg.MySQL.Password,
		hs.Scramble,
		s.Database,
		authPlugin,
	)

	// 4. 发送认证响应（sequence 1）。
	if err = protocol.WritePacket(s.Backend, 1, authResp); err != nil {
		return fmt.Errorf("write backend auth response: %w", err)
	}

	// 5. 读后端认证结果。
	result, err := protocol.ReadPacket(s.Backend)
	if err != nil {
		return fmt.Errorf("read backend auth result: %w", err)
	}
	if len(result.Payload) == 0 || result.Payload[0] == 0xff {
		return fmt.Errorf("backend auth failed: %s", string(result.Payload))
	}

	// 6. caching_sha2 缓存未命中时，后端返回 0x01 0x04 要求 full auth。
	if len(result.Payload) >= 2 &&
		result.Payload[0] == protocol.CachingSHA2AuthMoreData &&
		result.Payload[1] == protocol.CachingSHA2PerformFullAuth {
		if err = s.backendFullAuth(hs.Scramble); err != nil {
			return err
		}
	} else if result.Payload[0] != 0x00 {
		return fmt.Errorf("backend unexpected auth result: 0x%02x", result.Payload[0])
	}

	return nil
}

// backendFullAuth 执行 caching_sha2_password 的完整认证：
// 发送 0x02 请求公钥，读取后端返回的 RSA 公钥，用公钥加密密码后发送。
func (s *Session) backendFullAuth(scramble []byte) error {
	// 请求公钥。
	if err := protocol.WritePacket(s.Backend, 3, []byte{protocol.CachingSHA2RequestPublicKey}); err != nil {
		return fmt.Errorf("request backend public key: %w", err)
	}

	// 读后端返回的公钥（AuthMoreData 0x01 + PEM 公钥）。
	pkt, err := protocol.ReadPacket(s.Backend)
	if err != nil {
		return fmt.Errorf("read backend public key: %w", err)
	}
	pubPEM := pkt.Payload
	if len(pubPEM) > 0 && pubPEM[0] == protocol.CachingSHA2AuthMoreData {
		pubPEM = pubPEM[1:]
	}

	pubKey, err := protocol.ParsePublicKey(pubPEM)
	if err != nil {
		return fmt.Errorf("parse backend public key: %w", err)
	}

	// 用公钥加密密码。
	encrypted, err := protocol.CachingSHA2EncryptPassword(s.cfg.MySQL.Password, scramble, pubKey)
	if err != nil {
		return fmt.Errorf("encrypt password: %w", err)
	}

	// 发送加密后的密码。
	if err = protocol.WritePacket(s.Backend, 4, encrypted); err != nil {
		return fmt.Errorf("write encrypted password: %w", err)
	}

	// 读最终认证结果，必须为 OK 包。
	result, err := protocol.ReadPacket(s.Backend)
	if err != nil {
		return fmt.Errorf("read backend auth result after full auth: %w", err)
	}
	if len(result.Payload) == 0 || result.Payload[0] == 0xff {
		return fmt.Errorf("backend auth failed: %s", string(result.Payload))
	}
	if result.Payload[0] != 0x00 {
		return fmt.Errorf("backend unexpected auth result after full auth: 0x%02x", result.Payload[0])
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
