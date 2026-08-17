package protocol

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
)

// 客户端能力标志位（与 MySQL 协议一致）。
//
// 说明：这些标志用于两处——代理作为「服务端」发给客户端的握手包，以及
// 代理作为「客户端」连后端时发送的握手响应。为保持与真实 MySQL 行为一致，
// 应尽量完整声明后端支持的能力，避免客户端（尤其 Connector/J）因能力位
// 缺失而采用错误的解析方式（如 flags 读取长度、auth 数据长度编码等）。
const (
	clientLongPassword               = 0x00000001
	clientFoundRows                  = 0x00000002
	clientLongFlag                   = 0x00000004
	clientConnectWithDB              = 0x00000008
	clientProtocol41                 = 0x00000200
	ClientSSL                        = 0x00000800
	clientTransactions               = 0x00002000
	clientSecureConn                 = 0x00008000
	clientMultiStatements            = 0x00010000
	clientMultiResults               = 0x00020000
	clientPSMultiResults             = 0x00040000
	clientPluginAuth                 = 0x00080000
	clientConnectAttrs               = 0x00100000
	clientPluginAuthLenencClientData = 0x00200000
	clientDeprecateEOF               = 0x01000000
)

// serverCapabilities 代理对外（作为服务端）声明的能力集合。
//
// 参考真实 MySQL 后端的能力（0x003baa0f），排除代理暂不支持的特性：
//   - clientCompress：不支持压缩协议
//   - clientLocalFiles：不支持 LOAD DATA LOCAL INFILE
//
// 声明 clientSSL：代理支持 TLS，但是否真正启用由客户端握手响应决定
// （若客户端响应带 CLIENT_SSL 位则升级 TLS，否则走明文）。
const serverCapabilities = clientLongPassword |
	clientFoundRows |
	clientLongFlag |
	clientConnectWithDB |
	clientProtocol41 |
	ClientSSL |
	clientTransactions |
	clientSecureConn |
	clientMultiStatements |
	clientMultiResults |
	clientPSMultiResults |
	clientPluginAuth |
	clientConnectAttrs |
	clientPluginAuthLenencClientData

// clientCapabilities 代理作为客户端连后端时声明的能力集合。
//
// 与 serverCapabilities 基本一致；代理声明 clientSSL 表示支持 TLS，
// 是否真正启用由后端握手包决定（后端声明 CLIENT_SSL 时升级 TLS）。
const clientCapabilities = clientLongPassword |
	clientFoundRows |
	clientLongFlag |
	clientProtocol41 |
	ClientSSL |
	clientTransactions |
	clientSecureConn |
	clientMultiStatements |
	clientMultiResults |
	clientPSMultiResults |
	clientPluginAuth |
	clientConnectAttrs |
	clientPluginAuthLenencClientData

// maxPacketSizeValue 客户端声明的最大包大小（16MB - 1）。
const maxPacketSizeValue = 0xFFFFFF

// 握手相关常量。
const (
	// serverVersion 代理对外报告的 MySQL 版本。
	serverVersion = "8.0.33-proxy"
	// mysqlNativePassword 认证插件名。
	mysqlNativePassword = "mysql_native_password"
)

// BuildHandshakeV10 构造初始握手包（protocol 10），
// 返回握手包 payload 与用于密码认证的 20 字节 scramble。
//
// authPlugin 指定对外声明的默认认证插件（mysql_native_password 或
// caching_sha2_password）。
func BuildHandshakeV10(authPlugin string) ([]byte, []byte) {
	payload := make([]byte, 0, 128)

	payload = append(payload, 0x0a) // protocol version 10
	payload = append(payload, serverVersion...)
	payload = append(payload, 0x00)

	payload = binary.LittleEndian.AppendUint32(payload, 1) // connection id

	// auth-plugin-data-part-1（8 字节随机数）。
	authData := makeAuthData()
	payload = append(payload, authData[:8]...)
	payload = append(payload, 0x00) // filler

	capability := uint32(serverCapabilities)

	// capability flags (lower 2 bytes)，按小端写入低 16 位。
	payload = append(payload, byte(capability), byte(capability>>8))

	payload = append(payload, 0x21)       // character set: utf8mb4_general_ci
	payload = append(payload, 0x00, 0x00) // status flags (2 bytes)

	// capability flags (upper 2 bytes)，按小端写入高 16 位。
	payload = append(payload, byte(capability>>16), byte(capability>>24))

	payload = append(payload, 0x15) // auth-plugin-data length = 8 + 13 = 21

	// reserved (10 bytes)
	payload = append(payload, make([]byte, 10)...)

	// auth-plugin-data-part-2（12 字节有效数据 + 1 字节 0x00 结尾 = 13 字节）。
	payload = append(payload, authData[8:]...)

	payload = append(payload, authPlugin...)
	payload = append(payload, 0x00)

	// scramble = part1(8) + part2 有效 12 字节（去掉末尾 0x00）。
	scramble := make([]byte, 20)
	copy(scramble[:8], authData[:8])
	copy(scramble[8:], authData[8:20])

	return payload, scramble
}

// ServerHandshake 从服务端握手包解析出的关键信息。
type ServerHandshake struct {
	Scramble   []byte // 20 字节认证盐值
	AuthPlugin string // 认证插件名（如 mysql_native_password / caching_sha2_password）
	Capability uint32 // 服务端能力标志
}

// ParseServerHandshake 从服务端握手包 payload 中提取 scramble、认证插件与能力标志。
func ParseServerHandshake(payload []byte) (*ServerHandshake, error) {
	if len(payload) < 1 || payload[0] != 0x0a {
		return nil, errors.New("not a protocol 10 handshake")
	}

	pos := 1
	// 跳过版本号（null 终止）。
	for pos < len(payload) && payload[pos] != 0x00 {
		pos++
	}
	pos++ // 跳过 0x00

	pos += 4 // connection id

	if pos+8 > len(payload) {
		return nil, errors.New("handshake too short")
	}
	part1 := payload[pos : pos+8]
	pos += 8
	pos++ // filler

	// capability lower (2 bytes)
	capLower := binary.LittleEndian.Uint16(payload[pos : pos+2])
	pos += 2
	pos += 1 // charset
	pos += 2 // status

	// capability upper (2 bytes)
	capUpper := binary.LittleEndian.Uint16(payload[pos : pos+2])
	pos += 2
	capability := uint32(capLower) | uint32(capUpper)<<16

	pos += 1  // auth-plugin-data length
	pos += 10 // reserved

	if pos+12 > len(payload) {
		return nil, errors.New("handshake part2 too short")
	}
	part2 := payload[pos : pos+12]
	pos += 13 // part2 共 13 字节（12 有效 + 1 结尾 0x00）

	scramble := make([]byte, 20)
	copy(scramble[:8], part1)
	copy(scramble[8:], part2)

	// auth-plugin-name（null 终止），仅在声明 CLIENT_PLUGIN_AUTH 时存在。
	authPlugin := ""
	if capability&clientPluginAuth != 0 && pos < len(payload) {
		name, _, err := readNullTerminated(payload[pos:])
		if err == nil {
			authPlugin = name
		}
	}

	return &ServerHandshake{
		Scramble:   scramble,
		AuthPlugin: authPlugin,
		Capability: capability,
	}, nil
}

// BuildHandshakeResponse 构造客户端握手响应包（HandshakeResponse41）。
//
// authPlugin 指定认证插件名，决定 auth response 的计算方式：
//   - mysql_native_password：20 字节 SHA1 token
//   - caching_sha2_password：32 字节 SHA256 token
//
// database 为空时表示不设置 CLIENT_CONNECT_WITH_DB。
func BuildHandshakeResponse(username, password string, scramble []byte, database, authPlugin string) []byte {
	capability := uint32(clientCapabilities)
	if database != "" {
		capability |= clientConnectWithDB
	}

	var authResp []byte
	if authPlugin == AuthCachingSHA2Password {
		authResp = ComputeCachingSHA2Token(password, scramble)
	} else {
		authResp = ComputePasswordToken(password, scramble)
	}

	payload := make([]byte, 0, 128)
	payload = binary.LittleEndian.AppendUint32(payload, capability)         // capability (4)
	payload = binary.LittleEndian.AppendUint32(payload, maxPacketSizeValue) // max packet size (4)
	payload = append(payload, 0x21)                                         // charset: utf8mb4_general_ci
	payload = append(payload, make([]byte, 23)...)                          // reserved (23)
	payload = append(payload, username...)
	payload = append(payload, 0x00) // username null terminator
	// auth response 长度：因声明了 CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA，
	// 使用 length-encoded integer 编码。
	payload = appendLengthEncodedInt(payload, uint64(len(authResp)))
	payload = append(payload, authResp...)
	if database != "" {
		payload = append(payload, database...)
		payload = append(payload, 0x00)
	}
	payload = append(payload, authPlugin...)
	payload = append(payload, 0x00)

	return payload
}

// BuildSSLRequest 构造 32 字节的 SSL 请求包。
//
// 当客户端（或代理作为客户端）要求 SSL 时，先发送此包声明 CLIENT_SSL，
// 服务端收到后立即发起 TLS 握手；TLS 建立后再发送完整握手响应。此包
// 仅含 capability(4) + max packet size(4) + charset(1) + reserved(23)，
// 不含 username 与 auth response。
func BuildSSLRequest() []byte {
	capability := uint32(clientCapabilities) | ClientSSL
	payload := make([]byte, 0, 32)
	payload = binary.LittleEndian.AppendUint32(payload, capability)         // capability (4)
	payload = binary.LittleEndian.AppendUint32(payload, maxPacketSizeValue) // max packet size (4)
	payload = append(payload, 0x21)                                         // charset: utf8mb4_general_ci
	payload = append(payload, make([]byte, 23)...)                          // reserved (23)
	return payload
}

// ParseHandshakeResponse 解析客户端握手响应包，返回用户名、认证数据、数据库名、认证插件名与客户端能力标志。
//
// 返回顺序：username, authResponse, database, authPlugin, capability。
func ParseHandshakeResponse(payload []byte) (string, []byte, string, string, uint32, error) {
	if len(payload) < 32 {
		return "", nil, "", "", 0, errors.New("handshake response too short")
	}

	pos := 0

	// capability flags (4 bytes)
	capability := binary.LittleEndian.Uint32(payload[pos:])
	pos += 4

	// max packet size (4 bytes)
	pos += 4

	// character set (1 byte)
	pos += 1

	// reserved (23 bytes)
	pos += 23

	// username (null-terminated)
	username, n, err := readNullTerminated(payload[pos:])
	if err != nil {
		return "", nil, "", "", 0, err
	}
	pos += n

	var authResponse []byte
	var database string
	var authPlugin string

	// auth response 的长度编码方式：
	//   - CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA：length-encoded integer 前缀
	//   - CLIENT_SECURE_CONNECTION（且无 LENENC 标志）：1 字节长度前缀
	//   - 否则：null-terminated 字符串
	switch {
	case capability&clientPluginAuthLenencClientData != 0:
		var authLen uint64
		var ok bool
		authLen, pos, ok = readLengthEncodedInt(payload, pos)
		if !ok || pos+int(authLen) > len(payload) {
			return "", nil, "", "", 0, errors.New("invalid auth response length")
		}
		authResponse = payload[pos : pos+int(authLen)]
		pos += int(authLen)

	case capability&clientSecureConn != 0:
		// auth response 以 1 字节长度前缀。
		authLen := int(payload[pos])
		pos++
		if pos+authLen > len(payload) {
			return "", nil, "", "", 0, errors.New("invalid auth response length")
		}
		authResponse = payload[pos : pos+authLen]
		pos += authLen

	default:
		// 旧协议：auth response 为 null-terminated。
		var authStr string
		authStr, n, err = readNullTerminated(payload[pos:])
		if err != nil {
			return "", nil, "", "", 0, err
		}
		authResponse = []byte(authStr)
		pos += n
	}

	// database (null-terminated)，仅在设置了 CLIENT_CONNECT_WITH_DB 时存在。
	if capability&clientConnectWithDB != 0 && pos < len(payload) {
		database, n, err = readNullTerminated(payload[pos:])
		if err != nil {
			return "", nil, "", "", 0, err
		}
		pos += n
	}

	// auth-plugin-name (null-terminated)，设置了 CLIENT_PLUGIN_AUTH 时存在。
	if capability&clientPluginAuth != 0 && pos < len(payload) {
		authPlugin, _, err = readNullTerminated(payload[pos:])
		if err != nil {
			return "", nil, "", "", 0, err
		}
	}

	return username, authResponse, database, authPlugin, capability, nil
}

// ComputePasswordToken 计算 mysql_native_password 的认证 token：
// SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password))).
func ComputePasswordToken(password string, scramble []byte) []byte {
	if password == "" {
		return []byte{}
	}

	stage1 := sha1Sum([]byte(password))
	stage2 := sha1Sum(stage1)
	stage3 := sha1Sum(append(scramble, stage2...))

	token := make([]byte, len(stage1))
	for i := range stage1 {
		token[i] = stage1[i] ^ stage3[i]
	}
	return token
}

// makeAuthData 生成 21 字节随机认证数据：
// part-1 为前 8 字节，part-2 为后 12 字节 + 1 字节 0x00 结尾。
func makeAuthData() []byte {
	data := make([]byte, 21)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		// 理论上不会失败，失败则用简单递增填充。
		for i := range data {
			data[i] = byte(i)
		}
	}

	// MySQL 服务端生成的 scramble 仅包含可打印 ASCII 字符（0x21-0x7e，
	// 即 '!' 到 '~'）。若使用完全随机的字节，某些客户端（如 MySQL
	// Connector/J，被 DataGrip 使用）用 ASCII 编码解码 scramble 时会把
	// 非 ASCII 字节替换为 '?'，导致认证失败。
	for i := 0; i < 20; i++ {
		data[i] = byte('!') + data[i]%('~'-'!'+1)
	}
	// 确保 part-2 末尾以 0x00 结尾。
	data[20] = 0x00
	return data
}

func sha1Sum(b []byte) []byte {
	s := sha1.Sum(b)
	return s[:]
}

func readNullTerminated(b []byte) (string, int, error) {
	for i, c := range b {
		if c == 0x00 {
			return string(b[:i]), i + 1, nil
		}
	}
	return "", 0, errors.New("unterminated string")
}

// readLengthEncodedInt 读取 length-encoded integer，返回其值和下一个读取位置。
func readLengthEncodedInt(b []byte, pos int) (uint64, int, bool) {
	if pos >= len(b) {
		return 0, pos, false
	}
	switch b[pos] {
	case 0xfb:
		return 0, pos + 1, false // NULL
	case 0xfc:
		if pos+2 >= len(b) {
			return 0, pos, false
		}
		v := uint64(b[pos+1]) | uint64(b[pos+2])<<8
		return v, pos + 3, true
	case 0xfd:
		if pos+3 >= len(b) {
			return 0, pos, false
		}
		v := uint64(b[pos+1]) | uint64(b[pos+2])<<8 | uint64(b[pos+3])<<16
		return v, pos + 4, true
	case 0xfe:
		if pos+8 >= len(b) {
			return 0, pos, false
		}
		v := binary.LittleEndian.Uint64(b[pos+1 : pos+9])
		return v, pos + 9, true
	default:
		return uint64(b[pos]), pos + 1, true
	}
}
