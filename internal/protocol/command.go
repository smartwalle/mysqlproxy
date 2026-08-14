package protocol

import "encoding/binary"

// 客户端命令类型。
const (
	ComQuit     = 0x01
	ComInitDB   = 0x02
	ComQuery    = 0x03
	ComPing     = 0x0e
	ComStmtPrep = 0x16
	ComStmtExe  = 0x17
	ComReset    = 0x1f
)

// BuildOKPacket 构造 OK 响应包。
func BuildOKPacket(affectedRows, lastInsertID uint64, statusFlags uint16, warnings uint16) []byte {
	payload := []byte{0x00} // header: OK

	payload = appendLengthEncodedInt(payload, affectedRows)
	payload = appendLengthEncodedInt(payload, lastInsertID)

	payload = binary.LittleEndian.AppendUint16(payload, statusFlags)
	payload = binary.LittleEndian.AppendUint16(payload, warnings)

	return payload
}

// BuildErrPacket 构造 ERR 响应包。
func BuildErrPacket(errCode uint16, sqlState string, message string) []byte {
	payload := []byte{0xff} // header: ERR

	payload = binary.LittleEndian.AppendUint16(payload, errCode)

	// SQL state marker '#' + 5 字节 state。
	payload = append(payload, '#')
	payload = append(payload, sqlState...)

	payload = append(payload, message...)

	return payload
}

func appendLengthEncodedInt(b []byte, v uint64) []byte {
	switch {
	case v < 251:
		return append(b, byte(v))
	case v < 1<<16:
		b = append(b, 0xfc)
		return binary.LittleEndian.AppendUint16(b, uint16(v))
	case v < 1<<24:
		b = append(b, 0xfd)
		return append(b, byte(v), byte(v>>8), byte(v>>16))
	default:
		b = append(b, 0xfe)
		return binary.LittleEndian.AppendUint64(b, v)
	}
}
