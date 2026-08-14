package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

// 包头的固定长度：3 字节 payload 长度 + 1 字节 sequence id。
const headerSize = 4

// maxPacketSize MySQL 协议中单个 packet 的 payload 上限（16MB - 1）。
const maxPacketSize = 0xFFFFFF

// Packet MySQL 协议通信单元。
type Packet struct {
	Sequence uint8
	Payload  []byte
}

// ReadPacket 从连接读取一个完整 packet。
func ReadPacket(r io.Reader) (*Packet, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	seq := header[3]

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return &Packet{Sequence: seq, Payload: payload}, nil
}

// WritePacket 将 packet 写入连接，支持 payload 超过 16MB 时的分包。
func WritePacket(w io.Writer, seq uint8, payload []byte) error {
	// 空 payload 也要发送一个空的 packet（例如某些协议阶段）。
	if len(payload) == 0 {
		return writeChunk(w, seq, nil)
	}

	for len(payload) > 0 {
		chunkLen := len(payload)
		if chunkLen > maxPacketSize {
			chunkLen = maxPacketSize
		}
		if err := writeChunk(w, seq, payload[:chunkLen]); err != nil {
			return err
		}
		payload = payload[chunkLen:]
		seq++
	}
	return nil
}

func writeChunk(w io.Writer, seq uint8, chunk []byte) error {
	if len(chunk) > maxPacketSize {
		return fmt.Errorf("chunk too large: %d", len(chunk))
	}

	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header, uint32(len(chunk)))
	// 前 3 字节为长度，第 4 字节为 sequence id。
	header[3] = seq

	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(chunk) > 0 {
		if _, err := w.Write(chunk); err != nil {
			return err
		}
	}
	return nil
}
