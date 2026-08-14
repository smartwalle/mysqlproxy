package protocol

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// 独立实现（直接按 MySQL sha2_password 公式），用于交叉验证。
func referenceCachingSHA2Token(password string, scramble []byte) []byte {
	stage1 := sha256.Sum256([]byte(password))
	stage2 := sha256.Sum256(stage1[:])
	h := sha256.New()
	h.Write(stage2[:])
	h.Write(scramble)
	stage3 := h.Sum(nil)
	token := make([]byte, 32)
	for i := range token {
		token[i] = stage1[i] ^ stage3[i]
	}
	return token
}

func TestComputeCachingSHA2Token(t *testing.T) {
	password := "proxy_password"
	scramble := make([]byte, 20)
	for i := range scramble {
		scramble[i] = byte(i + 1)
	}

	token := ComputeCachingSHA2Token(password, scramble)

	if len(token) != 32 {
		t.Fatalf("token length = %d, want 32", len(token))
	}

	want := referenceCachingSHA2Token(password, scramble)
	if !bytes.Equal(token, want) {
		t.Fatalf("token mismatch:\n got  = %x\n want = %x", token, want)
	}
}

func TestCachingSHA2TokenDeterministic(t *testing.T) {
	scramble := []byte("abcdefghijklmnopqrst")
	a := ComputeCachingSHA2Token("pwd", scramble)
	b := ComputeCachingSHA2Token("pwd", scramble)
	if !bytes.Equal(a, b) {
		t.Fatalf("token not deterministic")
	}
}
