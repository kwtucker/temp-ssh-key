package qr

import (
	"bytes"
	"strings"
	"testing"
)

func TestTerminal(t *testing.T) {
	var buf bytes.Buffer
	if err := Terminal(&buf, "ssh-ed25519 AAAA test"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "██") {
		t.Fatal("terminal output contains no dark modules")
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) < 21 {
		t.Fatalf("terminal output has %d lines, want at least 21", len(lines))
	}
}

func TestPNG(t *testing.T) {
	var buf bytes.Buffer
	if err := PNG(&buf, "ssh-ed25519 AAAA test", 256); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	magic := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	if len(data) < len(magic) || !bytes.Equal(data[:len(magic)], magic) {
		t.Fatalf("output does not start with PNG magic: %x", data[:min(len(data), len(magic))])
	}
}
