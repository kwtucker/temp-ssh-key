package qr

import (
	"bytes"
	"strings"
	"testing"

	qrcode "github.com/skip2/go-qrcode"
)

func TestTerminal(t *testing.T) {
	const content = "ssh-ed25519 AAAA test"
	var buf bytes.Buffer
	if err := Terminal(&buf, content); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.ContainsAny(out, "█▀▄") {
		t.Fatal("terminal output contains no dark modules")
	}

	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	code, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		t.Fatal(err)
	}
	bitmap := code.Bitmap()
	wantRows := (len(bitmap) + 1) / 2
	if len(lines) != wantRows {
		t.Fatalf("terminal output has %d rows, want %d", len(lines), wantRows)
	}

	// Rebuild the module grid from the half-block characters and compare it
	// with the encoder's bitmap, so a swap of rows or columns cannot pass.
	got := make([][]bool, 0, len(bitmap))
	for _, line := range lines {
		top := make([]bool, 0, len(bitmap[0]))
		bottom := make([]bool, 0, len(bitmap[0]))
		for _, r := range line {
			var topDark, bottomDark bool
			switch r {
			case '█':
				topDark, bottomDark = true, true
			case '▀':
				topDark = true
			case '▄':
				bottomDark = true
			case ' ':
			default:
				t.Fatalf("unexpected character %q in terminal output", r)
			}
			top = append(top, topDark)
			bottom = append(bottom, bottomDark)
		}
		got = append(got, top)
		if len(got) < len(bitmap) {
			got = append(got, bottom)
		}
	}
	if len(got) != len(bitmap) {
		t.Fatalf("rebuilt %d rows, want %d", len(got), len(bitmap))
	}
	for y := range bitmap {
		for x := range bitmap[y] {
			if got[y][x] != bitmap[y][x] {
				t.Fatalf("module (%d,%d) = %v, want %v", x, y, got[y][x], bitmap[y][x])
			}
		}
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
