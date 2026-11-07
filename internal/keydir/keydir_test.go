package keydir

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestNewAndValidate(t *testing.T) {
	dir, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode = %o, want 700", got)
	}
	validated, err := Validate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if validated != dir {
		t.Fatalf("Validate() = %q, want %q", validated, dir)
	}
}

func TestValidateRejects(t *testing.T) {
	base := t.TempDir()
	good, err := New(base)
	if err != nil {
		t.Fatal(err)
	}

	loose := filepath.Join(base, DirPrefix+"loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}

	wrongName := filepath.Join(base, "not-a-key-dir")
	if err := os.Mkdir(wrongName, 0o700); err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(base, DirPrefix+"file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(base, DirPrefix+"link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		dir  string
	}{
		{name: "empty", dir: ""},
		{name: "relative", dir: "relative/path"},
		{name: "missing", dir: filepath.Join(base, DirPrefix+"missing")},
		{name: "wrong mode", dir: loose},
		{name: "wrong name", dir: wrongName},
		{name: "not a directory", dir: file},
		{name: "symlink", dir: link},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Validate(tt.dir); err == nil {
				t.Fatalf("Validate(%q) succeeded, want error", tt.dir)
			}
		})
	}
}

func TestCheckPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, PrivateKeyName)
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(path); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(path); err == nil {
		t.Fatal("CheckPrivate accepted mode 644")
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(path); err == nil {
		t.Fatal("CheckPrivate accepted an empty file")
	}
}

func TestReadPublic(t *testing.T) {
	line, wantFingerprint := testPublicKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, PublicKeyName)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pub, err := ReadPublic(path)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Line != line {
		t.Errorf("Line = %q, want %q", pub.Line, line)
	}
	if pub.Fingerprint != wantFingerprint {
		t.Errorf("Fingerprint = %q, want %q", pub.Fingerprint, wantFingerprint)
	}
}

func TestReadPublicRejects(t *testing.T) {
	line, _ := testPublicKey(t)
	dir := t.TempDir()

	tests := []struct {
		name    string
		content string
	}{
		{name: "empty", content: ""},
		{name: "rsa type", content: "ssh-rsa AAAA test"},
		{name: "not base64", content: "ssh-ed25519 !!!! test"},
		{name: "two lines", content: line + "\n" + line + "\n"},
		{name: "truncated", content: "ssh-ed25519 AAAA test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name)
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadPublic(path); err == nil {
				t.Fatalf("ReadPublic(%q) succeeded, want error", tt.name)
			}
		})
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "empty"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublic(link); err == nil {
		t.Fatal("ReadPublic accepted a symlink")
	}
}

func TestUnexpected(t *testing.T) {
	dir, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{PrivateKeyName, PublicKeyName, PNGName} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Unexpected(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("Unexpected() = %v, want none", got)
	}

	for _, name := range []string{"extra", ".hidden"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err = Unexpected(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".hidden", "extra"}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Unexpected() = %v, want %v", got, want)
	}
}

func testPublicKey(t *testing.T) (line, fingerprint string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	if err := binary.Write(&blob, binary.BigEndian, uint32(len("ssh-ed25519"))); err != nil {
		t.Fatal(err)
	}
	blob.WriteString("ssh-ed25519")
	if err := binary.Write(&blob, binary.BigEndian, uint32(len(pub))); err != nil {
		t.Fatal(err)
	}
	blob.Write(pub)

	sum := sha256.Sum256(blob.Bytes())
	fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	line = "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes()) + " test"
	return line, fingerprint
}
