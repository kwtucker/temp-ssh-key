package keydir

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
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

func TestNewClearsInheritedSetgid(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700|os.ModeSetgid); err != nil {
		t.Skipf("cannot set setgid on the base directory: %v", err)
	}
	info, err := os.Stat(base)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Skip("filesystem does not preserve the setgid bit")
	}

	dir, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid != 0 {
		t.Fatalf("new directory mode = %v, want no setgid bit", info.Mode())
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("new directory permissions = %o, want 700", got)
	}
	if _, err := Validate(dir); err != nil {
		t.Fatalf("Validate rejected the new directory: %v", err)
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

func TestReadPublicRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), PublicKeyName)
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), maxPublicKeyBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublic(path); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("ReadPublic() error = %v, want an oversized-file error", err)
	}
}

func TestPublicFromPrivate(t *testing.T) {
	line, wantFingerprint := testPublicKey(t)
	path := filepath.Join(t.TempDir(), PrivateKeyName)
	if err := os.WriteFile(path, privateKeyContainer(t, line), 0o600); err != nil {
		t.Fatal(err)
	}

	pub, err := PublicFromPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Fingerprint != wantFingerprint {
		t.Errorf("Fingerprint = %q, want %q", pub.Fingerprint, wantFingerprint)
	}
	if !strings.HasPrefix(pub.Line, "ssh-ed25519 ") {
		t.Errorf("Line = %q, want an ssh-ed25519 public key", pub.Line)
	}
}

func TestPublicFromPrivateRejects(t *testing.T) {
	line, _ := testPublicKey(t)
	container := privateKeyContainer(t, line)
	block, _ := pem.Decode(container)
	if block == nil {
		t.Fatal("test helper did not produce a PEM block")
	}
	tests := []struct {
		name    string
		content []byte
	}{
		{name: "not PEM", content: []byte("private\n")},
		{name: "wrong PEM type", content: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})},
		{name: "not OpenSSH", content: pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("private\n")})},
		{name: "truncated header", content: pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: block.Bytes[:20]})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), PrivateKeyName)
			if err := os.WriteFile(path, tt.content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := PublicFromPrivate(path); err == nil {
				t.Fatalf("PublicFromPrivate(%q) succeeded, want error", tt.name)
			}
		})
	}
}

func TestPublicFromPrivateRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), PrivateKeyName)
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), maxPrivateKeyBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PublicFromPrivate(path); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("PublicFromPrivate() error = %v, want an oversized-file error", err)
	}
}

func TestVerify(t *testing.T) {
	line, fingerprint := testPublicKey(t)
	dir, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, PrivateKeyName), privateKeyContainer(t, line), 0o600); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(dir, PublicKeyName)
	if err := os.WriteFile(publicPath, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	gotDir, pub, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if gotDir != dir {
		t.Errorf("Verify() dir = %q, want %q", gotDir, dir)
	}
	if pub.Fingerprint != fingerprint {
		t.Errorf("Fingerprint = %q, want %q", pub.Fingerprint, fingerprint)
	}

	otherLine, _ := testPublicKey(t)
	if err := os.WriteFile(publicPath, []byte(otherLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(dir); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Verify() error = %v, want a mismatch error", err)
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

// privateKeyContainer builds an OpenSSH private key file containing the public
// header. The parser only needs that header, so the private section is a
// placeholder.
func privateKeyContainer(t *testing.T, line string) []byte {
	t.Helper()
	fields := strings.Fields(line)
	if len(fields) < 2 {
		t.Fatalf("test key has no key data: %q", line)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	b.WriteString("openssh-key-v1\x00")
	for _, field := range []string{"none", "none", ""} {
		if err := binary.Write(&b, binary.BigEndian, uint32(len(field))); err != nil {
			t.Fatal(err)
		}
		b.WriteString(field)
	}
	if err := binary.Write(&b, binary.BigEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&b, binary.BigEndian, uint32(len(blob))); err != nil {
		t.Fatal(err)
	}
	b.Write(blob)
	if err := binary.Write(&b, binary.BigEndian, uint32(0)); err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: b.Bytes()})
}
