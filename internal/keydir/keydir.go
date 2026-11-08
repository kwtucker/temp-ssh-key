// Package keydir owns the layout, validation, and guarded inspection of a
// temporary key directory. It never contacts a remote and never decides
// whether a key should exist.
package keydir

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	// DirPrefix is required in the base name of every managed directory. It
	// keeps cleanup and inspection from touching unrelated paths.
	DirPrefix = "temp-ssh-key."
	// PrivateKeyName is the private key file name created by ssh-keygen.
	PrivateKeyName = "id_ed25519"
	// PublicKeyName is the public key file name created by ssh-keygen.
	PublicKeyName = "id_ed25519.pub"
	// PNGName is the optional rendered QR code file name.
	PNGName = "public-key.png"
)

// PublicKey is the parsed form of an OpenSSH Ed25519 public key.
type PublicKey struct {
	// Line is the original authorized_keys-style line, without a trailing
	// newline.
	Line string
	// Fingerprint is the OpenSSH SHA256 fingerprint, for example
	// SHA256:abc...
	Fingerprint string
}

// New creates a private temporary directory under base. The directory mode is
// 0700.
func New(base string) (string, error) {
	dir, err := os.MkdirTemp(base, DirPrefix)
	if err != nil {
		return "", fmt.Errorf("could not create a temporary directory under %s: %w", base, err)
	}
	return dir, nil
}

// Validate checks that dir is a directory this tool owns. It rejects relative
// paths, symlinks, other owners, unexpected modes, and unexpected names.
func Validate(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("missing key directory")
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("use an absolute key directory path: %s", dir)
	}
	dir = filepath.Clean(dir)

	info, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("no such key directory: %s", dir)
		}
		return "", fmt.Errorf("cannot inspect key directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing symlinked directory: %s", dir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", dir)
	}
	if !secureMode(info, 0o700) {
		return "", fmt.Errorf("key directory must be mode 700: %s", dir)
	}
	if !strings.HasPrefix(filepath.Base(dir), DirPrefix) {
		return "", fmt.Errorf("refusing unexpected directory (expected %s*): %s", DirPrefix, dir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return "", fmt.Errorf("key directory is not owned by you: %s", dir)
	}
	return dir, nil
}

// CheckPrivate verifies that path is a non-empty regular private key file with
// mode 0600 and no symlink.
func CheckPrivate(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("missing private key: %s", path)
		}
		return fmt.Errorf("cannot inspect private key %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked private key: %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular private key: %s", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("empty private key: %s", path)
	}
	if !secureMode(info, 0o600) {
		return fmt.Errorf("private key must be mode 600: %s", path)
	}
	return nil
}

func secureMode(info os.FileInfo, want os.FileMode) bool {
	special := os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	return info.Mode().Perm() == want && info.Mode()&special == 0
}

// ReadPublic parses an OpenSSH Ed25519 public key file and returns its line and
// fingerprint. It never prints key material as a side effect.
func ReadPublic(path string) (PublicKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return PublicKey{}, fmt.Errorf("missing public key: %s", path)
		}
		return PublicKey{}, fmt.Errorf("cannot inspect public key %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return PublicKey{}, fmt.Errorf("refusing symlinked public key: %s", path)
	}
	if !info.Mode().IsRegular() {
		return PublicKey{}, fmt.Errorf("not a regular public key: %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return PublicKey{}, fmt.Errorf("cannot read public key %s: %w", path, err)
	}
	line := strings.TrimSpace(string(data))
	if line == "" {
		return PublicKey{}, fmt.Errorf("empty public key: %s", path)
	}
	if strings.Contains(line, "\n") || strings.Contains(line, "\r") {
		return PublicKey{}, fmt.Errorf("public key must be a single line: %s", path)
	}

	fingerprint, err := fingerprint(line)
	if err != nil {
		return PublicKey{}, fmt.Errorf("not a valid Ed25519 public key: %s: %w", path, err)
	}
	return PublicKey{Line: line, Fingerprint: fingerprint}, nil
}

func fingerprint(line string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", errors.New("expected key type and key data")
	}
	if fields[0] != "ssh-ed25519" {
		return "", fmt.Errorf("key type is %q, not ssh-ed25519", fields[0])
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", fmt.Errorf("invalid key encoding: %w", err)
	}

	keyType, rest, err := readString(blob)
	if err != nil {
		return "", err
	}
	if keyType != "ssh-ed25519" {
		return "", fmt.Errorf("key blob type is %q, not ssh-ed25519", keyType)
	}
	key, rest, err := readString(rest)
	if err != nil {
		return "", err
	}
	if len(key) != ed25519.PublicKeySize {
		return "", fmt.Errorf("key length is %d, want %d", len(key), ed25519.PublicKeySize)
	}
	if len(rest) != 0 {
		return "", errors.New("unexpected trailing data in key blob")
	}

	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func readString(b []byte) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, errors.New("truncated key blob")
	}
	n := binary.BigEndian.Uint32(b[:4])
	if int64(n) > int64(len(b)-4) {
		return "", nil, errors.New("truncated key blob string")
	}
	return string(b[4 : 4+n]), b[4+n:], nil
}

// Unexpected lists entries in dir that this tool did not create. The result is
// sorted.
func Unexpected(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read key directory %s: %w", dir, err)
	}
	expected := map[string]bool{
		PrivateKeyName: true,
		PublicKeyName:  true,
		PNGName:        true,
	}
	var unexpected []string
	for _, entry := range entries {
		if !expected[entry.Name()] {
			unexpected = append(unexpected, entry.Name())
		}
	}
	sort.Strings(unexpected)
	return unexpected, nil
}

// Files returns the managed file paths in deletion order.
func Files(dir string) []string {
	return []string{
		filepath.Join(dir, PrivateKeyName),
		filepath.Join(dir, PublicKeyName),
		filepath.Join(dir, PNGName),
	}
}
