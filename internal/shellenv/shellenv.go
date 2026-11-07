// Package shellenv renders values and exports that are safe to pass to a
// POSIX shell's eval builtin.
package shellenv

import (
	"fmt"
	"strconv"
	"strings"
)

// Quote returns s as a single POSIX shell word. It is safe for eval and for
// embedding in a command line, including values containing spaces or single
// quotes.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Options describes the environment exports for an existing temporary key.
type Options struct {
	KeyDir        string
	KeyPath       string
	Name          string
	Email         string
	IsolateConfig bool
	// ConfigCount is the raw GIT_CONFIG_COUNT value from the caller's
	// environment. An empty value means zero.
	ConfigCount string
}

// Exports returns eval-safe export statements for the key, Git transport, and
// optional identity. The result ends with a newline.
func Exports(opts Options) (string, error) {
	idx, err := parseConfigCount(opts.ConfigCount)
	if err != nil {
		return "", err
	}

	sshCommand := fmt.Sprintf("ssh -F /dev/null -o IdentitiesOnly=yes -i %s", Quote(opts.KeyPath))

	var b strings.Builder
	fmt.Fprintf(&b, "export KEY_DIR=%s\n", Quote(opts.KeyDir))
	fmt.Fprintf(&b, "export KEY=%s\n", Quote(opts.KeyPath))
	fmt.Fprintf(&b, "export GIT_SSH_COMMAND=%s\n", Quote(sshCommand))
	fmt.Fprintf(&b, "export GIT_CONFIG_KEY_%d=core.sshCommand\n", idx)
	fmt.Fprintf(&b, "export GIT_CONFIG_VALUE_%d=%s\n", idx, Quote(sshCommand))
	fmt.Fprintf(&b, "export GIT_CONFIG_COUNT=%d\n", idx+1)

	if opts.Name != "" {
		fmt.Fprintf(&b, "export GIT_AUTHOR_NAME=%s\n", Quote(opts.Name))
		fmt.Fprintf(&b, "export GIT_AUTHOR_EMAIL=%s\n", Quote(opts.Email))
		fmt.Fprintf(&b, "export GIT_COMMITTER_NAME=%s\n", Quote(opts.Name))
		fmt.Fprintf(&b, "export GIT_COMMITTER_EMAIL=%s\n", Quote(opts.Email))
	}

	if opts.IsolateConfig {
		b.WriteString("export GIT_CONFIG_GLOBAL=/dev/null\n")
		b.WriteString("export GIT_CONFIG_SYSTEM=/dev/null\n")
	}

	return b.String(), nil
}

func parseConfigCount(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("GIT_CONFIG_COUNT is not a non-negative integer: %s", raw)
		}
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("GIT_CONFIG_COUNT is not a non-negative integer: %s", raw)
	}
	return n, nil
}

// IsIsolated reports whether the current process already lives in a shell
// started by this tool. The marker is authoritative; the history variables
// also recognize a manually configured equivalent.
func IsIsolated(getenv func(string) string) bool {
	if getenv("TEMP_SSH_KEY_ISOLATED") == "1" {
		return true
	}
	if getenv("HISTFILE") != "/dev/null" {
		return false
	}
	return getenv("SAVEHIST") == "0" || getenv("HISTSIZE") == "0"
}
