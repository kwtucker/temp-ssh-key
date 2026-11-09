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
	Fingerprint   string
	Name          string
	Email         string
	IsolateConfig bool
	// ConfigCount is the raw GIT_CONFIG_COUNT value from the caller's
	// environment. An empty value means zero.
	ConfigCount string
}

// Var is one environment assignment.
type Var struct {
	Name  string
	Value string
}

// Vars returns the environment for a temporary key session: the key paths,
// Git transport, and optional identity and config isolation.
func Vars(opts Options) ([]Var, error) {
	idx, err := parseConfigCount(opts.ConfigCount)
	if err != nil {
		return nil, err
	}

	sshCommand := fmt.Sprintf("ssh -F /dev/null -o IdentitiesOnly=yes -i %s", Quote(opts.KeyPath))

	vars := []Var{
		{Name: "KEY_DIR", Value: opts.KeyDir},
		{Name: "KEY", Value: opts.KeyPath},
	}
	if opts.Fingerprint != "" {
		vars = append(vars, Var{Name: "KEY_FINGERPRINT", Value: opts.Fingerprint})
	}
	vars = append(vars,
		Var{Name: "GIT_SSH_COMMAND", Value: sshCommand},
		Var{Name: "GIT_TERMINAL_PROMPT", Value: "0"},
		Var{Name: fmt.Sprintf("GIT_CONFIG_KEY_%d", idx), Value: "core.sshCommand"},
		Var{Name: fmt.Sprintf("GIT_CONFIG_VALUE_%d", idx), Value: sshCommand},
		Var{Name: "GIT_CONFIG_COUNT", Value: strconv.Itoa(idx + 1)},
	)

	if opts.Name != "" {
		vars = append(vars,
			Var{Name: "GIT_AUTHOR_NAME", Value: opts.Name},
			Var{Name: "GIT_AUTHOR_EMAIL", Value: opts.Email},
			Var{Name: "GIT_COMMITTER_NAME", Value: opts.Name},
			Var{Name: "GIT_COMMITTER_EMAIL", Value: opts.Email},
		)
	}

	if opts.IsolateConfig {
		vars = append(vars,
			Var{Name: "GIT_CONFIG_GLOBAL", Value: "/dev/null"},
			Var{Name: "GIT_CONFIG_SYSTEM", Value: "/dev/null"},
		)
	}

	return vars, nil
}

// Exports returns eval-safe export statements for the key, Git transport, and
// optional identity. The result ends with a newline.
func Exports(opts Options) (string, error) {
	vars, err := Vars(opts)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	for _, v := range vars {
		fmt.Fprintf(&b, "export %s=%s\n", v.Name, Quote(v.Value))
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
