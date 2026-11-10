// Package shellenv renders values and exports that are safe to pass to a
// POSIX shell's eval builtin.
package shellenv

import (
	"fmt"
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
}

// Var is one environment assignment.
type Var struct {
	Name  string
	Value string
}

// unsetVars are inherited variables that can redirect SSH or Git to
// credentials, repositories, or programs the user did not choose for this
// session. The isolated session removes them instead of trusting the machine.
var unsetVars = []string{
	"SSH_AUTH_SOCK", // use only the explicit key, not an inherited agent
	"SSH_ASKPASS",
	"SSH_ASKPASS_REQUIRE",
	"GIT_ASKPASS",
	"GIT_CONFIG_PARAMETERS", // undocumented config injection channel
	"GIT_CONFIG_COUNT",      // reset before setting the session's single entry
	"GIT_DIR",
	"GIT_WORK_TREE",
	"GIT_COMMON_DIR",
	"GIT_INDEX_FILE",
	"GIT_OBJECT_DIRECTORY",
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_NAMESPACE",
	"GIT_SSH",
	"GIT_SSH_VARIANT",
}

// Sanitize returns a copy of env without inherited variables that could
// redirect the session. It also drops numbered Git config entries.
func Sanitize(env []string) []string {
	out := make([]string, 0, len(env))
	for _, item := range env {
		name, _, _ := strings.Cut(item, "=")
		if isUnsetVar(name) || hasConfigIndex(name) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func isUnsetVar(name string) bool {
	for _, candidate := range unsetVars {
		if name == candidate {
			return true
		}
	}
	return false
}

func hasConfigIndex(name string) bool {
	return strings.HasPrefix(name, "GIT_CONFIG_KEY_") ||
		strings.HasPrefix(name, "GIT_CONFIG_VALUE_")
}

// Vars returns the environment for a temporary key session: the key paths,
// Git transport, and optional identity and config isolation.
func Vars(opts Options) []Var {
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
		Var{Name: "GIT_CONFIG_KEY_0", Value: "core.sshCommand"},
		Var{Name: "GIT_CONFIG_VALUE_0", Value: sshCommand},
		Var{Name: "GIT_CONFIG_COUNT", Value: "1"},
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

	return vars
}

// Exports returns eval-safe statements that reset inherited session variables
// and export the key, Git transport, and optional identity. The result ends
// with a newline.
func Exports(opts Options) string {
	var b strings.Builder
	for _, name := range unsetVars {
		fmt.Fprintf(&b, "unset %s\n", name)
	}
	for _, v := range Vars(opts) {
		fmt.Fprintf(&b, "export %s=%s\n", v.Name, Quote(v.Value))
	}
	return b.String()
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
