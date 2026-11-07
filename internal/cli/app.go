// Package cli wires the temp-ssh-key commands to Cobra.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// App carries process-level dependencies so commands can be tested without a
// real terminal, a real ssh-keygen, or a real process replacement.
type App struct {
	In      io.Reader
	Out     io.Writer
	Err     io.Writer
	Version string

	// Terminal status is tracked per stream because command substitution
	// captures stdout while stdin and stderr stay attached to the terminal.
	StdinIsTTY  bool
	StdoutIsTTY bool
	StderrIsTTY bool

	LookPath func(string) (string, error)
	Exec     func(path string, argv []string, env []string) error
	Getenv   func(string) string
	Environ  func() []string
}

// NewApp returns an App wired to the current process.
func NewApp(version string) *App {
	return &App{
		In:          os.Stdin,
		Out:         os.Stdout,
		Err:         os.Stderr,
		Version:     version,
		StdinIsTTY:  isTerminal(os.Stdin),
		StdoutIsTTY: isTerminal(os.Stdout),
		StderrIsTTY: isTerminal(os.Stderr),
		LookPath:    exec.LookPath,
		Exec: func(path string, argv []string, env []string) error {
			return syscall.Exec(path, argv, env)
		},
		Getenv:  os.Getenv,
		Environ: os.Environ,
	}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func (a *App) note(format string, args ...any) {
	fmt.Fprintf(a.Err, "temp-ssh-key: "+format+"\n", args...)
}

func (a *App) requireInteractive(what string) error {
	if !a.StdinIsTTY || !a.StdoutIsTTY {
		return fmt.Errorf("%s needs an interactive terminal; run this yourself, not through a tool call", what)
	}
	return nil
}

func (a *App) requireStdinTTY(what string) error {
	if !a.StdinIsTTY {
		return fmt.Errorf("%s needs an interactive terminal on stdin; run this yourself, not through a tool call", what)
	}
	return nil
}

func (a *App) requireStdoutTTY(what string) error {
	if !a.StdoutIsTTY {
		return fmt.Errorf("%s needs an interactive terminal on stdout", what)
	}
	return nil
}

func (a *App) requireStderrTTY(what string) error {
	if !a.StderrIsTTY {
		return fmt.Errorf("%s needs an interactive terminal on stderr", what)
	}
	return nil
}

func validateFormat(format string) error {
	switch format {
	case "text", "qr", "png":
		return nil
	default:
		return fmt.Errorf("invalid format: %s (use text, qr, or png)", format)
	}
}

func validateIdentity(name, email string) error {
	if (name == "") != (email == "") {
		return errors.New("--name and --email must be given together")
	}
	if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(email, "\r\n") {
		return errors.New("name and email must be single lines")
	}
	return nil
}

func validateShell(name string) error {
	switch name {
	case "zsh", "bash":
		return nil
	default:
		return fmt.Errorf("invalid shell: %s (use zsh or bash)", name)
	}
}
