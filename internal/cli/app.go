// Package cli wires the temp-ssh-key commands to Cobra.
package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

// App carries process-level dependencies so commands can be tested without a
// real terminal, a real ssh-keygen, or a real process replacement.
type App struct {
	In          io.Reader
	Out         io.Writer
	Err         io.Writer
	Version     string
	Interactive bool

	LookPath func(string) (string, error)
	Exec     func(path string, argv []string, env []string) error
	Getenv   func(string) string
	Environ  func() []string
}

// NewApp returns an App wired to the current process. Interactive is true only
// when both stdin and stdout are terminals.
func NewApp(version string) *App {
	return &App{
		In:          os.Stdin,
		Out:         os.Stdout,
		Err:         os.Stderr,
		Version:     version,
		Interactive: isTerminal(os.Stdin) && isTerminal(os.Stdout),
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
	if !a.Interactive {
		return fmt.Errorf("%s needs an interactive terminal; run this yourself, not through a tool call", what)
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

func validateShell(name string) error {
	switch name {
	case "zsh", "bash":
		return nil
	default:
		return fmt.Errorf("invalid shell: %s (use zsh or bash)", name)
	}
}
