package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kwtucker/temp-ssh-key/internal/keydir"
	"github.com/kwtucker/temp-ssh-key/internal/shellenv"
)

func newShellCmd(app *App) *cobra.Command {
	var shellName string
	cmd := &cobra.Command{
		Use:   "shell [KEY_DIR]",
		Short: "Enter a history-isolated shell",
		Long: `Enter a history-isolated zsh or bash. History storage is disabled for that
shell, so commands typed there do not land in the parent's history file.

When KEY_DIR is given, KEY_DIR and KEY are exported in the new shell. The
parent shell records only the shell command; 'exit' returns to it.

Use the strict flow when the key should be created inside the isolated shell:

  temp-ssh-key shell
  eval "$(temp-ssh-key create --format qr)"`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShell(app, shellName, args)
		},
	}
	cmd.Flags().StringVar(&shellName, "shell", "zsh", "isolated shell: zsh or bash")
	return cmd
}

func runShell(app *App, shellName string, args []string) error {
	if err := validateShell(shellName); err != nil {
		return err
	}
	if shellenv.IsIsolated(app.Getenv) {
		app.note("already in an isolated shell; nothing to do")
		return nil
	}
	if err := app.requireInteractive("shell"); err != nil {
		return err
	}

	var keyDir, keyPath, fingerprint string
	if len(args) == 1 {
		validated, err := keydir.Validate(args[0])
		if err != nil {
			return err
		}
		pub, err := keydir.ReadPublic(filepath.Join(validated, keydir.PublicKeyName))
		if err != nil {
			return err
		}
		keyPath = filepath.Join(validated, keydir.PrivateKeyName)
		if err := keydir.CheckPrivate(keyPath); err != nil {
			return err
		}
		keyDir = validated
		fingerprint = pub.Fingerprint
	}
	return execShell(app, shellName, keyDir, keyPath, fingerprint)
}

func execShell(app *App, shellName, keyDir, keyPath, fingerprint string) error {
	binary, err := app.LookPath(shellName)
	if err != nil {
		return fmt.Errorf("%s not found on PATH (needed for the isolated shell)", shellName)
	}

	env := app.Environ()
	env = setEnv(env, "TEMP_SSH_KEY_ISOLATED", "1")
	if keyDir != "" {
		env = setEnv(env, "KEY_DIR", keyDir)
		env = setEnv(env, "KEY", keyPath)
		env = setEnv(env, "KEY_FINGERPRINT", fingerprint)
	}

	var argv []string
	switch shellName {
	case "zsh":
		env = setEnv(env, "HISTFILE", "/dev/null")
		env = setEnv(env, "SAVEHIST", "0")
		argv = []string{binary, "-f"}
	case "bash":
		env = setEnv(env, "HISTFILE", "/dev/null")
		env = setEnv(env, "HISTSIZE", "0")
		argv = []string{binary, "--noprofile", "--norc"}
	default:
		return errors.New("invalid shell: " + shellName)
	}

	app.note("Entering history-isolated %s; run env, git, and cleanup here ('exit' returns).", shellName)
	return app.Exec(binary, argv, env)
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			if !replaced {
				out = append(out, prefix+value)
				replaced = true
			}
			continue
		}
		out = append(out, item)
	}
	if !replaced {
		out = append(out, prefix+value)
	}
	return out
}
