package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kwtucker/temp-ssh-key/internal/shellenv"
)

func newShellCmd(app *App) *cobra.Command {
	var shellName string
	cmd := &cobra.Command{
		Use:   "shell [KEY_DIR]",
		Short: "Enter a history-isolated shell",
		Long: `Enter a history-isolated zsh or bash. History storage is disabled for that
shell, so commands typed there do not land in the parent's history file.

When KEY_DIR is given, the new shell gets the same exports as 'env': KEY_DIR,
KEY, KEY_FINGERPRINT, GIT_SSH_COMMAND, GIT_TERMINAL_PROMPT=0, and Git config
isolation. The parent shell records only the shell command; 'exit' returns to
it.

Use the strict flow when the key should be created inside the isolated shell:

  temp-ssh-key shell
  eval "$(temp-ssh-key create --format qr)"
  eval "$(temp-ssh-key env "$KEY_DIR")"`,
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

	var vars []shellenv.Var
	if len(args) == 1 {
		opts, err := sessionOptions(args[0], "", "", true)
		if err != nil {
			return err
		}
		vars = shellenv.Vars(opts)
	}
	return execShell(app, shellName, vars, sessionSteps(len(args) == 1))
}

func execShell(app *App, shellName string, vars []shellenv.Var, steps []string) error {
	binary, err := app.LookPath(shellName)
	if err != nil {
		return fmt.Errorf("%s not found on PATH (needed for the isolated shell)", shellName)
	}

	env := shellenv.Sanitize(app.Environ())
	env = setEnv(env, "TEMP_SSH_KEY_ISOLATED", "1")
	for _, v := range vars {
		env = setEnv(env, v.Name, v.Value)
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

	if len(steps) > 0 {
		app.note("Next steps:")
		for i, step := range steps {
			app.note("  %d. %s", i+1, step)
		}
	}
	app.note("Entering history-isolated %s; history is disabled for that shell ('exit' returns).", shellName)
	return app.Exec(binary, argv, env)
}

// sessionSteps returns the short checklist printed before the isolated shell
// starts.
func sessionSteps(hasKey bool) []string {
	if hasKey {
		return []string{
			"Authorize the public key on your trusted device (scan the QR code or copy the text).",
			"Run your git commands here; the key and GIT_SSH_COMMAND are already exported.",
			"Revoke the key on your trusted device; deleting local files is not revocation.",
			"temp-ssh-key cleanup",
			"exit",
		}
	}
	return []string{
		`eval "$(temp-ssh-key create --format qr)"`,
		`eval "$(temp-ssh-key env "$KEY_DIR" --name "..." --email "...")"`,
		"Authorize the public key on your trusted device.",
		"Run your git commands here.",
		"Revoke the key on your trusted device; deleting local files is not revocation.",
		"temp-ssh-key cleanup",
		"exit",
	}
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
