package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/kwtucker/temp-ssh-key/internal/keydir"
	"github.com/kwtucker/temp-ssh-key/internal/shellenv"
)

func newEnvCmd(app *App) *cobra.Command {
	var name, email string
	var noIsolate bool
	cmd := &cobra.Command{
		Use:   "env KEY_DIR",
		Short: "Print eval-safe exports that make Git use this key",
		Long: `Print eval-safe shell exports that make Git use this key and identity:

  eval "$(temp-ssh-key env "$KEY_DIR" --name "..." --email "...")"

By default this also ignores global and system Git config in this shell for
predictable identity, rewrite rules, and signing. --no-isolate-config keeps
that config instead. GIT_TERMINAL_PROMPT=0 prevents Git from waiting for
credentials in a session where they should not be entered.

This command contacts no remote and writes no files.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnv(app, args[0], name, email, noIsolate)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Git author and committer name")
	cmd.Flags().StringVar(&email, "email", "", "Git author and committer email")
	cmd.Flags().BoolVar(&noIsolate, "no-isolate-config", false, "keep global and system Git config")
	return cmd
}

func runEnv(app *App, dir, name, email string, noIsolate bool) error {
	opts, err := sessionOptions(dir, name, email, !noIsolate)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(app.Out, shellenv.Exports(opts))
	return err
}

// sessionOptions validates an existing key directory and returns the exports
// for a Git session that uses it.
func sessionOptions(dir, name, email string, isolate bool) (shellenv.Options, error) {
	dir, pub, err := keydir.Verify(dir)
	if err != nil {
		return shellenv.Options{}, err
	}
	keyPath := filepath.Join(dir, keydir.PrivateKeyName)
	if err := validateIdentity(name, email); err != nil {
		return shellenv.Options{}, err
	}
	return shellenv.Options{
		KeyDir:        dir,
		KeyPath:       keyPath,
		Fingerprint:   pub.Fingerprint,
		Name:          name,
		Email:         email,
		IsolateConfig: isolate,
	}, nil
}
