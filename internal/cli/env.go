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
that config instead.

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
	dir, err := keydir.Validate(dir)
	if err != nil {
		return err
	}
	if _, err := keydir.ReadPublic(filepath.Join(dir, keydir.PublicKeyName)); err != nil {
		return err
	}
	keyPath := filepath.Join(dir, keydir.PrivateKeyName)
	if err := keydir.CheckPrivate(keyPath); err != nil {
		return err
	}

	if (name == "") != (email == "") {
		return errors.New("--name and --email must be given together")
	}
	if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(email, "\r\n") {
		return errors.New("name and email must be single lines")
	}

	output, err := shellenv.Exports(shellenv.Options{
		KeyDir:        dir,
		KeyPath:       keyPath,
		Name:          name,
		Email:         email,
		IsolateConfig: !noIsolate,
		ConfigCount:   app.Getenv("GIT_CONFIG_COUNT"),
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(app.Out, output)
	return err
}
