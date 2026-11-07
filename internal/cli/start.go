package cli

import (
	"errors"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/kwtucker/temp-ssh-key/internal/keydir"
	"github.com/kwtucker/temp-ssh-key/internal/shellenv"
)

func newStartCmd(app *App) *cobra.Command {
	opts := createOptions{}
	var shellName string
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Create a temporary key and enter an isolated shell",
		Long: `Create a temporary key and enter a history-isolated shell in one step.

The parent shell records only 'start'. The new shell exports KEY_DIR and KEY.
This is the convenience flow; use 'shell' then 'create' when key generation
itself must happen inside the isolated shell.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if shellenv.IsIsolated(app.Getenv) {
				return errors.New(`already in an isolated shell; run "temp-ssh-key create" instead`)
			}
			if err := validateShell(shellName); err != nil {
				return err
			}
			if err := app.requireInteractive("start"); err != nil {
				return err
			}

			opts.emitAssignments = false
			dir, fingerprint, err := runCreate(app, opts)
			if err != nil {
				return err
			}
			return execShell(app, shellName, dir, filepath.Join(dir, keydir.PrivateKeyName), fingerprint)
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "text", "public key output: text, qr, or png")
	cmd.Flags().StringVar(&opts.comment, "comment", "temporary-ssh-access", "public key comment")
	cmd.Flags().BoolVar(&opts.allowUnencrypted, "allow-unencrypted", false, "create a key without a passphrase")
	cmd.Flags().StringVar(&opts.base, "base", "", "parent directory for the temporary key directory (default: $TMPDIR or /tmp)")
	cmd.Flags().StringVar(&shellName, "shell", "zsh", "isolated shell: zsh or bash")
	return cmd
}
