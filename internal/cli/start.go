package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kwtucker/temp-ssh-key/internal/shellenv"
)

func newStartCmd(app *App) *cobra.Command {
	opts := createOptions{}
	var shellName, name, email string
	var noIsolate bool
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Create a temporary key and enter an isolated Git shell",
		Long: `Create a temporary key and enter a history-isolated shell in one step.

The new shell exports KEY_DIR, KEY, KEY_FINGERPRINT, GIT_SSH_COMMAND,
GIT_TERMINAL_PROMPT=0, and the Git config override that forces this key. Pass
--name and --email to export the commit identity too. Global and system Git
config are ignored by default for predictable identity, rewrite rules, and
signing; --no-isolate-config keeps that config instead.

The parent shell records only 'start'. This is the convenience flow; use
'shell' then 'create' when key generation itself must happen inside the
isolated shell.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if shellenv.IsIsolated(app.Getenv) {
				return errors.New(`already in an isolated shell; run "temp-ssh-key create" instead`)
			}
			if err := validateShell(shellName); err != nil {
				return err
			}
			if err := validateIdentity(name, email); err != nil {
				return err
			}
			if err := app.requireInteractive("start"); err != nil {
				return err
			}
			if _, err := app.LookPath(shellName); err != nil {
				return fmt.Errorf("%s not found on PATH (needed for the isolated shell)", shellName)
			}

			opts.emitAssignments = false
			dir, _, err := runCreate(app, opts)
			if err != nil {
				return err
			}
			keepKey := false
			defer func() {
				if !keepKey {
					removePartial(dir)
				}
			}()
			if name == "" && !noIsolate {
				app.note("No --name/--email given and Git config is isolated; set the identity in the repository or restart with them.")
			}
			session, err := sessionOptions(app, dir, name, email, !noIsolate)
			if err != nil {
				return err
			}
			vars, err := shellenv.Vars(session)
			if err != nil {
				return err
			}
			if err := execShell(app, shellName, vars, sessionSteps(true)); err != nil {
				return err
			}
			keepKey = true
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "text", "public key output: text, qr, or png")
	cmd.Flags().StringVar(&opts.comment, "comment", "temporary-ssh-access", "public key comment")
	cmd.Flags().BoolVar(&opts.allowUnencrypted, "allow-unencrypted", false, "create a key without a passphrase")
	cmd.Flags().StringVar(&opts.base, "base", "", "parent directory for the temporary key directory (default: $TMPDIR or /tmp)")
	cmd.Flags().StringVar(&shellName, "shell", "zsh", "isolated shell: zsh or bash")
	cmd.Flags().StringVar(&name, "name", "", "Git author and committer name")
	cmd.Flags().StringVar(&email, "email", "", "Git author and committer email")
	cmd.Flags().BoolVar(&noIsolate, "no-isolate-config", false, "keep global and system Git config")
	return cmd
}
