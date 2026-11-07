package cli

import (
	"github.com/spf13/cobra"
)

// NewRootCmd builds the complete command tree.
func NewRootCmd(app *App) *cobra.Command {
	root := &cobra.Command{
		Use:   "temp-ssh-key",
		Short: "Create and manage disposable SSH keys for untrusted machines",
		Long: `Create a disposable Ed25519 key pair, share only its public key, and enter
a history-isolated shell for the git operation.

This tool never contacts a remote, edits SSH or Git configuration, adds a key
to ssh-agent, or revokes authorization. Authorizing and revoking the public key
is always a separate, manual step on a trusted device. Deleting local files is
not revocation.`,
		Version:           app.Version,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Args:              cobra.NoArgs,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	root.SetVersionTemplate("temp-ssh-key {{.Version}}\n")
	root.SetIn(app.In)
	root.SetOut(app.Out)
	root.SetErr(app.Err)

	root.AddCommand(
		newCreateCmd(app),
		newShellCmd(app),
		newStartCmd(app),
		newShowCmd(app),
		newEnvCmd(app),
		newCleanupCmd(app),
	)
	return root
}
