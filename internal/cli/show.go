package cli

import (
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/kwtucker/temp-ssh-key/internal/keydir"
)

func newShowCmd(app *App) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "show KEY_DIR",
		Short: "Verify an existing temporary key directory and display its public key",
		Long: `Verify an existing temporary key directory and display its public key.

The requested artifact goes to stdout. The fingerprint goes to stderr.
QR output needs an interactive terminal; PNG output is written into the key
directory and its path is printed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShow(app, args[0], format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "public key output: text, qr, or png")
	return cmd
}

func runShow(app *App, dir, format string) error {
	if err := validateFormat(format); err != nil {
		return err
	}
	if format == "qr" {
		if err := app.requireInteractive("QR output"); err != nil {
			return err
		}
	}

	dir, err := keydir.Validate(dir)
	if err != nil {
		return err
	}
	pub, err := keydir.ReadPublic(filepath.Join(dir, keydir.PublicKeyName))
	if err != nil {
		return err
	}
	if err := render(app, dir, format, pub.Line, app.Out); err != nil {
		return err
	}
	app.note("fingerprint: %s", pub.Fingerprint)
	return nil
}
