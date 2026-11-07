package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kwtucker/temp-ssh-key/internal/keydir"
	"github.com/kwtucker/temp-ssh-key/internal/qr"
	"github.com/kwtucker/temp-ssh-key/internal/shellenv"
)

type createOptions struct {
	format           string
	comment          string
	allowUnencrypted bool
	base             string
	// emitAssignments controls whether KEY_DIR and KEY_FINGERPRINT are written
	// to stdout. start suppresses them because it replaces the process.
	emitAssignments bool
}

func newCreateCmd(app *App) *cobra.Command {
	opts := createOptions{}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Generate a temporary Ed25519 key pair and display its public key",
		Long: `Generate a temporary Ed25519 key pair in a private directory and display
only the public key.

stdout contains exactly two eval-safe assignments, so this works:

  eval "$(temp-ssh-key create --format qr)"

The public key, QR code, PNG path, and warnings are written to stderr.
Creation prompts for a passphrase through ssh-keygen. --allow-unencrypted is
required to skip the passphrase and is never implicit.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.emitAssignments = true
			_, _, err := runCreate(app, opts)
			return err
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "text", "public key output: text, qr, or png")
	cmd.Flags().StringVar(&opts.comment, "comment", "temporary-ssh-access", "public key comment")
	cmd.Flags().BoolVar(&opts.allowUnencrypted, "allow-unencrypted", false, "create a key without a passphrase")
	cmd.Flags().StringVar(&opts.base, "base", "", "parent directory for the temporary key directory (default: $TMPDIR or /tmp)")
	return cmd
}

func runCreate(app *App, opts createOptions) (string, string, error) {
	if err := validateFormat(opts.format); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(opts.comment) == "" {
		return "", "", errors.New("comment must not be empty")
	}
	if strings.ContainsAny(opts.comment, "\r\n") {
		return "", "", errors.New("comment must be a single line")
	}
	if opts.format == "qr" {
		if err := app.requireInteractive("QR output"); err != nil {
			return "", "", fmt.Errorf("%w; use --format text or png", err)
		}
	}
	if !opts.allowUnencrypted {
		if err := app.requireInteractive("create"); err != nil {
			return "", "", fmt.Errorf("%w; use --allow-unencrypted only when you intend an unencrypted key", err)
		}
	}

	sshKeygen, err := app.LookPath("ssh-keygen")
	if err != nil {
		return "", "", errors.New("ssh-keygen not found on PATH")
	}

	base, err := resolveBase(app, opts.base)
	if err != nil {
		return "", "", err
	}

	dir, err := keydir.New(base)
	if err != nil {
		return "", "", err
	}
	privatePath := filepath.Join(dir, keydir.PrivateKeyName)
	publicPath := filepath.Join(dir, keydir.PublicKeyName)

	for _, path := range []string{privatePath, publicPath} {
		if _, err := os.Lstat(path); err == nil {
			removePartial(dir)
			return "", "", fmt.Errorf("refusing to overwrite existing file: %s", path)
		} else if !errors.Is(err, fs.ErrNotExist) {
			removePartial(dir)
			return "", "", fmt.Errorf("cannot inspect %s: %w", path, err)
		}
	}

	args := []string{"-q", "-t", "ed25519", "-C", opts.comment, "-f", privatePath}
	if opts.allowUnencrypted {
		args = append(args, "-N", "")
	}
	cmd := exec.Command(sshKeygen, args...)
	cmd.Stdin = app.In
	cmd.Stdout = app.Err
	cmd.Stderr = app.Err
	if err := cmd.Run(); err != nil {
		removePartial(dir)
		return "", "", fmt.Errorf("ssh-keygen failed: %w", err)
	}

	if err := keydir.CheckPrivate(privatePath); err != nil {
		removePartial(dir)
		return "", "", err
	}
	pub, err := keydir.ReadPublic(publicPath)
	if err != nil {
		removePartial(dir)
		return "", "", err
	}

	if err := render(app, dir, opts.format, pub.Line, app.Err); err != nil {
		removePartial(dir)
		return "", "", err
	}

	app.note("Private key: %s (never share or copy it)", privatePath)
	app.note("Show again:  temp-ssh-key show %s --format qr", shellenv.Quote(dir))
	app.note("Clean up:    temp-ssh-key cleanup %s", shellenv.Quote(dir))

	if opts.emitAssignments {
		fmt.Fprintf(app.Out, "KEY_DIR=%s\n", shellenv.Quote(dir))
		fmt.Fprintf(app.Out, "KEY_FINGERPRINT=%s\n", shellenv.Quote(pub.Fingerprint))
	}
	return dir, pub.Fingerprint, nil
}

func resolveBase(app *App, configured string) (string, error) {
	base := configured
	if base == "" {
		base = app.Getenv("TMPDIR")
	}
	if base == "" {
		base = "/tmp"
	}
	base = strings.TrimRight(base, "/")
	if base == "" {
		base = "/"
	}
	if !filepath.IsAbs(base) {
		return "", fmt.Errorf("--base must be an absolute path: %s", base)
	}
	info, err := os.Stat(base)
	if err != nil {
		return "", fmt.Errorf("base directory does not exist: %s", base)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("base is not a directory: %s", base)
	}
	return base, nil
}

// render writes the requested public artifact. create sends it to stderr so
// stdout stays eval-safe; show sends it to stdout.
func render(app *App, dir, format, publicKey string, out io.Writer) error {
	switch format {
	case "text":
		_, err := fmt.Fprintln(out, publicKey)
		return err
	case "qr":
		return qr.Terminal(out, publicKey)
	case "png":
		path, err := writePNG(dir, publicKey)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, path)
		return err
	default:
		return fmt.Errorf("invalid format: %s", format)
	}
}

func writePNG(dir, publicKey string) (string, error) {
	path := filepath.Join(dir, keydir.PNGName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("refusing to overwrite existing file: %s", path)
		}
		return "", fmt.Errorf("cannot create %s: %w", path, err)
	}
	if err := qr.PNG(f, publicKey, 512); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("cannot finish %s: %w", path, err)
	}
	return path, nil
}

func removePartial(dir string) {
	for _, path := range keydir.Files(dir) {
		_ = os.Remove(path)
	}
	_ = os.Remove(dir)
}
