package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kwtucker/temp-ssh-key/internal/keydir"
	"github.com/kwtucker/temp-ssh-key/internal/shellenv"
)

func newCleanupCmd(app *App) *cobra.Command {
	var dryRun, yes bool
	cmd := &cobra.Command{
		Use:   "cleanup [KEY_DIR]",
		Short: "Remove this tool's local key files",
		Long: `Remove this tool's local key files after prompting per file.

With --dry-run, print the commands instead of deleting anything. With --yes,
skip the per-file prompts.

KEY_DIR defaults to $KEY_DIR, so inside a session started by 'start' or by
'shell KEY_DIR' this is enough:

  temp-ssh-key cleanup

Revoke the key's remote authorization first. Deleting local files is not
revocation, and this command never contacts a remote.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRun && yes {
				return errors.New("--dry-run and --yes are mutually exclusive")
			}
			dir := ""
			if len(args) == 1 {
				dir = args[0]
			}
			return runCleanup(app, dir, dryRun, yes)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the commands instead of deleting anything")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the per-file prompts")
	return cmd
}

func runCleanup(app *App, dir string, dryRun, yes bool) error {
	if dir == "" {
		dir = app.Getenv("KEY_DIR")
		if dir == "" {
			return errors.New("KEY_DIR is not set; pass KEY_DIR or run inside a temp-ssh-key session")
		}
	}
	dir, err := keydir.Validate(dir)
	if err != nil {
		return err
	}
	unexpected, err := keydir.Unexpected(dir)
	if err != nil {
		return err
	}
	if len(unexpected) > 0 {
		return fmt.Errorf("unexpected files in %s: %s (not cleaning up)", dir, strings.Join(unexpected, " "))
	}

	if dryRun {
		return printCleanup(app, dir)
	}
	if !yes {
		if err := app.requireStdinStderrTTY("cleanup"); err != nil {
			return err
		}
	}
	app.note("Revoke remote authorization first; deleting local files is not revocation.")

	reader := bufio.NewReader(app.In)
	for _, path := range keydir.Files(dir) {
		ok, err := exists(path)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if !yes {
			confirmed, err := confirm(reader, app.Err, fmt.Sprintf("remove %s?", shellenv.Quote(path)))
			if err != nil {
				return err
			}
			if !confirmed {
				continue
			}
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("could not remove %s: %w", path, err)
		}
	}

	if err := os.Remove(dir); err != nil {
		return fmt.Errorf("directory not empty; left in place: %s", dir)
	}
	app.note("Removed: %s", dir)
	return nil
}

func printCleanup(app *App, dir string) error {
	app.note("Revoke remote authorization first; deleting local files is not revocation.")
	var existing []string
	for _, path := range keydir.Files(dir) {
		ok, err := exists(path)
		if err != nil {
			return err
		}
		if ok {
			existing = append(existing, shellenv.Quote(path))
		}
	}
	if len(existing) > 0 {
		if _, err := fmt.Fprintf(app.Out, "rm -i %s\n", strings.Join(existing, " ")); err != nil {
			return fmt.Errorf("cannot write cleanup commands: %w", err)
		}
	}
	if _, err := fmt.Fprintf(app.Out, "rmdir %s\n", shellenv.Quote(dir)); err != nil {
		return fmt.Errorf("cannot write cleanup commands: %w", err)
	}
	app.note("This was a dry run; run those commands yourself or rerun without --dry-run.")
	return nil
}

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("cannot inspect %s: %w", path, err)
}

func confirm(reader *bufio.Reader, out io.Writer, prompt string) (bool, error) {
	if _, err := fmt.Fprintf(out, "%s [y/N] ", prompt); err != nil {
		return false, fmt.Errorf("cannot write prompt: %w", err)
	}
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.TrimSpace(line)
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes"), nil
}
