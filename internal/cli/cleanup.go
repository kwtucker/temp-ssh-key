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
	var remove bool
	cmd := &cobra.Command{
		Use:   "cleanup KEY_DIR",
		Short: "Print or remove this tool's local key files",
		Long: `Print the commands that delete only this tool's files. With --remove, delete
them after prompting per file and require an interactive terminal.

Revoke the key's remote authorization first. Deleting local files is not
revocation, and this command never contacts a remote.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCleanup(app, args[0], remove)
		},
	}
	cmd.Flags().BoolVar(&remove, "remove", false, "delete the files after prompting per file")
	return cmd
}

func runCleanup(app *App, dir string, remove bool) error {
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

	if !remove {
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
			fmt.Fprintf(app.Out, "rm -i %s\n", strings.Join(existing, " "))
		}
		fmt.Fprintf(app.Out, "rmdir %s\n", shellenv.Quote(dir))
		app.note("Run those yourself in your terminal; this tool deleted nothing.")
		return nil
	}

	if err := app.requireInteractive("cleanup --remove"); err != nil {
		return err
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
		confirmed, err := confirm(reader, app.Err, fmt.Sprintf("remove %s?", shellenv.Quote(path)))
		if err != nil {
			return err
		}
		if !confirmed {
			continue
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
	fmt.Fprintf(out, "%s [y/N] ", prompt)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.TrimSpace(line)
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes"), nil
}
