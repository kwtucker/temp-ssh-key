package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kwtucker/temp-ssh-key/internal/keydir"
)

func newTestApp(t *testing.T) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errOut bytes.Buffer
	app := &App{
		In:          strings.NewReader(""),
		Out:         &out,
		Err:         &errOut,
		Version:     "test",
		StdinIsTTY:  false,
		StdoutIsTTY: false,
		StderrIsTTY: false,
		LookPath:    exec.LookPath,
		Exec:        func(string, []string, []string) error { return nil },
		Getenv:      func(string) string { return "" },
		Environ:     func() []string { return []string{"PATH=" + os.Getenv("PATH")} },
	}
	return app, &out, &errOut
}

func setInteractive(app *App) {
	app.StdinIsTTY = true
	app.StdoutIsTTY = true
	app.StderrIsTTY = true
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func runCLI(t *testing.T, app *App, args ...string) error {
	t.Helper()
	cmd := NewRootCmd(app)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestIsTerminalRejectsDevNull(t *testing.T) {
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Fatal("isTerminal treated /dev/null as a terminal")
	}
}

func TestVersion(t *testing.T) {
	app, out, _ := newTestApp(t)
	if err := runCLI(t, app, "--version"); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "temp-ssh-key test\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestHelpListsCommands(t *testing.T) {
	app, out, _ := newTestApp(t)
	if err := runCLI(t, app, "help"); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"create", "shell", "start", "show", "env", "cleanup"} {
		if !strings.Contains(out.String(), command) {
			t.Errorf("help output does not mention %q", command)
		}
	}
}

func TestCreateText(t *testing.T) {
	line, fingerprint := setupFakeKeygen(t)
	app, out, errOut := newTestApp(t)
	base := t.TempDir()

	if err := runCLI(t, app, "create", "--allow-unencrypted", "--format", "text", "--base", base); err != nil {
		t.Fatal(err)
	}

	assignments := parseAssignments(t, out.String())
	if len(assignments) != 2 {
		t.Fatalf("stdout has %d assignments, want 2:\n%s", len(assignments), out.String())
	}
	dir := assignments["KEY_DIR"]
	if dir == "" {
		t.Fatalf("missing KEY_DIR:\n%s", out.String())
	}
	if got := assignments["KEY_FINGERPRINT"]; got != fingerprint {
		t.Fatalf("KEY_FINGERPRINT = %q, want %q", got, fingerprint)
	}
	if !strings.Contains(errOut.String(), line) {
		t.Fatalf("stderr does not contain the public key:\n%s", errOut.String())
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("key directory mode = %o, want 700", got)
	}
	privateInfo, err := os.Stat(filepath.Join(dir, keydir.PrivateKeyName))
	if err != nil {
		t.Fatal(err)
	}
	if got := privateInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("private key mode = %o, want 600", got)
	}
}

func TestCreateRequiresTTYWithoutAllowUnencrypted(t *testing.T) {
	setupFakeKeygen(t)
	app, out, _ := newTestApp(t)
	base := t.TempDir()

	err := runCLI(t, app, "create", "--format", "text", "--base", base)
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("error = %v, want an interactive-terminal error", err)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", out.String())
	}
}

func TestCreateQRRequiresTTY(t *testing.T) {
	setupFakeKeygen(t)
	app, _, _ := newTestApp(t)

	err := runCLI(t, app, "create", "--allow-unencrypted", "--format", "qr", "--base", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("error = %v, want an interactive-terminal error", err)
	}
}

// Command substitution captures stdout. create must still render the QR to
// stderr and write the assignments to the captured stdout.
func TestCreateQRWithCapturedStdout(t *testing.T) {
	setupFakeKeygen(t)
	app, out, errOut := newTestApp(t)
	app.StdinIsTTY = true
	app.StderrIsTTY = true

	if err := runCLI(t, app, "create", "--allow-unencrypted", "--format", "qr", "--base", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	assignments := parseAssignments(t, out.String())
	if assignments["KEY_DIR"] == "" {
		t.Fatalf("missing KEY_DIR:\n%s", out.String())
	}
	if !strings.ContainsAny(errOut.String(), "█▀▄") {
		t.Fatalf("stderr does not contain a QR code:\n%s", errOut.String())
	}
}

// The passphrase prompt needs stdin only; stdout may be captured by eval.
func TestCreatePassphraseWithCapturedStdout(t *testing.T) {
	setupFakeKeygen(t)
	app, out, _ := newTestApp(t)
	app.StdinIsTTY = true

	if err := runCLI(t, app, "create", "--format", "text", "--base", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if assignments := parseAssignments(t, out.String()); assignments["KEY_DIR"] == "" {
		t.Fatalf("missing KEY_DIR:\n%s", out.String())
	}
}

func TestShowQRUsesStdoutTTY(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, out, _ := newTestApp(t)
	app.StdoutIsTTY = true

	if err := runCLI(t, app, "show", dir, "--format", "qr"); err != nil {
		t.Fatal(err)
	}
	if !strings.ContainsAny(out.String(), "█▀▄") {
		t.Fatal("stdout does not contain a QR code")
	}
}

func TestCreatePNG(t *testing.T) {
	line, _ := setupFakeKeygen(t)
	app, out, errOut := newTestApp(t)

	if err := runCLI(t, app, "create", "--allow-unencrypted", "--format", "png", "--base", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	assignments := parseAssignments(t, out.String())
	dir := assignments["KEY_DIR"]
	if dir == "" {
		t.Fatalf("missing KEY_DIR:\n%s", out.String())
	}
	path := filepath.Join(dir, keydir.PNGName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	magic := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	if len(data) < len(magic) || !bytes.Equal(data[:len(magic)], magic) {
		t.Fatalf("%s does not start with PNG magic", path)
	}
	if !strings.Contains(errOut.String(), path) {
		t.Fatalf("stderr does not mention the PNG path:\n%s", errOut.String())
	}
	if !strings.Contains(line, "ssh-ed25519") {
		t.Fatal("test key is not an SSH key")
	}
}

func TestCreateRejectsMultilineComment(t *testing.T) {
	setupFakeKeygen(t)
	app, _, _ := newTestApp(t)

	err := runCLI(t, app, "create", "--allow-unencrypted", "--base", t.TempDir(), "--comment", "two\nlines")
	if err == nil || !strings.Contains(err.Error(), "single line") {
		t.Fatalf("error = %v, want a single-line error", err)
	}
}

func TestShowText(t *testing.T) {
	dir, line, fingerprint := makeKeyDir(t)
	app, out, errOut := newTestApp(t)

	if err := runCLI(t, app, "show", dir, "--format", "text"); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), line+"\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if !strings.Contains(errOut.String(), fingerprint) {
		t.Fatalf("stderr does not contain the fingerprint:\n%s", errOut.String())
	}
}

func TestShowQRRequiresTTY(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, _, _ := newTestApp(t)

	if err := runCLI(t, app, "show", dir, "--format", "qr"); err == nil {
		t.Fatal("show --format qr succeeded without a terminal")
	}
}

func TestShowRejectsMismatchedKey(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	otherLine, _ := testKey(t)
	if err := os.WriteFile(filepath.Join(dir, keydir.PublicKeyName), []byte(otherLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app, out, _ := newTestApp(t)

	err := runCLI(t, app, "show", dir, "--format", "text")
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want a private/public mismatch error", err)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", out.String())
	}
}

func TestShowRejectsMissingPrivateKey(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	if err := os.Remove(filepath.Join(dir, keydir.PrivateKeyName)); err != nil {
		t.Fatal(err)
	}
	app, _, _ := newTestApp(t)

	if err := runCLI(t, app, "show", dir, "--format", "text"); err == nil {
		t.Fatal("show succeeded without a private key")
	}
}

func TestShowPNGRepeatable(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, out, _ := newTestApp(t)

	for run := 1; run <= 2; run++ {
		out.Reset()
		if err := runCLI(t, app, "show", dir, "--format", "png"); err != nil {
			t.Fatalf("show --format png run %d: %v", run, err)
		}
		path := filepath.Join(dir, keydir.PNGName)
		if got := strings.TrimSpace(out.String()); got != path {
			t.Fatalf("run %d stdout = %q, want %q", run, got, path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("run %d did not create the PNG: %v", run, err)
		}
	}
}

func TestEnv(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, out, _ := newTestApp(t)
	app.Getenv = func(key string) string {
		if key == "GIT_CONFIG_COUNT" {
			return "2"
		}
		return ""
	}

	if err := runCLI(t, app, "env", dir, "--name", "Kevin Tucker", "--email", "kevin@example.com"); err != nil {
		t.Fatal(err)
	}
	output := out.String()
	for _, want := range []string{
		"export KEY_DIR='" + dir + "'",
		"export KEY='" + filepath.Join(dir, keydir.PrivateKeyName) + "'",
		"export KEY_FINGERPRINT='",
		"export GIT_TERMINAL_PROMPT='0'",
		"export GIT_CONFIG_KEY_2='core.sshCommand'",
		"export GIT_CONFIG_COUNT='3'",
		"export GIT_AUTHOR_NAME='Kevin Tucker'",
		"export GIT_AUTHOR_EMAIL='kevin@example.com'",
		"export GIT_CONFIG_GLOBAL='/dev/null'",
		"export GIT_CONFIG_SYSTEM='/dev/null'",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output does not contain %q:\n%s", want, output)
		}
	}

	out.Reset()
	if err := runCLI(t, app, "env", dir, "--no-isolate-config"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "GIT_CONFIG_GLOBAL") {
		t.Fatalf("--no-isolate-config still isolated config:\n%s", out.String())
	}
}

func TestEnvValidation(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, _, _ := newTestApp(t)

	if err := runCLI(t, app, "env", dir, "--name", "Only Name"); err == nil {
		t.Fatal("env accepted --name without --email")
	}

	app.Getenv = func(key string) string {
		if key == "GIT_CONFIG_COUNT" {
			return "nope"
		}
		return ""
	}
	if err := runCLI(t, app, "env", dir); err == nil {
		t.Fatal("env accepted a non-numeric GIT_CONFIG_COUNT")
	}
}

func TestCleanupPrint(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, out, errOut := newTestApp(t)

	if err := runCLI(t, app, "cleanup", dir); err != nil {
		t.Fatal(err)
	}
	output := out.String()
	if !strings.Contains(output, "rm -i '"+filepath.Join(dir, keydir.PrivateKeyName)+"'") {
		t.Errorf("stdout does not contain the rm command:\n%s", output)
	}
	if !strings.Contains(output, "rmdir '"+dir+"'") {
		t.Errorf("stdout does not contain rmdir:\n%s", output)
	}
	if !strings.Contains(errOut.String(), "not revocation") {
		t.Errorf("stderr does not warn about revocation:\n%s", errOut.String())
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("cleanup without --remove deleted the directory: %v", err)
	}
}

func TestCleanupDefaultsToKeyDirEnv(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, out, _ := newTestApp(t)
	app.Getenv = func(key string) string {
		if key == "KEY_DIR" {
			return dir
		}
		return ""
	}

	if err := runCLI(t, app, "cleanup"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "rmdir '"+dir+"'") {
		t.Fatalf("stdout does not contain rmdir for $KEY_DIR:\n%s", out.String())
	}
}

func TestCleanupWithoutKeyDir(t *testing.T) {
	app, _, _ := newTestApp(t)
	err := runCLI(t, app, "cleanup")
	if err == nil || !strings.Contains(err.Error(), "KEY_DIR is not set") {
		t.Fatalf("error = %v, want a missing KEY_DIR error", err)
	}
}

func TestCleanupRemove(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, _, errOut := newTestApp(t)
	setInteractive(app)
	app.In = strings.NewReader("y\ny\n")

	if err := runCLI(t, app, "cleanup", dir, "--remove"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key directory still exists: %v", err)
	}
	if !strings.Contains(errOut.String(), "Removed: "+dir) {
		t.Errorf("stderr does not report removal:\n%s", errOut.String())
	}
}

func TestCleanupRemoveDeclined(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, _, _ := newTestApp(t)
	setInteractive(app)
	app.In = strings.NewReader("n\nn\n")

	if err := runCLI(t, app, "cleanup", dir, "--remove"); err == nil {
		t.Fatal("cleanup --remove succeeded even though every prompt was declined")
	}
	for _, name := range []string{keydir.PrivateKeyName, keydir.PublicKeyName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s was removed despite a declined prompt: %v", name, err)
		}
	}
}

func TestCleanupRemoveRequiresTTY(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, _, _ := newTestApp(t)

	if err := runCLI(t, app, "cleanup", dir, "--remove"); err == nil {
		t.Fatal("cleanup --remove succeeded without a terminal")
	}
}

func TestCleanupRemoveRequiresStderrTTY(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, _, _ := newTestApp(t)
	app.StdinIsTTY = true
	app.StderrIsTTY = false

	if err := runCLI(t, app, "cleanup", dir, "--remove"); err == nil {
		t.Fatal("cleanup --remove succeeded without a stderr terminal")
	}
	if _, err := os.Stat(filepath.Join(dir, keydir.PrivateKeyName)); err != nil {
		t.Fatalf("cleanup removed files without an interactive stderr: %v", err)
	}
}

func TestCleanupRemoveWithCapturedStdout(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, out, _ := newTestApp(t)
	app.StdinIsTTY = true
	app.StderrIsTTY = true
	app.StdoutIsTTY = false
	app.In = strings.NewReader("y\ny\n")

	if err := runCLI(t, app, "cleanup", dir, "--remove"); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty because prompts go to stderr", out.String())
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key directory still exists: %v", err)
	}
}

func TestCleanupRemovePromptWriteError(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, _, _ := newTestApp(t)
	app.StdinIsTTY = true
	app.StderrIsTTY = true
	app.In = strings.NewReader("y\ny\n")
	app.Err = errorWriter{err: errors.New("stderr closed")}

	err := runCLI(t, app, "cleanup", dir, "--remove")
	if err == nil || !strings.Contains(err.Error(), "cannot write prompt") {
		t.Fatalf("error = %v, want a prompt-write error", err)
	}
	if _, err := os.Stat(filepath.Join(dir, keydir.PrivateKeyName)); err != nil {
		t.Fatalf("cleanup removed files after a failed prompt: %v", err)
	}
}

func TestCleanupPrintWriteError(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	app, _, _ := newTestApp(t)
	app.Out = errorWriter{err: errors.New("stdout closed")}

	err := runCLI(t, app, "cleanup", dir)
	if err == nil || !strings.Contains(err.Error(), "cannot write cleanup commands") {
		t.Fatalf("error = %v, want a cleanup-write error", err)
	}
}

func TestCleanupUnexpectedFile(t *testing.T) {
	dir, _, _ := makeKeyDir(t)
	extra := filepath.Join(dir, "extra")
	if err := os.WriteFile(extra, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, _, _ := newTestApp(t)
	setInteractive(app)
	app.In = strings.NewReader("y\ny\ny\n")

	err := runCLI(t, app, "cleanup", dir, "--remove")
	if err == nil || !strings.Contains(err.Error(), "unexpected files") {
		t.Fatalf("error = %v, want an unexpected-files error", err)
	}
	if _, err := os.Stat(extra); err != nil {
		t.Fatalf("unexpected file was removed: %v", err)
	}
}

func TestShell(t *testing.T) {
	dir, _, fingerprint := makeKeyDir(t)
	app, _, _ := newTestApp(t)
	setInteractive(app)

	var gotPath string
	var gotArgv, gotEnv []string
	app.Exec = func(path string, argv, env []string) error {
		gotPath = path
		gotArgv = argv
		gotEnv = env
		return nil
	}

	if err := runCLI(t, app, "shell", dir, "--shell", "bash"); err != nil {
		t.Fatal(err)
	}
	if filepath.Base(gotPath) != "bash" {
		t.Errorf("exec path = %q, want bash", gotPath)
	}
	if strings.Join(gotArgv[1:], " ") != "--noprofile --norc" {
		t.Errorf("argv = %v, want bash --noprofile --norc", gotArgv)
	}
	env := envMap(gotEnv)
	if env["HISTFILE"] != "/dev/null" {
		t.Errorf("HISTFILE = %q, want /dev/null", env["HISTFILE"])
	}
	if env["HISTSIZE"] != "0" {
		t.Errorf("HISTSIZE = %q, want 0", env["HISTSIZE"])
	}
	if env["TEMP_SSH_KEY_ISOLATED"] != "1" {
		t.Errorf("TEMP_SSH_KEY_ISOLATED = %q, want 1", env["TEMP_SSH_KEY_ISOLATED"])
	}
	if env["KEY_DIR"] != dir {
		t.Errorf("KEY_DIR = %q, want %q", env["KEY_DIR"], dir)
	}
	if env["KEY"] != filepath.Join(dir, keydir.PrivateKeyName) {
		t.Errorf("KEY = %q, want the private key path", env["KEY"])
	}
	if env["KEY_FINGERPRINT"] != fingerprint {
		t.Errorf("KEY_FINGERPRINT = %q, want %q", env["KEY_FINGERPRINT"], fingerprint)
	}
	if !strings.Contains(env["GIT_SSH_COMMAND"], filepath.Join(dir, keydir.PrivateKeyName)) {
		t.Errorf("GIT_SSH_COMMAND does not use the temporary key: %q", env["GIT_SSH_COMMAND"])
	}
	if env["GIT_TERMINAL_PROMPT"] != "0" {
		t.Errorf("GIT_TERMINAL_PROMPT = %q, want 0", env["GIT_TERMINAL_PROMPT"])
	}
	if env["GIT_CONFIG_KEY_0"] != "core.sshCommand" || env["GIT_CONFIG_COUNT"] != "1" {
		t.Errorf("missing Git config override: KEY_0=%q COUNT=%q", env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_COUNT"])
	}
	if env["GIT_CONFIG_GLOBAL"] != "/dev/null" || env["GIT_CONFIG_SYSTEM"] != "/dev/null" {
		t.Errorf("Git config was not isolated: GLOBAL=%q SYSTEM=%q", env["GIT_CONFIG_GLOBAL"], env["GIT_CONFIG_SYSTEM"])
	}
}

func TestShellAlreadyIsolated(t *testing.T) {
	app, _, errOut := newTestApp(t)
	app.Getenv = func(key string) string {
		if key == "TEMP_SSH_KEY_ISOLATED" {
			return "1"
		}
		return ""
	}
	called := false
	app.Exec = func(string, []string, []string) error {
		called = true
		return nil
	}

	if err := runCLI(t, app, "shell"); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("shell nested inside an isolated shell")
	}
	if !strings.Contains(errOut.String(), "already in an isolated shell") {
		t.Fatalf("missing isolation note:\n%s", errOut.String())
	}
}

func TestShellWithoutKey(t *testing.T) {
	app, _, _ := newTestApp(t)
	setInteractive(app)
	app.LookPath = func(name string) (string, error) {
		if name == "zsh" {
			return "/bin/zsh", nil
		}
		return "", errors.New("unexpected lookup: " + name)
	}
	var gotEnv []string
	app.Exec = func(_ string, _ []string, env []string) error {
		gotEnv = env
		return nil
	}

	if err := runCLI(t, app, "shell", "--shell", "zsh"); err != nil {
		t.Fatal(err)
	}
	env := envMap(gotEnv)
	if _, ok := env["KEY_DIR"]; ok {
		t.Errorf("KEY_DIR was exported without a key directory: %q", env["KEY_DIR"])
	}
	if _, ok := env["KEY_FINGERPRINT"]; ok {
		t.Errorf("KEY_FINGERPRINT was exported without a key directory: %q", env["KEY_FINGERPRINT"])
	}
	if env["SAVEHIST"] != "0" {
		t.Errorf("SAVEHIST = %q, want 0", env["SAVEHIST"])
	}
}

func TestStart(t *testing.T) {
	line, _ := setupFakeKeygen(t)
	app, out, errOut := newTestApp(t)
	setInteractive(app)
	var gotEnv []string
	app.Exec = func(_ string, _ []string, env []string) error {
		gotEnv = env
		return nil
	}

	if err := runCLI(t, app, "start", "--allow-unencrypted", "--format", "text", "--base", t.TempDir(),
		"--shell", "bash", "--name", "Kevin Tucker", "--email", "kevin@example.com"); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty because start replaces the process", out.String())
	}
	if !strings.Contains(errOut.String(), line) {
		t.Fatalf("stderr does not contain the public key:\n%s", errOut.String())
	}
	for _, want := range []string{"Next steps:", "cleanup --remove", "Revoke the key"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr does not contain %q:\n%s", want, errOut.String())
		}
	}
	env := envMap(gotEnv)
	dir := env["KEY_DIR"]
	if dir == "" {
		t.Fatal("start did not export KEY_DIR")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("started key directory is missing: %v", err)
	}
	if env["GIT_AUTHOR_NAME"] != "Kevin Tucker" || env["GIT_AUTHOR_EMAIL"] != "kevin@example.com" {
		t.Errorf("identity was not exported: NAME=%q EMAIL=%q", env["GIT_AUTHOR_NAME"], env["GIT_AUTHOR_EMAIL"])
	}
	if !strings.Contains(env["GIT_SSH_COMMAND"], filepath.Join(dir, keydir.PrivateKeyName)) {
		t.Errorf("GIT_SSH_COMMAND does not use the temporary key: %q", env["GIT_SSH_COMMAND"])
	}
	if env["GIT_TERMINAL_PROMPT"] != "0" {
		t.Errorf("GIT_TERMINAL_PROMPT = %q, want 0", env["GIT_TERMINAL_PROMPT"])
	}
	if env["GIT_CONFIG_GLOBAL"] != "/dev/null" {
		t.Errorf("GIT_CONFIG_GLOBAL = %q, want /dev/null by default", env["GIT_CONFIG_GLOBAL"])
	}
}

func TestStartNoIsolateConfig(t *testing.T) {
	setupFakeKeygen(t)
	app, _, errOut := newTestApp(t)
	setInteractive(app)
	var gotEnv []string
	app.Exec = func(_ string, _ []string, env []string) error {
		gotEnv = env
		return nil
	}

	if err := runCLI(t, app, "start", "--allow-unencrypted", "--format", "text", "--base", t.TempDir(),
		"--shell", "bash", "--no-isolate-config"); err != nil {
		t.Fatal(err)
	}
	env := envMap(gotEnv)
	if _, ok := env["GIT_CONFIG_GLOBAL"]; ok {
		t.Errorf("--no-isolate-config still exported GIT_CONFIG_GLOBAL=%q", env["GIT_CONFIG_GLOBAL"])
	}
	if strings.Contains(errOut.String(), "No --name/--email given") {
		t.Errorf("identity warning appeared despite --no-isolate-config:\n%s", errOut.String())
	}
}

func TestStartWarnsWhenIdentityMissing(t *testing.T) {
	setupFakeKeygen(t)
	app, _, errOut := newTestApp(t)
	setInteractive(app)
	app.Exec = func(string, []string, []string) error { return nil }

	if err := runCLI(t, app, "start", "--allow-unencrypted", "--format", "text", "--base", t.TempDir(),
		"--shell", "bash"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "No --name/--email given") {
		t.Fatalf("missing identity warning:\n%s", errOut.String())
	}
}

func TestStartRejectsHalfIdentity(t *testing.T) {
	app, _, _ := newTestApp(t)
	setInteractive(app)

	err := runCLI(t, app, "start", "--name", "Kevin Tucker")
	if err == nil || !strings.Contains(err.Error(), "must be given together") {
		t.Fatalf("error = %v, want an identity pairing error", err)
	}
}

func TestStartIsolated(t *testing.T) {
	app, _, _ := newTestApp(t)
	app.Getenv = func(key string) string {
		if key == "TEMP_SSH_KEY_ISOLATED" {
			return "1"
		}
		return ""
	}
	setInteractive(app)

	err := runCLI(t, app, "start")
	if err == nil || !strings.Contains(err.Error(), "create") {
		t.Fatalf("error = %v, want a direction to create", err)
	}
}

func TestStartRequiresTTY(t *testing.T) {
	app, _, _ := newTestApp(t)

	if err := runCLI(t, app, "start"); err == nil {
		t.Fatal("start succeeded without a terminal")
	}
}

func TestStartCleansUpWhenShellFails(t *testing.T) {
	setupFakeKeygen(t)
	app, _, _ := newTestApp(t)
	setInteractive(app)
	base := t.TempDir()
	app.LookPath = func(name string) (string, error) {
		if name == "zsh" {
			return "", errors.New("zsh is not installed")
		}
		return exec.LookPath(name)
	}

	err := runCLI(t, app, "start", "--allow-unencrypted", "--format", "text", "--base", base)
	if err == nil {
		t.Fatal("start succeeded without a shell")
	}
	entries, readErr := os.ReadDir(base)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("start left key material behind after the shell failed: %v", names)
	}
}

func TestStartCleansUpWhenSessionSetupFails(t *testing.T) {
	setupFakeKeygen(t)
	app, _, _ := newTestApp(t)
	setInteractive(app)
	base := t.TempDir()
	app.Getenv = func(key string) string {
		if key == "GIT_CONFIG_COUNT" {
			return "not-a-number"
		}
		return ""
	}

	err := runCLI(t, app, "start", "--allow-unencrypted", "--format", "text", "--base", base, "--shell", "bash")
	if err == nil {
		t.Fatal("start succeeded with an invalid GIT_CONFIG_COUNT")
	}
	entries, readErr := os.ReadDir(base)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("start left key material behind after session setup failed: %v", entries)
	}
}

func TestUnknownCommand(t *testing.T) {
	app, _, _ := newTestApp(t)
	if err := runCLI(t, app, "nope"); err == nil {
		t.Fatal("unknown command succeeded")
	}
}

func setupFakeKeygen(t *testing.T) (line, fingerprint string) {
	t.Helper()
	line, fingerprint = testKey(t)
	t.Setenv("FAKE_PUB", line)

	privateFile := filepath.Join(t.TempDir(), "fake-private-key")
	if err := os.WriteFile(privateFile, privateKeyContainer(t, line), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_PRIVATE", privateFile)

	binDir := t.TempDir()
	script := filepath.Join(binDir, "ssh-keygen")
	content := `#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -f) f="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$f" ] || exit 2
cat "$FAKE_PRIVATE" > "$f" || exit 2
printf '%s\n' "$FAKE_PUB" > "$f.pub"
chmod 600 "$f" "$f.pub"
`
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return line, fingerprint
}

func makeKeyDir(t *testing.T) (dir, line, fingerprint string) {
	t.Helper()
	var err error
	dir, err = keydir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	line, fingerprint = testKey(t)
	if err := os.WriteFile(filepath.Join(dir, keydir.PrivateKeyName), privateKeyContainer(t, line), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keydir.PublicKeyName), []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, line, fingerprint
}

// privateKeyContainer builds an OpenSSH private key file containing the public
// header. The parser only needs that header, so the private section is a
// placeholder.
func privateKeyContainer(t *testing.T, line string) []byte {
	t.Helper()
	fields := strings.Fields(line)
	if len(fields) < 2 {
		t.Fatalf("test key has no key data: %q", line)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	b.WriteString("openssh-key-v1\x00")
	for _, field := range []string{"none", "none", ""} {
		if err := binary.Write(&b, binary.BigEndian, uint32(len(field))); err != nil {
			t.Fatal(err)
		}
		b.WriteString(field)
	}
	if err := binary.Write(&b, binary.BigEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&b, binary.BigEndian, uint32(len(blob))); err != nil {
		t.Fatal(err)
	}
	b.Write(blob)
	if err := binary.Write(&b, binary.BigEndian, uint32(0)); err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: b.Bytes()})
}

func testKey(t *testing.T) (line, fingerprint string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	if err := binary.Write(&blob, binary.BigEndian, uint32(len("ssh-ed25519"))); err != nil {
		t.Fatal(err)
	}
	blob.WriteString("ssh-ed25519")
	if err := binary.Write(&blob, binary.BigEndian, uint32(len(pub))); err != nil {
		t.Fatal(err)
	}
	blob.Write(pub)

	sum := sha256.Sum256(blob.Bytes())
	fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	line = "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes()) + " test"
	return line, fingerprint
}

func parseAssignments(t *testing.T, output string) map[string]string {
	t.Helper()
	assignments := map[string]string{}
	for _, raw := range strings.Split(strings.TrimSpace(output), "\n") {
		if raw == "" {
			continue
		}
		key, value, ok := strings.Cut(raw, "=")
		if !ok {
			t.Fatalf("malformed assignment: %q", raw)
		}
		if len(value) < 2 || value[0] != '\'' || value[len(value)-1] != '\'' {
			t.Fatalf("assignment %q is not a single-quoted shell word", raw)
		}
		assignments[key] = strings.ReplaceAll(value[1:len(value)-1], `'\''`, "'")
	}
	return assignments
}

func envMap(env []string) map[string]string {
	result := make(map[string]string, len(env))
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			result[key] = value
		}
	}
	return result
}
