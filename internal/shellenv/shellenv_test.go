package shellenv

import (
	"strings"
	"testing"
)

func TestQuote(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "/tmp/temp-ssh-key.abc", want: "'/tmp/temp-ssh-key.abc'"},
		{name: "space", in: "a b", want: "'a b'"},
		{name: "single quote", in: "a'b", want: `'a'\''b'`},
		{name: "empty", in: "", want: "''"},
		{name: "dollar", in: "$HOME", want: "'$HOME'"},
		{name: "newline", in: "a\nb", want: "'a\nb'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Quote(tt.in); got != tt.want {
				t.Fatalf("Quote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExports(t *testing.T) {
	got := Exports(Options{
		KeyDir:        "/tmp/temp-ssh-key.abc",
		KeyPath:       "/tmp/temp-ssh-key.abc/id_ed25519",
		Fingerprint:   "SHA256:abc",
		Name:          "Kevin Tucker",
		Email:         "kevin@example.com",
		IsolateConfig: true,
	})

	wantLines := []string{
		"unset SSH_AUTH_SOCK",
		"unset SSH_ASKPASS",
		"unset SSH_ASKPASS_REQUIRE",
		"unset GIT_ASKPASS",
		"unset GIT_CONFIG_PARAMETERS",
		"unset GIT_CONFIG_COUNT",
		"unset GIT_DIR",
		"unset GIT_WORK_TREE",
		"unset GIT_COMMON_DIR",
		"unset GIT_INDEX_FILE",
		"unset GIT_OBJECT_DIRECTORY",
		"unset GIT_ALTERNATE_OBJECT_DIRECTORIES",
		"unset GIT_NAMESPACE",
		"unset GIT_SSH",
		"unset GIT_SSH_VARIANT",
		"export KEY_DIR='/tmp/temp-ssh-key.abc'",
		"export KEY='/tmp/temp-ssh-key.abc/id_ed25519'",
		"export KEY_FINGERPRINT='SHA256:abc'",
		`export GIT_SSH_COMMAND='ssh -F /dev/null -o IdentitiesOnly=yes -i '\''/tmp/temp-ssh-key.abc/id_ed25519'\'''`,
		"export GIT_TERMINAL_PROMPT='0'",
		"export GIT_CONFIG_KEY_0='core.sshCommand'",
		`export GIT_CONFIG_VALUE_0='ssh -F /dev/null -o IdentitiesOnly=yes -i '\''/tmp/temp-ssh-key.abc/id_ed25519'\'''`,
		"export GIT_CONFIG_COUNT='1'",
		"export GIT_AUTHOR_NAME='Kevin Tucker'",
		"export GIT_AUTHOR_EMAIL='kevin@example.com'",
		"export GIT_COMMITTER_NAME='Kevin Tucker'",
		"export GIT_COMMITTER_EMAIL='kevin@example.com'",
		"export GIT_CONFIG_GLOBAL='/dev/null'",
		"export GIT_CONFIG_SYSTEM='/dev/null'",
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != len(wantLines) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(wantLines), got)
	}
	for i, want := range wantLines {
		if lines[i] != want {
			t.Errorf("line %d = %q, want %q", i+1, lines[i], want)
		}
	}
}

func TestExportsNoIdentityOrIsolation(t *testing.T) {
	got := Exports(Options{
		KeyDir:  "/tmp/k",
		KeyPath: "/tmp/k/id_ed25519",
	})
	for _, forbidden := range []string{"KEY_FINGERPRINT", "GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("output unexpectedly contains %s:\n%s", forbidden, got)
		}
	}
	if !strings.Contains(got, "export GIT_CONFIG_KEY_0='core.sshCommand'\n") {
		t.Errorf("missing single config override:\n%s", got)
	}
	if !strings.Contains(got, "export GIT_CONFIG_COUNT='1'\n") {
		t.Errorf("missing config count:\n%s", got)
	}
}

func TestVarsOrder(t *testing.T) {
	vars := Vars(Options{
		KeyDir:        "/tmp/k",
		KeyPath:       "/tmp/k/id_ed25519",
		Fingerprint:   "SHA256:abc",
		Name:          "Kevin Tucker",
		Email:         "kevin@example.com",
		IsolateConfig: true,
	})
	var names []string
	for _, v := range vars {
		names = append(names, v.Name)
	}
	want := []string{
		"KEY_DIR", "KEY", "KEY_FINGERPRINT", "GIT_SSH_COMMAND", "GIT_TERMINAL_PROMPT",
		"GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_COUNT",
		"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL",
		"GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("Vars names = %v, want %v", names, want)
	}
}

func TestExportsUnsetsInheritedEnvironment(t *testing.T) {
	got := Exports(Options{KeyDir: "/tmp/k", KeyPath: "/tmp/k/id_ed25519"})
	for _, name := range []string{"SSH_AUTH_SOCK", "GIT_ASKPASS", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_DIR"} {
		if !strings.Contains(got, "unset "+name+"\n") {
			t.Errorf("output does not unset %s:\n%s", name, got)
		}
	}
}

func TestSanitize(t *testing.T) {
	in := []string{
		"PATH=/bin",
		"SSH_AUTH_SOCK=/tmp/agent.sock",
		"GIT_DIR=/somewhere/.git",
		"GIT_ASKPASS=/tmp/askpass",
		"GIT_SSH_COMMAND=ssh -i legitimate",
		"GIT_CONFIG_PARAMETERS='core.sshCommand=evil'",
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=core.pager",
		"GIT_CONFIG_VALUE_0=/tmp/evil",
		"GIT_CONFIG_KEY_9=core.hooksPath",
		"GIT_CONFIG_VALUE_9=/tmp/hooks",
		"GIT_CONFIG_KEY=keep",
		"GIT_TRACE=1",
		"GIT_DIR", // malformed entry without '='
	}
	got := Sanitize(in)
	want := []string{
		"PATH=/bin",
		"GIT_SSH_COMMAND=ssh -i legitimate",
		"GIT_CONFIG_KEY=keep",
		"GIT_TRACE=1",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Sanitize() = %q, want %q", got, want)
	}
	if len(in) != 14 || in[1] != "SSH_AUTH_SOCK=/tmp/agent.sock" {
		t.Fatal("Sanitize modified its input")
	}
}

func TestIsIsolated(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{name: "marker", env: map[string]string{"TEMP_SSH_KEY_ISOLATED": "1"}, want: true},
		{name: "zsh history", env: map[string]string{"HISTFILE": "/dev/null", "SAVEHIST": "0"}, want: true},
		{name: "bash history", env: map[string]string{"HISTFILE": "/dev/null", "HISTSIZE": "0"}, want: true},
		{name: "normal", env: map[string]string{"HISTFILE": "/home/me/.zsh_history"}, want: false},
		{name: "empty", env: map[string]string{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string { return tt.env[key] }
			if got := IsIsolated(getenv); got != tt.want {
				t.Fatalf("IsIsolated() = %v, want %v", got, tt.want)
			}
		})
	}
}
