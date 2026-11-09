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
	got, err := Exports(Options{
		KeyDir:        "/tmp/temp-ssh-key.abc",
		KeyPath:       "/tmp/temp-ssh-key.abc/id_ed25519",
		Fingerprint:   "SHA256:abc",
		Name:          "Kevin Tucker",
		Email:         "kevin@example.com",
		IsolateConfig: true,
		ConfigCount:   "2",
	})
	if err != nil {
		t.Fatal(err)
	}

	wantLines := []string{
		"export KEY_DIR='/tmp/temp-ssh-key.abc'",
		"export KEY='/tmp/temp-ssh-key.abc/id_ed25519'",
		"export KEY_FINGERPRINT='SHA256:abc'",
		`export GIT_SSH_COMMAND='ssh -F /dev/null -o IdentitiesOnly=yes -i '\''/tmp/temp-ssh-key.abc/id_ed25519'\'''`,
		"export GIT_TERMINAL_PROMPT='0'",
		"export GIT_CONFIG_KEY_2='core.sshCommand'",
		`export GIT_CONFIG_VALUE_2='ssh -F /dev/null -o IdentitiesOnly=yes -i '\''/tmp/temp-ssh-key.abc/id_ed25519'\'''`,
		"export GIT_CONFIG_COUNT='3'",
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
	got, err := Exports(Options{
		KeyDir:  "/tmp/k",
		KeyPath: "/tmp/k/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"KEY_FINGERPRINT", "GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("output unexpectedly contains %s:\n%s", forbidden, got)
		}
	}
	if !strings.Contains(got, "export GIT_CONFIG_KEY_0='core.sshCommand'\n") {
		t.Errorf("missing zero-count override:\n%s", got)
	}
	if !strings.Contains(got, "export GIT_CONFIG_COUNT='1'\n") {
		t.Errorf("missing incremented count:\n%s", got)
	}
}

func TestVarsOrder(t *testing.T) {
	vars, err := Vars(Options{
		KeyDir:        "/tmp/k",
		KeyPath:       "/tmp/k/id_ed25519",
		Fingerprint:   "SHA256:abc",
		Name:          "Kevin Tucker",
		Email:         "kevin@example.com",
		IsolateConfig: true,
		ConfigCount:   "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, v := range vars {
		names = append(names, v.Name)
	}
	want := []string{
		"KEY_DIR", "KEY", "KEY_FINGERPRINT", "GIT_SSH_COMMAND", "GIT_TERMINAL_PROMPT",
		"GIT_CONFIG_KEY_1", "GIT_CONFIG_VALUE_1", "GIT_CONFIG_COUNT",
		"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL",
		"GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("Vars names = %v, want %v", names, want)
	}
}

func TestExportsRejectsInvalidConfigCount(t *testing.T) {
	for _, raw := range []string{"abc", "-1", "+1", "1.5", " 1"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := Exports(Options{ConfigCount: raw}); err == nil {
				t.Fatalf("Exports accepted GIT_CONFIG_COUNT=%q", raw)
			}
		})
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
