//go:build lockfamily_managed_test

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"
)

const managedBody = `version = 1
organisation = "Example Corp"

[lockssh.bounds]
exec = false
hosts = ["*.example.com"]
limits.max_session = "4h"

[lockssh.defaults]
known_hosts = "/etc/lockfamily/known_hosts"

[lockssh.profiles.prod-web]
host = "web.example.com"
user = "ops"
key = "/etc/lockfamily/id"
production = true
allow = ["uptime"]
`

// withManaged writes body as the managed file in root (so that golden
// replaces its path with $ROOT) and makes managed.Load read it.
func withManaged(t *testing.T, root, body string) {
	t.Helper()
	path := filepath.Join(root, managed.FileName)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	managed.SetTestPath(path)
	t.Cleanup(func() { managed.SetTestPath("") })
}

// managed show, managed check and doctor's managed line, as lox and the
// human read them: a change of a line or an exit code shows here first.
func TestGoldenManaged(t *testing.T) {
	t.Setenv("LOCKSSH_INSTANCE", "")
	t.Setenv("LEA_LOCKSSH_INSTANCES", "")
	for _, c := range []struct {
		name, body, profiles string
		args                 []string
		code                 int
	}{
		{"managed-show-none", "", oneProfile, []string{"managed", "show"}, exitOK},
		{"managed-show", managedBody, oneProfile, []string{"managed", "show"}, exitOK},
		{"managed-show-refused", "version = 2\n", oneProfile, []string{"managed", "show"}, exitUsage},
		{"managed-check-none", "", oneProfile, []string{"managed", "check"}, exitOK},
		{"managed-check-ok", managedBody, oneProfile, []string{"managed", "check"}, exitOK},
		{"managed-check-blocked", managedBody, oneProfile + "exec = true\n[profiles.evil]\nhost = \"evil.test\"\nuser = \"u\"\nkey = \"k\"\n",
			[]string{"managed", "check"}, exitUsage},
		{"managed-check-one", managedBody, oneProfile + "[profiles.evil]\nhost = \"evil.test\"\nuser = \"u\"\nkey = \"k\"\n",
			[]string{"managed", "check", "--profile", "dev"}, exitOK},
		{"managed-check-redefined", managedBody, strings.Replace(oneProfile, "[profiles.dev]", "[profiles.prod-web]", 1),
			[]string{"managed", "check"}, exitUsage},
		{"managed-check-refused", "version = 2\n", oneProfile, []string{"managed", "check"}, exitUsage},
		{"doctor-managed", managedBody, oneProfile, []string{"doctor", "--json"}, exitOK},
		{"doctor-managed-refused", "version = 2\n", oneProfile, []string{"doctor", "--json"}, exitUsage},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := project(t, c.profiles)
			managed.SetTestPath("")
			if c.body != "" {
				withManaged(t, root, c.body)
			}
			code, out, stderr := runWith(t, root, nil, os.ErrNotExist, "", c.args...)
			if code != c.code {
				t.Fatalf("exit %d, want %d: %s%s", code, c.code, out, stderr)
			}
			got := out
			if stderr != "" {
				got += "stderr: " + stderr
			}
			golden(t, c.name, root, got)
		})
	}
}
