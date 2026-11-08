package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockssh/internal/mcptools"
)

// update rewrites the golden files: go test ./cmd/lockssh -run TestGolden -update
var update = flag.Bool("update", false, "rewrite the golden files of testdata/")

// golden compares got with testdata/NAME.golden, after replacing what
// changes from run to run (the project's temporary directory, the build
// version, the uid) with $ROOT, $VERSION and $UID.
func golden(t *testing.T, name, root, got string) {
	t.Helper()
	if root != "" {
		got = strings.ReplaceAll(got, root, "$ROOT")
	}
	got = strings.ReplaceAll(got, `"version":"`+version+`"`, `"version":"$VERSION"`)
	got = strings.ReplaceAll(got, "uid "+strconv.Itoa(os.Getuid()), "uid $UID")
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to write it)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from %s:\ngot:\n%s\nwant:\n%s", name, path, got, want)
	}
}

// The JSON of each launcher verb that lox add and lea read, line for line:
// a change to a key, a code or a check name shows here first.
func TestGoldenVerbsJSON(t *testing.T) {
	// The instance comes from the environment only when a test sets it.
	t.Setenv("LOCKSSH_INSTANCE", "")
	t.Setenv("LEA_LOCKSSH_INSTANCES", "")
	for _, c := range []struct {
		name     string
		profiles string
		dialErr  error
		args     []string
		code     int
	}{
		{"version", "", nil, []string{"version", "--json"}, exitOK},
		{"profile-add", oneProfile, nil, []string{"profile", "add", "--non-interactive", "--json", "--profile", "web",
			"--production", "--credentials", "vault", "--vault-path", "secret/data/lockssh/web", "--host", "web1.example.com",
			"--port", "2222", "--user", "ro", "--key", "~/.ssh/lockssh", "--known-hosts", "~/.ssh/known_hosts", "--allow", "uptime"}, exitOK},
		{"profile-add-key", "", nil, []string{"profile", "add", "--non-interactive", "--json", "--credentials", "none",
			"--host", "web1", "--user", "deploy", "--auth", "key", "--key", "~/.ssh/id_ed25519"}, exitOK},
		{"profile-add-exists", oneProfile, nil, []string{"profile", "add", "--non-interactive", "--json", "--profile", "dev",
			"--host", "web1", "--user", "deploy", "--key", "~/.ssh/id"}, exitUsage},
		{"profile-add-secret", "", nil, []string{"profile", "add", "--non-interactive", "--json",
			"--host", "web1", "--user", "deploy", "--key", "~/.ssh/id", "--password", "glsa_CanarySecret"}, exitUsage},
		{"profile-add-usage", "", nil, []string{"profile", "add", "--non-interactive", "--json", "--user", "deploy"}, exitUsage},
		{"profile-rules", oneProfile + "[profiles.prod]\nhost = \"h\"\nuser = \"u\"\nkey = \"k\"\nproduction = true\n[profiles.prod.auto]\nexec = \"deny\"\n",
			nil, []string{"profile", "rules", "--json"}, exitOK},
		{"doctor", oneProfile, os.ErrNotExist, []string{"doctor", "--json"}, exitOK},
		{"doctor-no-profile", "", os.ErrNotExist, []string{"doctor", "--json"}, exitUsage},
		{"doctor-usage", oneProfile, os.ErrNotExist, []string{"doctor", "--json", "--yes"}, exitUsage},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := project(t, c.profiles)
			code, out, stderr := runWith(t, root, nil, c.dialErr, "", c.args...)
			if code != c.code {
				t.Fatalf("exit %d, want %d: %s", code, c.code, stderr)
			}
			if strings.Count(out, "\n") != 1 {
				t.Fatalf("stdout is not one line: %q", out)
			}
			if strings.Contains(out+stderr, "glsa_Canary") {
				t.Fatalf("echoed the secret: %q %q", out, stderr)
			}
			golden(t, c.name, root, out)
		})
	}
}

// doctor --fix --yes --json, as lox add runs it: the repair it made in
// fixed, the checks after it.
func TestGoldenDoctorFixJSON(t *testing.T) {
	t.Setenv("LOCKSSH_INSTANCE", "")
	t.Setenv("LEA_LOCKSSH_INSTANCES", "")
	root := project(t, oneProfile)
	var out, errb bytes.Buffer
	e := containerEnv(t, root, "", &out, &errb)
	e.svc = func(name string) (svcAccount, bool) {
		return svcAccount{name: "lockssh", uid: os.Getuid() + 7}, name == "lockssh"
	}
	e.euid = func() int { return 0 }
	e.root = func(string) error { return os.Chmod(filepath.Join(root, ".lockssh"), 0o755) }
	e.dial = func(string) (mcptools.Conn, error) { return nil, os.ErrNotExist }
	if err := os.Chmod(filepath.Join(root, ".lockssh"), 0o775); err != nil {
		t.Fatal(err)
	}
	if code := run(e, []string{"doctor", "--fix", "--yes", "--json"}); code != exitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	golden(t, "doctor-fix", root, out.String())
}

// init claude, as lox add runs it: what it wrote, then the same files left
// as they are on a second run.
func TestGoldenInit(t *testing.T) {
	root := project(t, oneProfile)
	for _, name := range []string{"init-claude", "init-claude-again"} {
		code, out, stderr := runWith(t, root, nil, nil, "", "init", "claude")
		if code != exitOK {
			t.Fatalf("%s: exit %d: %s", name, code, stderr)
		}
		golden(t, name, root, out)
	}
}
