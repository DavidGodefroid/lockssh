//go:build integration && lockfamily_managed_test && unix

package sshconsole

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/managed"

	"github.com/DavidGodefroid/lockssh/internal/product"
)

// The managed configuration against a real OpenSSH server: a profile
// beyond [lockssh.bounds] is refused before any prompt; one within them
// runs, its audit records carry the managed fingerprint, and a loosening
// beyond the bounds while it runs is refused at the next poll, never
// pending; a managed profile with its known_hosts connects and runs an
// allowed command, and a project profile of its name fails the load.
//
//	go test -tags 'integration lockfamily_managed_test' -run TestOpenSSH ./internal/sshconsole/
func TestOpenSSHManaged(t *testing.T) {
	home := t.TempDir()
	tun, port := openSSH(t, home, "lockssh-it-sshd-managed")
	tun.Close()
	kh := filepath.Join(home, "known_hosts")
	target := "host = \"127.0.0.1\"\nport = " + strconv.Itoa(port) + "\nuser = \"deploy\"\nkey = \"~/.ssh/id_ed25519\"\nknown_hosts = \"" + kh + "\"\nallow = [\"id -un\"]\n"
	useManaged(t, "[lockssh.bounds]\nexec = false\n\n[lockssh.profiles.managed-web]\n"+target)
	mf, err := managed.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	root, state := t.TempDir(), t.TempDir()
	cfg := filepath.Join(root, ".lockssh", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	io := &fakeIO{}
	backend := func(profile string) *Backend {
		t.Helper()
		be, err := New(Options{Profile: profile, Root: root, StateDir: state, IO: io, Home: home})
		if err != nil {
			t.Fatal(err)
		}
		return be
	}

	// exec = true beyond exec = false: refused at start, no prompt.
	write("[profiles.uat]\n" + target + "exec = true\n")
	be := backend("uat")
	pol, err := be.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	err = console.CheckManaged(product.P, be, pol, mf)
	if !strings.Contains(strings.Join(console.ManagedLines(err), "\n"), "blocked by company policy: lockssh.bounds.exec = false (profile uat: exec = true)") || io.promptCount() != 0 {
		t.Fatalf("exec = true: %v, %d prompts", err, io.promptCount())
	}

	// exec = false: it runs under the managed file.
	write("[profiles.uat]\n" + target)
	srv := serve(t, backend("uat"), state, io, mf)
	if out := output(t, srv.Handle(context.Background(), runReq("id", "-un"))); strings.TrimSpace(out.Stdout) != "deploy" {
		t.Errorf("id -un: %+v", out)
	}
	log, _ := os.ReadFile(filepath.Join(state, product.P.Name, "audit.log"))
	if !strings.Contains(string(log), mf.Fingerprint) {
		t.Errorf("the audit records do not carry the managed fingerprint:\n%s", log)
	}
	// Edited to exec = true while it runs: refused at the next poll.
	write("[profiles.uat]\n" + target + "exec = true\n")
	srv.CheckPolicy()
	if !srv.PolicyRefused() || srv.PolicyPending() || srv.Policy().(Policy).Policy.Profile.Exec {
		t.Errorf("refused %v pending %v", srv.PolicyRefused(), srv.PolicyPending())
	}
	if log, _ := os.ReadFile(filepath.Join(state, product.P.Name, "audit.log")); !strings.Contains(string(log), console.DecisionRefusedManaged) {
		t.Errorf("no %s record:\n%s", console.DecisionRefusedManaged, log)
	}

	// The managed profile, with its known_hosts, connects and runs.
	write("[profiles.uat]\n" + target)
	srv = serve(t, backend("managed-web"), state, io, mf)
	if out := output(t, srv.Handle(context.Background(), runReq("id", "-un"))); strings.TrimSpace(out.Stdout) != "deploy" {
		t.Errorf("managed profile: %+v", out)
	}
	// A project profile of the managed name fails the load.
	write("[profiles.managed-web]\n" + target)
	if _, err := backend("managed-web").LoadPolicy(); err == nil || !strings.Contains(err.Error(), `"managed-web"`) {
		t.Errorf("a project profile of a managed name: %v", err)
	}
}

// serve connects be and returns its server under the managed file mf,
// re-read at every poll as console.Run does.
func serve(t *testing.T, be *Backend, state string, io console.IO, mf *managed.File) *console.Server {
	t.Helper()
	pol, err := be.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if err := console.CheckManaged(product.P, be, pol, mf); err != nil {
		t.Fatal(err)
	}
	sess, err := be.Connect(context.Background(), console.Credentials{User: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	log, err := audit.Open(product.P, state)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := console.NewServer(console.ServerConfig{Product: product.P, Backend: be, Policy: pol, Session: sess,
		Audit: log, IO: io, Sanitizer: Sanitizer(), Managed: mf, LoadManaged: managed.Load})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func runReq(argv ...string) ipc.Request {
	raw, _ := json.Marshal(Params{Argv: argv})
	return ipc.Request{JSONRPC: "2.0", ID: 7, Method: MethodRun, Params: raw}
}
