//go:build unix

package sshconsole

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
)

// An allow-listed command runs at once: its argv reaches the host quoted,
// its output comes back masked (pseudonyms for the email and the public
// IP, ⟦secret⟧ for the token), and the audit log names the command, never
// the output.
func TestAllowListedRunsMasked(t *testing.T) {
	r := newRig(t, rigOpts{})
	out := output(t, r.call(MethodRun, Params{Argv: []string{"uptime"}}))
	if out.ExitStatus == nil || *out.ExitStatus != 0 || out.Action != "run" || out.Rule != "uptime" || r.io.promptCount() != 0 {
		t.Fatalf("output %+v prompts %d", out, r.io.promptCount())
	}
	if strings.Contains(out.Stdout, "alice@example.com") || strings.Contains(out.Stdout, "8.8.8.8") || strings.Contains(out.Stdout, "correct-horse") {
		t.Fatalf("clear value in %q", out.Stdout)
	}
	if !regexp.MustCompile(`⟦email:[0-9A-Z]{12}⟧`).MatchString(out.Stdout) || !regexp.MustCompile(`⟦ip:[0-9A-Z]{12}⟧`).MatchString(out.Stdout) ||
		!strings.Contains(out.Stdout, "⟦secret⟧") || out.Masked["email"] != 1 || out.Masked["ip"] != 1 {
		t.Errorf("masked output %q %v", out.Stdout, out.Masked)
	}
	// The same value is the same pseudonym within the console run.
	again := output(t, r.call(MethodRun, Params{Argv: []string{"uptime"}}))
	if again.Stdout != out.Stdout {
		t.Errorf("pseudonyms moved: %q vs %q", again.Stdout, out.Stdout)
	}
	got := r.host.received()
	if len(got) < 2 || got[len(got)-1] != "'uptime'" {
		t.Errorf("lines %q", got)
	}
	log := r.auditLog()
	if !strings.Contains(log, `"command":"uptime"`) || !strings.Contains(log, `"auto_rule":"auto.run=auto"`) || strings.Contains(log, "alice") || strings.Contains(log, "up 3 days") {
		t.Errorf("audit:\n%s", log)
	}
}

// There is no shell: what looks like shell syntax is passed as literal
// arguments, quoted.
func TestShellSyntaxIsLiteral(t *testing.T) {
	r := newRig(t, rigOpts{})
	argv := []string{"echo", "a; rm -rf /", "$(id)", "it's", "`x`", "|", ">f"}
	out := output(t, r.call(MethodRun, Params{Argv: argv}))
	if out.Stdout != "a; rm -rf / $(id) it's `x` | >f\n" {
		t.Errorf("stdout %q", out.Stdout)
	}
	got := r.host.received()
	if want := `'echo' 'a; rm -rf /' '$(id)' 'it'\''s' '` + "`x`" + `' '|' '>f'`; got[len(got)-1] != want {
		t.Errorf("line %q, want %q", got[len(got)-1], want)
	}
}

// Outside the allow list with exec off, nothing runs: E_NOT_ALLOWED,
// audited as a refusal.
func TestNotAllowedRefused(t *testing.T) {
	r := newRig(t, rigOpts{})
	before := len(r.host.received())
	for _, argv := range [][]string{{"rm", "-rf", "/"}, {"systemctl", "restart", "nginx"}, {"echoX"}, {"uptime", "-p"}} {
		if code := refusedCode(t, r.call(MethodRun, Params{Argv: argv})); code != string(CodeNotAllowed) {
			t.Errorf("%v: %s", argv, code)
		}
	}
	if len(r.host.received()) != before {
		t.Fatal("a refused command reached the host")
	}
	if !strings.Contains(r.auditLog(), `"code":"E_NOT_ALLOWED"`) {
		t.Error("refusal not audited")
	}
}

// A glob matches one argument and never crosses "/".
func TestGlobRules(t *testing.T) {
	r := newRig(t, rigOpts{allow: []string{"cat /var/log/*"}})
	output(t, r.call(MethodRun, Params{Argv: []string{"cat", "/var/log/syslog"}}))
	for _, argv := range [][]string{{"cat", "/var/log/../../etc/shadow"}, {"cat", "/var/log/a", "/etc/shadow"}, {"cat"}} {
		if code := refusedCode(t, r.call(MethodRun, Params{Argv: argv})); code != string(CodeNotAllowed) {
			t.Errorf("%v: %s", argv, code)
		}
	}
}

func TestBadArgv(t *testing.T) {
	r := newRig(t, rigOpts{})
	for _, argv := range [][]string{nil, {""}, {"echo", "a\nb"}, {"echo", "a\x00b"}, {"echo", "\u202eevil"}} {
		if code := refusedCode(t, r.call(MethodRun, Params{Argv: argv})); code != string(CodeBadArgv) {
			t.Errorf("%q: %s", argv, code)
		}
	}
}

// A failing command answers its exit status and its masked stderr; a long
// output is cut at max_output_bytes; a command past request_timeout is
// killed and answers timed_out.
func TestExitStatusCapsAndTimeout(t *testing.T) {
	r := newRig(t, rigOpts{extra: "[profiles.uat.limits]\nrequest_timeout = \"1s\"\nmax_output_bytes = 1024\n"})
	out := output(t, r.call(MethodRun, Params{Argv: []string{"fail"}}))
	if out.ExitStatus == nil || *out.ExitStatus != 3 || strings.Contains(out.Stderr, "bob@") || !strings.Contains(out.Stderr, "⟦email:") {
		t.Errorf("fail: %+v", out)
	}
	out = output(t, r.call(MethodRun, Params{Argv: []string{"big"}}))
	if len(out.Stdout) != 1024 || !out.StdoutTruncated {
		t.Errorf("big: %d bytes, truncated %t", len(out.Stdout), out.StdoutTruncated)
	}
	out = output(t, r.call(MethodRun, Params{Argv: []string{"sleep", "60"}}))
	if !out.TimedOut || out.ExitStatus != nil || out.DurationMS > 5000 {
		t.Errorf("sleep: %+v", out)
	}
	// The session still serves the next command.
	output(t, r.call(MethodRun, Params{Argv: []string{"uptime"}}))
}

// A command outside the allow list on a profile with exec on waits for a
// decision (here a console without a hub: the terminal), then runs.
func TestExecAsksThenRuns(t *testing.T) {
	r := newRig(t, rigOpts{exec: true, answers: []string{"y"}})
	out := output(t, r.call(MethodRun, Params{Argv: []string{"reboot"}, Intent: "the kernel was upgraded"}))
	if out.Action != "exec" || out.Rule != "" || r.io.promptCount() != 1 {
		t.Fatalf("output %+v prompts %d", out, r.io.promptCount())
	}
	if !strings.Contains(r.io.output(), "RUN reboot") || !strings.Contains(r.io.output(), "no allow rule matches") {
		t.Errorf("screen:\n%s", r.io.output())
	}
	// Denied: nothing runs.
	before := len(r.host.received())
	if resp := r.call(MethodRun, Params{Argv: []string{"reboot"}}); resp.Error == nil {
		t.Fatalf("ran without an answer: %s", resp.Result)
	}
	if len(r.host.received()) != before {
		t.Fatal("a denied command reached the host")
	}
}

// Clear output needs the console's switch, then its own decision.
func TestUnmask(t *testing.T) {
	r := newRig(t, rigOpts{})
	if code := refusedCode(t, r.call(MethodRun, Params{Argv: []string{"uptime"}, Unmask: true})); code != string(CodeUnmaskOff) {
		t.Errorf("code %s", code)
	}
	r = newRig(t, rigOpts{allowUnmask: true, answers: []string{"y"}})
	out := output(t, r.call(MethodRun, Params{Argv: []string{"uptime"}, Unmask: true}))
	if !out.Unmasked || !strings.Contains(out.Stdout, "alice@example.com") || r.io.promptCount() != 1 {
		t.Errorf("unmask: %+v prompts %d", out, r.io.promptCount())
	}
	if !strings.Contains(r.auditLog(), `"unmasked":true`) {
		t.Error("unmasked run not audited as such")
	}
}

// Auto rules: deny refuses before anything runs; ask puts an allow-listed
// command behind a decision.
func TestAutoRules(t *testing.T) {
	r := newRig(t, rigOpts{extra: "[profiles.uat.auto]\nrun = \"deny\"\n"})
	if code := refusedCode(t, r.call(MethodRun, Params{Argv: []string{"uptime"}})); code != string(CodeAutoDenied) {
		t.Errorf("deny: %s", code)
	}
	r = newRig(t, rigOpts{extra: "[profiles.uat.auto]\nrun = \"ask\"\n", answers: []string{"y"}})
	output(t, r.call(MethodRun, Params{Argv: []string{"uptime"}}))
	if r.io.promptCount() != 1 {
		t.Errorf("ask: prompts %d", r.io.promptCount())
	}
}

// op.plan says what op.run would do, running nothing.
func TestPlan(t *testing.T) {
	r := newRig(t, rigOpts{exec: true})
	before := len(r.host.received())
	for argv, want := range map[string]string{"uptime": "run", "reboot": "prompt", "": "refused"} {
		p := Params{}
		if argv != "" {
			p.Argv = []string{argv}
		}
		var plan Plan
		if err := json.Unmarshal([]byte(mustOK(t, r.call(MethodPlan, p))), &plan); err != nil || plan.Verdict != want {
			t.Errorf("%q: %+v %v", argv, plan, err)
		}
	}
	if len(r.host.received()) != before {
		t.Fatal("op.plan ran a command")
	}
}

// A root login is a finding of the account check; status reports the host
// key and the uid.
func TestChecksAndStatus(t *testing.T) {
	r := newRig(t, rigOpts{})
	if f := r.be.Checks(context.Background(), nil); len(f) != 0 {
		t.Errorf("findings %+v", f)
	}
	st, _ := json.Marshal(r.be.Status(nil))
	if !strings.Contains(string(st), `"uid":"1000"`) || !strings.Contains(string(st), `"host_key":"SHA256:`) || !strings.Contains(string(st), `"allow":[`) {
		t.Errorf("status %s", st)
	}
	r.host.mu.Lock()
	r.host.uid = "0"
	r.host.mu.Unlock()
	sess, err := r.be.Connect(context.Background(), console.Credentials{User: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if f := r.be.Checks(context.Background(), sess); len(f) != 1 || !strings.Contains(f[0].Text, "root") {
		t.Errorf("root findings %+v", f)
	}
}

// With the console account's known_hosts, an unknown host key is trusted
// only on the human's answer, then recorded; with a known_hosts file the
// profile names, a key it does not hold is refused.
func TestHostKeyTrust(t *testing.T) {
	r := newRig(t, rigOpts{tofu: true, answers: []string{"yes"}})
	if !strings.Contains(r.io.output(), "can't be established") {
		t.Errorf("no host key question:\n%s", r.io.output())
	}
	if data, err := os.ReadFile(filepath.Join(r.home, ".ssh", "known_hosts")); err != nil || !strings.Contains(string(data), "ssh-ed25519") {
		t.Errorf("not recorded: %q %v", data, err)
	}
	// Refused without the answer.
	be, err := New(Options{Profile: "uat", Root: r.root, StateDir: t.TempDir(), IO: &fakeIO{}, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	home := be.o.Home
	clientKeyCopy(t, r.home, home)
	if _, err := be.Connect(context.Background(), console.Credentials{User: "deploy"}); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("unanswered: %v", err)
	}
	// A pinned file without the key refuses it.
	kh := filepath.Join(t.TempDir(), "known_hosts")
	os.WriteFile(kh, nil, 0o600)
	cfg, _ := os.ReadFile(filepath.Join(r.root, ".lockssh", "config.toml"))
	os.WriteFile(filepath.Join(r.root, ".lockssh", "config.toml"), append(cfg, []byte("known_hosts = \""+kh+"\"\n")...), 0o600)
	be, _ = New(Options{Profile: "uat", Root: r.root, StateDir: t.TempDir(), IO: &fakeIO{answers: []string{"yes"}}, Home: home})
	if _, err := be.Connect(context.Background(), console.Credentials{User: "deploy"}); err == nil {
		t.Error("a key the pinned file does not hold was accepted")
	}
}

func clientKeyCopy(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(from, ".ssh", "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(to, ".ssh"), 0o700)
	if err := os.WriteFile(filepath.Join(to, ".ssh", "id_ed25519"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// With results on, a masked output is also shown in clear on the console,
// never to the client.
func TestShowResults(t *testing.T) {
	r := newRig(t, rigOpts{showResults: true})
	out := output(t, r.call(MethodRun, Params{Argv: []string{"uptime"}}))
	if strings.Contains(out.Stdout, "alice") || !strings.Contains(r.io.output(), "alice@example.com") {
		t.Errorf("client %q console:\n%s", out.Stdout, r.io.output())
	}
}

var _ = ipc.CodeRefused
