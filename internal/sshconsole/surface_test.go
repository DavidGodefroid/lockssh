//go:build unix

package sshconsole

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/ipc"

	"github.com/DavidGodefroid/lockssh/internal/config"
)

// The glob bypasses of docs/decisions.md, end to end: each one is refused
// with E_NOT_ALLOWED and nothing reaches the host.
func TestGlobBypassesNeverRun(t *testing.T) {
	r := newRig(t, rigOpts{allow: []string{"git log *", "journalctl *", "tar -tf *", "cat /var/log/*/*/*", "ls *", "less *", "echo **"}})
	before := len(r.host.received())
	for _, argv := range [][]string{
		{"git", "log", "--output=/home/u/.bashrc"},
		{"journalctl", "--vacuum-time=1s"},
		{"tar", "-tf", "--to-command=sh"},
		{"cat", "/var/log/../../etc/shadow"},
		{"ls", ".."},
		{"less", "+!id"},
		{"echo", "-e", "x"},
		{"echo", "a", "../b"},
	} {
		if code := refusedCode(t, r.call(MethodRun, Params{Argv: argv})); code != string(CodeNotAllowed) {
			t.Errorf("%q: %s", argv, code)
		}
	}
	if len(r.host.received()) != before {
		t.Fatalf("a refused command reached the host: %q", r.host.received()[before:])
	}
}

// argv[0] is never an option of exec, and a builtin named by argv[0] is
// looked up on the PATH by exec, never run as a builtin: the line always
// starts with exec.
func TestProgramIsNeverABuiltin(t *testing.T) {
	r := newRig(t, rigOpts{exec: true, answers: []string{"y"}})
	for _, argv := range [][]string{{"-c", "id"}, {"+x", "id"}} {
		if code := refusedCode(t, r.call(MethodRun, Params{Argv: argv})); code != string(CodeBadArgv) {
			t.Errorf("%q: %s", argv, code)
		}
	}
	out := output(t, r.call(MethodRun, Params{Argv: []string{"eval", "echo pwned"}}))
	if out.ExitStatus == nil || *out.ExitStatus != 127 || strings.Contains(out.Stdout, "pwned") {
		t.Errorf("eval: %+v", out)
	}
	got := r.host.received()
	if last := got[len(got)-1]; last != `exec 'eval' 'echo pwned'` {
		t.Errorf("line %q", last)
	}
	for _, l := range got {
		if !strings.HasPrefix(l, "exec ") {
			t.Errorf("line without exec: %q", l)
		}
	}
}

// Mask rules mask more, allow rules keep a named value in clear, a
// secret stays a secret; pii.list shows both, pii.add appends a mask rule
// to the file and applies it at once.
func TestPIIRules(t *testing.T) {
	r := newRig(t, rigOpts{pii: "[[mask]]\npattern = 'up [0-9]+ days'\n\n[[allow]]\nkind = \"ip\"\nvalue = \"8.8.8.8\"\n"})
	out := output(t, r.call(MethodRun, Params{Argv: []string{"uptime"}}))
	if strings.Contains(out.Stdout, "up 3 days") || !strings.Contains(out.Stdout, "8.8.8.8") ||
		strings.Contains(out.Stdout, "alice@") || strings.Contains(out.Stdout, "correct-horse") || out.Masked["mask"] != 1 {
		t.Errorf("masked %q %v", out.Stdout, out.Masked)
	}
	var list ipc.PIIListResult
	if err := json.Unmarshal([]byte(mustOK(t, r.call(ipc.MethodPIIList, nil))), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Mask) != 1 || list.Mask[0] != "up [0-9]+ days" || len(list.Allow) != 1 || list.Allow[0] != "ip:8.8.8.8" {
		t.Errorf("list %+v", list)
	}
	mustOK(t, r.call(ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "ops contact"}))
	out = output(t, r.call(MethodRun, Params{Argv: []string{"uptime"}}))
	if strings.Contains(out.Stdout, "ops contact") || out.Masked["mask"] != 2 {
		t.Errorf("after pii.add %q %v", out.Stdout, out.Masked)
	}
	raw, err := os.ReadFile(filepath.Join(r.root, ".lockssh", "pii.toml"))
	if err != nil || !strings.Contains(string(raw), "ops contact") {
		t.Errorf("file %q %v", raw, err)
	}
	// A rule that matches nothing or does not parse is refused.
	for _, bad := range []string{"", "x*", "("} {
		if resp := r.call(ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: bad}); resp.Error == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A write on production is never approved by an auto rule, even if a
// policy with auto.exec = auto were in force.
func TestProductionExecNeverAuto(t *testing.T) {
	r := newRig(t, rigOpts{})
	pr := config.Profile{Name: "prod", Exec: true, Auto: config.AutoRules{Exec: config.AutoAuto}}
	pr.Production = true
	pp := &prep{pol: Policy{config.NewPolicy(pr)}, argv: []string{"reboot"}, action: config.ActExec}
	if sc := r.be.screen(pp, ""); !sc.NeverAuto {
		t.Error("production exec may be auto-approved")
	}
	pr.Production = false
	pp.pol = Policy{config.NewPolicy(pr)}
	if sc := r.be.screen(pp, ""); sc.NeverAuto {
		t.Error("exec auto off production is never auto")
	}
}
