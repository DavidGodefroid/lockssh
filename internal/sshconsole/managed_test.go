//go:build unix && lockfamily_managed_test

package sshconsole

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/managed"

	"github.com/DavidGodefroid/lockssh/internal/product"
)

// useManaged makes managed.Load read a managed file of body (after the
// version header) for the test.
func useManaged(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), managed.FileName)
	if err := os.WriteFile(path, []byte("version = 1\norganisation = \"Example Corp\"\n\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	managed.SetTestPath(path)
	t.Cleanup(func() { managed.SetTestPath("") })
	return path
}

func checkManaged(t *testing.T, r *rig) error {
	t.Helper()
	pol, err := r.be.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	f, err := managed.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return console.CheckManaged(product.P, r.be, pol, f)
}

// The console's start check: a profile beyond [lockssh.bounds] is refused
// with the citing line, an allowlist bound (hosts) through ManagedBounds'
// error, and a profile within the bounds starts.
func TestManagedStartCheck(t *testing.T) {
	useManaged(t, "[lockssh.bounds]\nexec = false\n")
	r := newRig(t, rigOpts{exec: true})
	err := checkManaged(t, r)
	if !errors.Is(err, console.ErrManaged) || !slices.ContainsFunc(console.ManagedLines(err), func(l string) bool {
		return strings.Contains(l, "blocked by company policy: lockssh.bounds.exec = false (profile uat: exec = true)")
	}) {
		t.Errorf("exec beyond the bound: %v %q", err, console.ManagedLines(err))
	}
	if err := checkManaged(t, newRig(t, rigOpts{})); err != nil {
		t.Errorf("a profile within the bounds: %v", err)
	}
	useManaged(t, "[lockssh.bounds]\nhosts = [\"*.corp.example\"]\n")
	err = checkManaged(t, newRig(t, rigOpts{}))
	if !errors.Is(err, console.ErrManaged) || !strings.Contains(err.Error(), "lockssh.bounds.hosts") {
		t.Errorf("host outside the list: %v", err)
	}
}

// The managed file's required detectors and mask rules reach the policy in
// force: a value a managed mask rule matches is masked in the output, and
// the run's audit record carries the managed fingerprint.
func TestManagedMasksApplied(t *testing.T) {
	useManaged(t, "[lockssh.bounds]\ndetectors = [\"fr_nir\"]\n[[lockssh.bounds.pii_mask]]\npattern = \"days\"\n")
	r := newRig(t, rigOpts{managed: true})
	pol, err := r.be.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	p := pol.(Policy)
	if !slices.Contains(p.Mask, "days") || !slices.Contains(p.Policy.Profile.Detectors, "fr_nir") {
		t.Errorf("policy %+v", p.Policy)
	}
	out := output(t, r.call(MethodRun, Params{Argv: []string{"uptime"}}))
	if strings.Contains(out.Stdout, "days") {
		t.Errorf("a managed mask rule did not mask: %q", out.Stdout)
	}
	// lockssh's own records carry the managed fingerprint, as the
	// console's do.
	if fp := r.srv.Managed().Fingerprint; !strings.Contains(r.auditLog(), `"managed":"`+fp+`"`) {
		t.Errorf("no managed fingerprint in the run record:\n%s", r.auditLog())
	}
}

// A loosening beyond the bounds made while the console runs is refused at
// the next poll, never pending, and audited refused-managed.
func TestManagedPollRefuses(t *testing.T) {
	useManaged(t, "[lockssh.bounds]\nexec = false\n")
	r := newRig(t, rigOpts{managed: true})
	cfg := filepath.Join(r.root, ".lockssh", "config.toml")
	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, append(data, []byte("exec = true\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	r.srv.CheckPolicy()
	if !r.srv.PolicyRefused() || r.srv.PolicyPending() {
		t.Errorf("refused %v pending %v", r.srv.PolicyRefused(), r.srv.PolicyPending())
	}
	if log := r.auditLog(); !strings.Contains(log, console.DecisionRefusedManaged) {
		t.Errorf("audit:\n%s", log)
	}
	if r.srv.Policy().(Policy).Policy.Profile.Exec {
		t.Error("exec = true is in force")
	}
}
