package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A write on production is a human's decision: auto.exec = "auto" and the
// full-auto preset are refused when the policy loads.
func TestProductionAutoExecRefused(t *testing.T) {
	base := "[profiles.prod]\nhost = \"h\"\nuser = \"u\"\nkey = \"k\"\nproduction = true\n"
	for name, body := range map[string]string{
		"exec auto": "[profiles.prod.auto]\nexec = \"auto\"\n",
		"full-auto": "auto = \"full-auto\"\n",
	} {
		_, err := parse(t, base+body)
		if err == nil || !strings.Contains(err.Error(), "production") {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, body := range []string{"", "[profiles.prod.auto]\nexec = \"ask\"\nrun = \"auto\"\n", "[profiles.prod.auto]\nexec = \"deny\"\n"} {
		if _, err := parse(t, base+body); err != nil {
			t.Errorf("%q: %v", body, err)
		}
	}
	// Elsewhere it stays the human's choice.
	if _, err := parse(t, "[profiles.dev]\nhost = \"h\"\nuser = \"u\"\nkey = \"k\"\nauto = \"full-auto\"\n"); err != nil {
		t.Error(err)
	}
}

func TestParseMaskAllow(t *testing.T) {
	for in, want := range map[string]string{" cust-[0-9]{6} ": "cust-[0-9]{6}", "(?i)acme-\\w+": "(?i)acme-\\w+"} {
		if got, err := ParseMask(in); err != nil || got != want {
			t.Errorf("ParseMask(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "  ", "x*", "(", "a|", strings.Repeat("a", MaxPIIRuleBytes+1), string([]byte{0xff})} {
		if _, err := ParseMask(bad); err == nil {
			t.Errorf("ParseMask(%q) accepted", bad)
		}
	}
	for in, want := range map[string]string{"email:Support@Example.COM": "email:support@example.com", "ip: 10.0.0.1": "ip:10.0.0.1"} {
		if got, err := ParseAllow(in); err != nil || got != want {
			t.Errorf("ParseAllow(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "ip", "ip:", ":x", "secret:hunter2", "nope:hunter2", "email:a\nb", "Email:hunter2"} {
		_, err := ParseAllow(bad)
		if err == nil {
			t.Errorf("ParseAllow(%q) accepted", bad)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("ParseAllow(%q) quotes the value: %v", bad, err)
		}
	}
}

func TestLoadPIIAndAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".lockssh", PIIFile)
	if r, err := LoadPII(path); err != nil || len(r.Mask)+len(r.Allow) != 0 {
		t.Fatalf("missing file: %+v %v", r, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[[mask]]\npattern = 'cust-[0-9]{6}'\n\n[[allow]]\nkind = \"ip\"\nvalue = \"10.0.0.1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AppendMask(path, "ord-[0-9]+"); err != nil {
		t.Fatal(err)
	}
	r, err := LoadPII(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Mask, []string{"cust-[0-9]{6}", "ord-[0-9]+"}) || !slices.Equal(r.Allow, []string{"ip:10.0.0.1"}) {
		t.Errorf("rules %+v", r)
	}
	if err := os.WriteFile(path, []byte("[[allow]]\nkind = \"secret\"\nvalue = \"hunter2\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPII(path); err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "allow rule 1") {
		t.Errorf("secret allow: %v", err)
	}
	if got := PIIPath("/p", "/u/config.toml"); got != filepath.Join("/p", ".lockssh", PIIFile) {
		t.Errorf("PIIPath %q", got)
	}
	if got := PIIPath("", "/u/config.toml"); got != filepath.Join("/u", PIIFile) {
		t.Errorf("PIIPath %q", got)
	}
}

func TestPolicyPII(t *testing.T) {
	ps, err := parse(t, "[profiles.p]\nhost = \"h\"\nuser = \"u\"\nkey = \"k\"\nallow = [\"uptime\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	a := NewPolicy(ps["p"])
	// No rules: the fingerprinted JSON is the one of v0.1.0.
	b, _ := json.Marshal(a)
	if strings.Contains(string(b), "pii_") {
		t.Errorf("JSON without rules holds pii fields: %s", b)
	}
	if d := a.WithPII(PIIRules{}).Diff(a); len(d) != 0 {
		t.Errorf("empty rules: %+v", d)
	}
	withMask := a.WithPII(PIIRules{Mask: []string{"x+"}})
	for name, c := range map[string]struct {
		cur, approved Policy
		loosens       bool
	}{
		"mask added":    {withMask, a, false},
		"mask removed":  {a, withMask, true},
		"allow added":   {a.WithPII(PIIRules{Allow: []string{"ip:10.0.0.1"}}), a, true},
		"allow removed": {a, a.WithPII(PIIRules{Allow: []string{"ip:10.0.0.1"}}), false},
	} {
		ch := c.cur.Diff(c.approved)
		if len(ch) != 1 || ch[0].Loosens != c.loosens || !strings.HasPrefix(ch[0].Field, "pii.") {
			t.Errorf("%s: %+v", name, ch)
		}
	}
	d := strings.Join(a.WithPII(PIIRules{Mask: []string{"x+"}, Allow: []string{"ip:10.0.0.1"}}).Describe(), "\n")
	if !strings.Contains(d, "pii mask: x+") || !strings.Contains(d, "pii allow (in clear): ip:10.0.0.1") {
		t.Errorf("describe:\n%s", d)
	}
}

// The policy review warns on a code-running program given a glob and on
// an option glob, both in the description and in the change that adds the
// rule.
func TestPolicyReviewWarnings(t *testing.T) {
	ps, err := parse(t, "[profiles.p]\nhost = \"h\"\nuser = \"u\"\nkey = \"k\"\nallow = [\"uptime\", \"sed -n * f\", \"ls -*\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	pol := NewPolicy(ps["p"])
	d := strings.Join(pol.Describe(), "\n")
	if strings.Count(d, "warning:") != 2 || !strings.Contains(d, "sed can run code") || !strings.Contains(d, "chooses the option") {
		t.Errorf("describe:\n%s", d)
	}
	ap := pol
	ap.Profile.Allow = []string{"uptime"}
	var warned []string
	for _, ch := range pol.Diff(ap) {
		if ch.Field == "allow" && strings.Contains(ch.New, "(warning: ") {
			warned = append(warned, ch.New)
		}
	}
	if len(warned) != 2 {
		t.Errorf("diff warnings %q", warned)
	}
	// Builtin-only programs are refused when the policy loads.
	if _, err := parse(t, "[profiles.p]\nhost = \"h\"\nuser = \"u\"\nkey = \"k\"\nallow = [\"eval *\"]\n"); err == nil || !strings.Contains(err.Error(), "builtin") {
		t.Errorf("eval rule: %v", err)
	}
}
