package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/managed"
)

const managedHead = "version = 1\norganisation = \"Example Corp\"\n\n"

// mustManaged parses a managed file of body (after the version header).
func mustManaged(t *testing.T, body string) *Managed {
	t.Helper()
	m, err := parseManaged(body)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func parseManaged(body string) (*Managed, error) {
	f, err := managed.Parse([]byte(managedHead + body))
	if err != nil {
		return nil, err
	}
	return NewManaged(f)
}

// devProfile is a profile within every bound of the tests below unless a
// test loosens it: key auth, unencrypted key, one allow rule.
const devProfile = `[profiles.dev]
host = "web1.corp.example"
user = "deploy"
key = "~/.ssh/id"
known_hosts = "/etc/ssh/known"
allow = ["uptime"]
credentials_ttl = "30m"
[profiles.dev.limits]
request_timeout = "10s"
max_output_bytes = 1000
idle_timeout = "5m"
max_session = "1h"
`

// profileWith is devProfile with extra keys in its table.
func profileWith(extra string) string {
	return strings.Replace(devProfile, "[profiles.dev.limits]", extra+"\n[profiles.dev.limits]", 1)
}

func loadUnder(t *testing.T, m *Managed, cfg string) (map[string]Profile, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	ps, _, err := LoadWith("", path, m)
	return ps, err
}

func violations(t *testing.T, m *Managed, cfg string) []string {
	t.Helper()
	ps, err := loadUnder(t, m, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, v := range m.Violations(NewPolicy(ps["dev"])) {
		out = append(out, v.String())
	}
	return out
}

// One test per bound of the table in lockssh#17: a looser profile is
// cited with the managed key; one equal or stricter is not.
func TestManagedBoundsDiff(t *testing.T) {
	for _, c := range []struct {
		name, bound, loose, want string
	}{
		{"production", "production = true", "", "blocked by company policy: lockssh.bounds.production = true (profile dev: production = false)"},
		{"known_hosts", `known_hosts = "/etc/ssh/managed_known_hosts"`, "", "blocked by company policy: lockssh.bounds.known_hosts = /etc/ssh/managed_known_hosts (profile dev: known_hosts = /etc/ssh/known)"},
		{"exec", "exec = false", "exec = true", "blocked by company policy: lockssh.bounds.exec = false (profile dev: exec = true)"},
		{"allow", `allow = ["uptime", "df -h"]`, "", "blocked by company policy: lockssh.bounds.allow does not allow cat /etc/passwd (profile dev: allow + cat /etc/passwd)"},
		{"auto", `auto = { exec = "ask" }`, `auto = { exec = "auto" }`, "blocked by company policy: lockssh.bounds.auto.exec = ask (profile dev: auto.exec = auto)"},
		{"credentials_ttl", `credentials_ttl = "1h"`, `credentials_ttl = "2h"`, "blocked by company policy: lockssh.bounds.credentials_ttl = 1h0m0s (profile dev: credentials_ttl = 2h0m0s)"},
		{"max_output_bytes", "limits.max_output_bytes = 1000", "", "blocked by company policy: lockssh.bounds.limits.max_output_bytes = 1000 (profile dev: limits.max_output_bytes = 2000)"},
		{"request_timeout", `limits.request_timeout = "10s"`, "", "blocked by company policy: lockssh.bounds.limits.request_timeout = 10s (profile dev: limits.request_timeout = 20s)"},
		{"idle_timeout", `limits.idle_timeout = "5m"`, "", "blocked by company policy: lockssh.bounds.limits.idle_timeout = 5m0s (profile dev: limits.idle_timeout = 10m0s)"},
		{"max_session", `limits.max_session = "1h"`, "", "blocked by company policy: lockssh.bounds.limits.max_session = 1h0m0s (profile dev: limits.max_session = 2h0m0s)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := mustManaged(t, "[lockssh.bounds]\n"+c.bound+"\n")
			if got := violations(t, m, devProfile); c.name != "production" && c.name != "known_hosts" && len(got) > 0 {
				t.Errorf("a profile within the bound: %q", got)
			}
			loose := profileWith(c.loose)
			switch c.name {
			case "allow":
				loose = strings.Replace(devProfile, `allow = ["uptime"]`, `allow = ["uptime", "cat /etc/passwd"]`, 1)
			case "max_output_bytes":
				loose = strings.Replace(devProfile, "max_output_bytes = 1000", "max_output_bytes = 2000", 1)
			case "request_timeout":
				loose = strings.Replace(devProfile, `request_timeout = "10s"`, `request_timeout = "20s"`, 1)
			case "idle_timeout":
				loose = strings.Replace(devProfile, `idle_timeout = "5m"`, `idle_timeout = "10m"`, 1)
			case "max_session":
				loose = strings.Replace(devProfile, `max_session = "1h"`, `max_session = "2h"`, 1)
			case "credentials_ttl":
				loose = strings.Replace(devProfile, `credentials_ttl = "30m"`, `credentials_ttl = "2h"`, 1)
			}
			got := violations(t, m, loose)
			if len(got) != 1 || got[0] != c.want {
				t.Errorf("got %q\nwant %q", got, c.want)
			}
		})
	}
	// Equal to or stricter than every bound: no violation.
	m := mustManaged(t, `[lockssh.bounds]
production = true
known_hosts = "/etc/ssh/known"
exec = false
allow = ["uptime", "df -h"]
auto = { connect = "ask", run = "auto", exec = "ask", unmask = "ask" }
credentials_ttl = "1h"
limits = { max_output_bytes = 1000, request_timeout = "10s", idle_timeout = "5m", max_session = "1h" }
`)
	if got := violations(t, m, profileWith("production = true\nauto = { exec = \"deny\" }")); len(got) > 0 {
		t.Errorf("a profile within every bound: %q", got)
	}
}

func TestManagedAutoBound(t *testing.T) {
	m := mustManaged(t, "[lockssh.bounds]\nauto = { exec = \"ask\" }\n")
	if got := violations(t, m, profileWith(`auto = "full-auto"`)); len(got) != 1 || !strings.Contains(got[0], "lockssh.bounds.auto.exec = ask") {
		t.Errorf("full-auto: %q", got)
	}
	if got := violations(t, m, profileWith(`auto = { exec = "deny" }`)); len(got) > 0 {
		t.Errorf("deny: %q", got)
	}
	if _, err := parseManaged("[lockssh.bounds]\nauto = \"full-auto\"\n"); err == nil || !strings.Contains(err.Error(), "lockssh.bounds") {
		t.Errorf("full-auto bound: %v", err)
	}
}

// The allowlists Diff cannot express refuse a value outside the list,
// naming the managed key, and accept one inside it.
func TestManagedBoundsAllowlists(t *testing.T) {
	for _, c := range []struct {
		name, bound, in, out, want string
	}{
		{"hosts", `hosts = ["*.corp.example"]`, "", `host = "evil.example.com"`,
			"blocked by company policy: lockssh.bounds.hosts = *.corp.example (profile dev: host = evil.example.com)"},
		{"auth", `auth = ["key"]`, "", "auth = \"password\"\nkey = \"\"",
			"blocked by company policy: lockssh.bounds.auth = key (profile dev: auth = password)"},
		{"credentials", `credentials = ["none", "vault"]`, "", `credentials = "keychain"`,
			"blocked by company policy: lockssh.bounds.credentials = none, vault (profile dev: credentials = keychain)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := mustManaged(t, "[lockssh.bounds]\n"+c.bound+"\n")
			if got := violations(t, m, devProfile); len(got) > 0 {
				t.Errorf("inside the list: %q", got)
			}
			cfg := devProfile
			for _, line := range strings.Split(c.out, "\n") {
				k, _, _ := strings.Cut(line, " = ")
				re := strings.Split(cfg, "\n")
				done := false
				for i, l := range re {
					if strings.HasPrefix(l, k+" = ") {
						re[i], done = line, true
					}
				}
				cfg = strings.Join(re, "\n")
				if !done {
					cfg = profileWith(line)
				}
			}
			got := violations(t, m, cfg)
			if len(got) != 1 || got[0] != c.want {
				t.Errorf("got %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestManagedVaultRequired(t *testing.T) {
	m := mustManaged(t, "[family]\nvault = { address = \"https://vault.example.com\", required = true }\n")
	got := violations(t, m, devProfile)
	if len(got) != 1 || got[0] != "blocked by company policy: family.vault.required = vault (profile dev: credentials = none)" {
		t.Errorf("got %q", got)
	}
	if got := violations(t, m, profileWith("credentials = \"vault\"\nvault_path = \"secret/data/lockssh/web\"")); len(got) > 0 {
		t.Errorf("vault: %q", got)
	}
}

func TestManagedProfiles(t *testing.T) {
	m := mustManaged(t, `[lockssh.profiles.prod-web]
host = "web.corp.example"
user = "ops"
key = "/etc/lockssh/id"
known_hosts = "/etc/lockfamily/known_hosts"
production = true
allow = ["uptime"]
`)
	ps, err := loadUnder(t, m, devProfile)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := ps["prod-web"]
	if !ok || p.Host() != "web.corp.example" || p.User != "ops" || !p.Production || p.KnownHosts != "/etc/lockfamily/known_hosts" ||
		!slices.Equal(p.Allow, []string{"uptime"}) || p.Name != "prod-web" {
		t.Errorf("managed profile not served as written: %+v", p)
	}
	if _, ok := ps["dev"]; !ok {
		t.Error("the user's own profile is gone")
	}
	_, err = loadUnder(t, m, strings.Replace(devProfile, "[profiles.dev", "[profiles.prod-web", 2))
	if err == nil || !strings.Contains(err.Error(), `"prod-web"`) {
		t.Errorf("a user profile of a managed name: %v", err)
	}
	_, err = parseManaged(`[lockssh.bounds]
exec = false
[lockssh.profiles.loose]
host = "h"
user = "u"
key = "k"
exec = true
`)
	if err == nil || !strings.Contains(err.Error(), "lockssh.bounds.exec") || !strings.Contains(err.Error(), "lockssh.profiles.loose") {
		t.Errorf("a managed profile beyond the bounds: %v", err)
	}
}

func TestManagedDefaults(t *testing.T) {
	m := mustManaged(t, `[lockssh.bounds]
limits.max_session = "2h"
[lockssh.defaults]
known_hosts = "/etc/lockfamily/known_hosts"
exec = true
limits.max_session = "1h"
auto = { exec = "deny" }
`)
	cfg := `[profiles.dev]
host = "h"
user = "u"
key = "k"
`
	ps, err := loadUnder(t, m, cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := ps["dev"]
	if p.KnownHosts != "/etc/lockfamily/known_hosts" || !p.Exec || p.MaxSession != time.Hour || p.Auto.Rule(ActExec) != AutoDeny {
		t.Errorf("defaults not applied: %+v", p)
	}
	// A value of the user's file wins, false and other limits included.
	ps, err = loadUnder(t, m, cfg+"exec = false\nknown_hosts = \"/k\"\nlimits.max_session = \"90m\"\nauto = { exec = \"ask\" }\n")
	if err != nil {
		t.Fatal(err)
	}
	p = ps["dev"]
	if p.KnownHosts != "/k" || p.Exec || p.MaxSession != 90*time.Minute || p.Auto.Rule(ActExec) != AutoAsk {
		t.Errorf("the user's values lost to the defaults: %+v", p)
	}
	_, err = parseManaged("[lockssh.bounds]\nlimits.max_session = \"1h\"\n[lockssh.defaults]\nlimits.max_session = \"2h\"\n")
	if err == nil || !strings.Contains(err.Error(), "lockssh.bounds.limits.max_session") {
		t.Errorf("a default beyond the bounds: %v", err)
	}
	// A bound on a key the defaults do not set is no default error.
	if _, err := parseManaged("[lockssh.bounds]\nhosts = [\"*.corp\"]\nauth = [\"password\"]\n[lockssh.defaults]\nexec = true\n"); err != nil {
		t.Errorf("defaults that set no bounded key: %v", err)
	}
}

func TestManagedDetectorsAndMasks(t *testing.T) {
	m := mustManaged(t, `[lockssh.bounds]
detectors = ["fr_nir", "email"]
[[lockssh.bounds.pii_mask]]
pattern = "cust-[0-9]{6}"
`)
	ps, err := loadUnder(t, m, profileWith(`detectors = ["ip"]`))
	if err != nil {
		t.Fatal(err)
	}
	if got := ps["dev"].Detectors; !slices.Equal(got, []string{"email", "fr_nir", "ip"}) {
		t.Errorf("detectors %q", got)
	}
	r, err := m.WithPII(PIIRules{Mask: []string{"x[0-9]+"}, Allow: []string{"ip:10.0.0.1"}})
	if err != nil || !slices.Equal(r.Mask, []string{"cust-[0-9]{6}", "x[0-9]+"}) {
		t.Errorf("masks %q %v", r.Mask, err)
	}
	if _, err := m.WithPII(PIIRules{Allow: []string{"email:cust-123456@example.com"}}); err == nil ||
		!strings.Contains(err.Error(), "lockssh.bounds.pii_mask") || strings.Contains(err.Error(), "cust-123456") {
		t.Errorf("an allow rule unmasking a managed pattern: %v", err)
	}
	var many strings.Builder
	many.WriteString("[lockssh.bounds]\n")
	for i := 0; i <= MaxPIIRules; i++ {
		many.WriteString("[[lockssh.bounds.pii_mask]]\npattern = \"a" + strings.Repeat("b", i%5) + "\"\n")
	}
	if _, err := parseManaged(many.String()); err == nil {
		t.Error("more than MaxPIIRules mask rules accepted")
	}
	if _, err := parseManaged("[[lockssh.bounds.pii_mask]]\npattern = \"" + strings.Repeat("a", MaxPIIRuleBytes+1) + "\"\n"); err == nil {
		t.Error("a mask rule beyond MaxPIIRuleBytes accepted")
	}
}

func TestManagedNil(t *testing.T) {
	var m *Managed
	if m.Profiles() != nil || m.Masks() != nil || len(m.Violations(NewPolicy(Profile{Name: "x"}))) != 0 {
		t.Error("a nil Managed changes something")
	}
	ps, err := loadUnder(t, nil, devProfile)
	if err != nil || ps["dev"].Host() != "web1.corp.example" {
		t.Errorf("%v %+v", err, ps)
	}
}

// A longer session is a loosening in Diff, as lockssh#17 decides.
func TestDiffLongerMaxSessionLoosens(t *testing.T) {
	a := NewPolicy(Profile{Name: "x", Base: kconfig.Base{MaxSession: time.Hour, IdleTimeout: time.Minute}})
	c := a
	c.Profile.MaxSession = 2 * time.Hour
	found := false
	for _, ch := range c.Diff(a) {
		if ch.Field == "limits.max_session" && ch.Loosens {
			found = true
		}
	}
	if !found {
		t.Error("a longer max_session does not loosen")
	}
}
