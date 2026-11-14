package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
)

func parse(t *testing.T, s string) (map[string]Profile, error) {
	t.Helper()
	return ParseProfiles([]byte(s), "test.toml")
}

func TestDefaults(t *testing.T) {
	ps, err := parse(t, "[profiles.dev]\nhost = \"web1\"\nuser = \"deploy\"\nkey = \"~/.ssh/id\"\nallow = [\"df  -h\", \"uptime\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	p := ps["dev"]
	if p.Host() != "web1" || p.Port() != 22 || p.Auth() != AuthKey || p.Credentials != CredentialsNone || p.SSH.User != "deploy" ||
		!slices.Equal(p.Allow, []string{"df -h", "uptime"}) || p.Exec || p.Limits != DefaultLimits() ||
		!slices.Equal(p.Detectors, DefaultDetectors()) || p.IdleTimeout != DefaultIdleTimeout || p.MaxSession != DefaultMaxSession {
		t.Errorf("profile %+v", p)
	}
	ps, err = parse(t, "[profiles.dev]\nhost = \"[::1]\"\nport = 2222\nuser = \"u\"\nauth = \"password\"\ndetectors = []\n[profiles.dev.limits]\nrequest_timeout = \"2m\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if p := ps["dev"]; p.Host() != "::1" || p.Port() != 2222 || p.Credentials != kconfig.CredentialsAsk || len(p.Detectors) != 0 || p.Limits.RequestTimeout != 2*time.Minute {
		t.Errorf("profile %+v", p)
	}
}

func TestRefusals(t *testing.T) {
	base := "host = \"web1\"\nuser = \"deploy\"\nkey = \"k\"\n"
	for name, body := range map[string]string{
		"no host":         "user = \"u\"\nkey = \"k\"\n",
		"no user":         "host = \"h\"\nkey = \"k\"\n",
		"user@host":       "host = \"u@h\"\nuser = \"u\"\nkey = \"k\"\n",
		"host:port":       "host = \"h:22\"\nuser = \"u\"\nkey = \"k\"\n",
		"no key":          "host = \"h\"\nuser = \"u\"\n",
		"key w/ password": base + "auth = \"password\"\n",
		"bad auth":        base + "auth = \"agent\"\n",
		"none w/ pw":      "host = \"h\"\nuser = \"u\"\nauth = \"password\"\ncredentials = \"none\"\n",
		"vault no path":   base + "credentials = \"vault\"\n",
		"path no vault":   base + "vault_path = \"a/b\"\n",
		"bad cred":        base + "credentials = \"hunter2\"\n",
		"bad rule":        base + "allow = [\"* x\"]\n",
		"bad detector":    base + "detectors = [\"nope\"]\n",
		"secret key":      base + "password = \"x\"\n",
		"big output":      base + "[profiles.p.limits]\nmax_output_bytes = 99999999\n",
		"long timeout":    base + "[profiles.p.limits]\nrequest_timeout = \"1h\"\n",
		"bad auto":        base + "[profiles.p.auto]\npurge = \"auto\"\n",
		"port":            base + "port = 70000\n",
	} {
		_, err := parse(t, "[profiles.p]\n"+body)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: echoed: %v", name, err)
		}
	}
}

func TestDiff(t *testing.T) {
	ps, err := parse(t, "[profiles.p]\nhost = \"h\"\nuser = \"u\"\nkey = \"k\"\nallow = [\"uptime\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	a := NewPolicy(ps["p"])
	loosen := func(edit func(*Profile)) []kconfig.Change {
		c := a
		pr := c.Profile
		pr.Allow = slices.Clone(pr.Allow)
		pr.Detectors = slices.Clone(pr.Detectors)
		ssh := *pr.SSH
		pr.SSH = &ssh
		edit(&pr)
		c.Profile = pr
		return NewPolicy(c.Profile).Diff(a)
	}
	for name, c := range map[string]struct {
		edit    func(*Profile)
		loosens bool
	}{
		"new rule":       {func(p *Profile) { p.Allow = append(p.Allow, "df -h") }, true},
		"rule removed":   {func(p *Profile) { p.Allow = nil }, false},
		"exec on":        {func(p *Profile) { p.Exec = true }, true},
		"detector gone":  {func(p *Profile) { p.Detectors = p.Detectors[1:] }, true},
		"bigger output":  {func(p *Profile) { p.Limits.MaxOutputBytes *= 2 }, true},
		"shorter":        {func(p *Profile) { p.Limits.RequestTimeout = time.Second }, false},
		"other host":     {func(p *Profile) { p.SSH.Host = "evil" }, true},
		"known_hosts":    {func(p *Profile) { p.KnownHosts = "/tmp/kh" }, true},
		"auto run ask":   {func(p *Profile) { p.Auto.Run = AutoAsk }, false},
		"auto exec auto": {func(p *Profile) { p.Auto.Exec = AutoAuto }, true},
		"unconfined on":  {func(p *Profile) { p.Unconfined = true }, true},
	} {
		ch := loosen(c.edit)
		if len(ch) == 0 {
			t.Errorf("%s: no change", name)
			continue
		}
		got := false
		for _, x := range ch {
			got = got || x.Loosens
		}
		if got != c.loosens {
			t.Errorf("%s: loosens %t, want %t (%+v)", name, got, c.loosens, ch)
		}
	}
	if d := strings.Join(a.Describe(), "\n"); !strings.Contains(d, "allow: uptime") || !strings.Contains(d, "exec: off") || !strings.Contains(d, "u@h:22") {
		t.Errorf("describe:\n%s", d)
	}
}

// TestUnconfined: the profile key unconfined is read into the profile base,
// changes the policy fingerprint, and turning it off is a tightening.
func TestUnconfined(t *testing.T) {
	body := "host = \"h\"\nuser = \"u\"\nkey = \"k\"\n"
	ps, err := parse(t, "[profiles.p]\n"+body+"\n[profiles.q]\n"+body+"unconfined = true\n")
	if err != nil {
		t.Fatal(err)
	}
	p, q := ps["p"], ps["q"]
	if p.Unconfined || !q.Unconfined {
		t.Fatalf("unconfined: p %t, q %t", p.Unconfined, q.Unconfined)
	}
	q.Name = p.Name
	pp, qp := NewPolicy(p), NewPolicy(q)
	if kconfig.Fingerprint(pp) == kconfig.Fingerprint(qp) {
		t.Error("unconfined does not change the fingerprint")
	}
	loosens := func(ch []kconfig.Change) bool {
		return slices.ContainsFunc(ch, func(c kconfig.Change) bool { return c.Loosens })
	}
	if ch := qp.Diff(pp); len(ch) != 1 || ch[0].Field != "unconfined" || !loosens(ch) {
		t.Errorf("unconfined on: %+v", ch)
	}
	if ch := pp.Diff(qp); len(ch) != 1 || loosens(ch) {
		t.Errorf("unconfined off: %+v", ch)
	}
	if d := strings.Join(qp.Describe(), "\n"); !strings.Contains(d, "unconfined: ON") {
		t.Errorf("describe:\n%s", d)
	}
}
