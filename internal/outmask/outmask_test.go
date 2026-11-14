package outmask

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/pii"
	"github.com/DavidGodefroid/lockssh/internal/config"
)

func TestMask(t *testing.T) {
	ds, err := pii.Detectors([]string{"email", "ip", "secret"})
	if err != nil {
		t.Fatal(err)
	}
	ps, err := pii.NewEpoch(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m := New(ds, ps)
	in := "user Alice <alice@example.com> from 8.8.8.8 and 10.0.0.1 password=hunter2hunter2 ALICE@EXAMPLE.COM \xff end"
	r := m.Mask(in)
	if strings.Contains(r.Text, "alice@") || strings.Contains(r.Text, "8.8.8.8") || strings.Contains(r.Text, "hunter2") {
		t.Fatalf("clear value: %q", r.Text)
	}
	ids := regexp.MustCompile(`⟦email:([0-9A-Z]{12})⟧`).FindAllStringSubmatch(r.Text, -1)
	if len(ids) != 2 || ids[0][1] != ids[1][1] {
		t.Errorf("one address, two spellings, one pseudonym: %q", r.Text)
	}
	if !strings.Contains(r.Text, "10.0.0.1") || !strings.Contains(r.Text, "⟦secret⟧") || !strings.Contains(r.Text, "�") {
		t.Errorf("text %q", r.Text)
	}
	if r.Kinds["email"] != 2 || r.Kinds["ip"] != 1 || r.Kinds["secret"] != 1 {
		t.Errorf("kinds %v", r.Kinds)
	}
	if got := New(ds, nil).Mask("a@example.com").Text; got != "⟦email⟧" {
		t.Errorf("no epoch: %q", got)
	}
	if r := m.Mask("nothing here"); r.Text != "nothing here" || r.Kinds != nil {
		t.Errorf("clean: %+v", r)
	}
}

// A flag secret only through "auth" keeps an auth method name, and a stop
// word after a secret flag stays in clear (lockkit v0.19.2, lockkit#198):
// initdb's hint reads as written; real secrets are still masked.
func TestMaskAuthFlags(t *testing.T) {
	ds, err := pii.Detectors(config.DefaultDetectors())
	if err != nil {
		t.Fatal(err)
	}
	m := New(ds, nil)
	for _, in := range []string{
		"initdb: hint: You can change this by editing pg_hba.conf or using the option -A, or --auth-local and --auth-host, the next time you run initdb.",
		"initdb -D /var/lib/postgresql/data --auth-local peer --auth-host scram-sha-256",
		"usage: tool [--password or --token]",
	} {
		if r := m.Mask(in); r.Text != in || r.Kinds != nil {
			t.Errorf("over-masked:\n in  %q\n out %q", in, r.Text)
		}
	}
	for _, in := range []string{
		"curl --auth admin:pw https://h/",
		"tool --auth s3cr3tT0ken",
		"psql --password hunter2",
	} {
		if r := m.Mask(in); r.Kinds["secret"] != 1 {
			t.Errorf("secret in clear: %q -> %q", in, r.Text)
		}
	}
}
