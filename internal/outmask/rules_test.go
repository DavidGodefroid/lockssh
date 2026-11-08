package outmask

import (
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/pii"
)

func masker(t *testing.T, mask, allow []string) *Masker {
	t.Helper()
	ds, err := pii.Detectors([]string{"email", "ip", "secret"})
	if err != nil {
		t.Fatal(err)
	}
	ps, err := pii.NewEpoch(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(ds, ps).WithRules(mask, allow)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMaskRules(t *testing.T) {
	m := masker(t, []string{"cust-[0-9]{6}"}, nil)
	r := m.Mask("order for cust-123456 and cust-123456, not cust-12")
	if strings.Contains(r.Text, "cust-123456") || r.Kinds[MaskKind] != 2 || !strings.Contains(r.Text, "cust-12") {
		t.Errorf("mask rule: %+v", r)
	}
	if strings.Count(r.Text, "⟦mask:") != 2 {
		t.Errorf("pseudonyms: %q", r.Text)
	}
}

func TestAllowRules(t *testing.T) {
	m := masker(t, nil, []string{"email:support@example.com", "ip:8.8.8.8", "secret:x"})
	r := m.Mask("from SUPPORT@example.com to bob@example.com via 8.8.8.8 and 1.1.1.1 password=hunter2hunter2")
	if !strings.Contains(r.Text, "SUPPORT@example.com") || !strings.Contains(r.Text, "8.8.8.8") {
		t.Errorf("allowed value masked: %q", r.Text)
	}
	for _, leak := range []string{"bob@", "1.1.1.1", "hunter2"} {
		if strings.Contains(r.Text, leak) {
			t.Errorf("leak %q: %q", leak, r.Text)
		}
	}
}

// Overlapping matches merge: no byte of a longer match leaks past a
// shorter one that starts first, and a secret inside stays a secret.
func TestOverlapsMerge(t *testing.T) {
	m := masker(t, []string{"id=[a-z]+@ex", "abcdef"}, nil)
	r := m.Mask("x id=alice@example.com y abcdefabcdef")
	for _, leak := range []string{"alice", "example.com", "abcdef"} {
		if strings.Contains(r.Text, leak) {
			t.Errorf("leak %q: %q", leak, r.Text)
		}
	}
	if !strings.HasPrefix(r.Text, "x ") || !strings.Contains(r.Text, " y ") {
		t.Errorf("text %q", r.Text)
	}
	r = masker(t, []string{"password=hun"}, nil).Mask("password=hunter2hunter2 end")
	if strings.Contains(r.Text, "hunter") || !strings.Contains(r.Text, "⟦secret⟧") {
		t.Errorf("secret overlap: %q", r.Text)
	}
}

func TestBadRuleFailsClosed(t *testing.T) {
	m, err := New(nil, nil).WithRules([]string{"("}, nil)
	if err == nil {
		t.Fatal("bad rule accepted")
	}
	if r := m.Mask("anything at all"); r.Text != "⟦mask⟧" {
		t.Errorf("broken masker: %q", r.Text)
	}
	if r := m.Mask(""); r.Text != "" {
		t.Errorf("empty: %q", r.Text)
	}
}
