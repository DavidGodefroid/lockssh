package outmask

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// pseudonyms hides the keyed ids: two different values of one kind differ
// only there, and the agent cannot invert them.
var pseudonyms = regexp.MustCompile(`⟦([a-z]+):[0-9A-Z]{12}⟧`)

func shape(s string) string { return pseudonyms.ReplaceAllString(s, "⟦$1⟧") }

// A mask rule sees only what the agent already sees: guessing a masked
// value with a rule must not change the output in any way.
func TestMaskRuleNoOracle(t *testing.T) {
	in := "user alice@example.com logged in"
	right := masker(t, []string{`alice@example\.com `}, nil).Mask(in)
	wrong := masker(t, []string{`bob@example\.com `}, nil).Mask(in)
	none := masker(t, nil, nil).Mask(in)
	if shape(right.Text) != shape(wrong.Text) || shape(right.Text) != shape(none.Text) || fmt.Sprint(right.Kinds) != fmt.Sprint(none.Kinds) {
		t.Errorf("rule reveals the value: right %q wrong %q none %q", right.Text, wrong.Text, none.Text)
	}
	lo := masker(t, []string{`a[a-m]\S*@\S+ `}, nil).Mask(in)
	hi := masker(t, []string{`a[n-z]\S*@\S+ `}, nil).Mask(in)
	if shape(lo.Text) != shape(hi.Text) || fmt.Sprint(lo.Kinds) != fmt.Sprint(hi.Kinds) {
		t.Errorf("binary search: %q %v vs %q %v", lo.Text, lo.Kinds, hi.Text, hi.Kinds)
	}
}

// A rule still masks clear text around a placeholder, never the
// placeholder itself: the pseudonym stays as the detectors made it.
func TestMaskRuleAroundPlaceholder(t *testing.T) {
	m := masker(t, []string{`user \S+ logged`}, nil)
	r := m.Mask("user alice@example.com logged in")
	if strings.Contains(r.Text, "alice") || !strings.Contains(r.Text, "⟦email:") || !strings.HasSuffix(r.Text, " in") || strings.Contains(r.Text, "user") {
		t.Errorf("text %q", r.Text)
	}
	if r.Kinds["email"] != 1 || r.Kinds[MaskKind] != 2 {
		t.Errorf("kinds %v", r.Kinds)
	}
	// A rule aimed at the placeholder's own bytes leaves it whole.
	r = masker(t, []string{`[0-9A-Z]{12}`, `⟦email`, `:`}, nil).Mask("to bob@example.com")
	if !pseudonyms.MatchString(r.Text) || r.Kinds[MaskKind] != 0 {
		t.Errorf("placeholder touched: %q %v", r.Text, r.Kinds)
	}
}

// Property: for random addresses and random guessing rules, the output's
// shape never depends on which address the text held.
func TestMaskRuleNoOracleProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	word := func() string {
		const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
		b := make([]byte, 1+rng.Intn(10))
		for i := range b {
			b[i] = abc[rng.Intn(len(abc))]
		}
		return string(b)
	}
	email := func() string { return word() + "@" + word() + ".com" }
	for i := 0; i < 300; i++ {
		a, b := email(), email()
		var rules []string
		for j := 0; j < 1+rng.Intn(5); j++ {
			switch rng.Intn(4) {
			case 0:
				rules = append(rules, regexp.QuoteMeta(a)+" ")
			case 1:
				rules = append(rules, regexp.QuoteMeta(a[:1+rng.Intn(len(a)-1)]))
			case 2:
				c := a[0]
				rules = append(rules, fmt.Sprintf(`[%c-%c]\S*@\S+`, c, c))
			default:
				rules = append(rules, `\S{`+fmt.Sprint(1+rng.Intn(20))+`}`)
			}
		}
		m := masker(t, rules, nil)
		tpl := "user %s logged in from %s"
		ra, rb := m.Mask(fmt.Sprintf(tpl, a, "x")), m.Mask(fmt.Sprintf(tpl, b, "x"))
		if shape(ra.Text) != shape(rb.Text) || fmt.Sprint(ra.Kinds) != fmt.Sprint(rb.Kinds) {
			t.Fatalf("rules %q tell %q from %q: %q vs %q", rules, a, b, ra.Text, rb.Text)
		}
		if strings.Contains(ra.Text, a) {
			t.Fatalf("clear value: %q", ra.Text)
		}
	}
}
