// Package outmask masks a command's output before it leaves the console:
// what the profile's detectors find becomes a keyed pseudonym
// (⟦email:7F3KQ2M9ZD4X⟧, stable within the console run, so "the same
// address" still reads as the same), a secret becomes ⟦secret⟧, and
// invalid UTF-8 becomes U+FFFD.
package outmask

import (
	"strings"
	"unicode/utf8"

	"github.com/DavidGodefroid/lockkit/pii"
)

// Masker masks text with a set of detectors and one pseudonym epoch.
type Masker struct {
	ds []pii.Detector
	ps *pii.Pseudonymizer
}

// New returns a masker. ps may be nil: every match is then redacted by
// kind only.
func New(ds []pii.Detector, ps *pii.Pseudonymizer) *Masker { return &Masker{ds: ds, ps: ps} }

// Result is one masked text and what was masked in it.
type Result struct {
	Text string
	// Kinds counts the masked values by kind.
	Kinds map[string]int
}

// Mask masks s.
func (m *Masker) Mask(s string) Result {
	matches := pii.FindInViews(s, m.ds)
	var b strings.Builder
	b.Grow(len(s))
	kinds := map[string]int{}
	last := 0
	for _, mt := range matches {
		if mt.Start < last || mt.End > len(s) || mt.Start > mt.End {
			continue
		}
		b.WriteString(valid(s[last:mt.Start]))
		b.WriteString(m.placeholder(mt.Kind, s[mt.Start:mt.End]))
		kinds[mt.Kind]++
		last = mt.End
	}
	b.WriteString(valid(s[last:]))
	if len(kinds) == 0 {
		kinds = nil
	}
	return Result{Text: b.String(), Kinds: kinds}
}

func (m *Masker) placeholder(kind, value string) string {
	switch kind {
	case "secret":
		return "⟦secret⟧"
	case pii.CutKind:
		return "⟦cut⟧"
	}
	if m.ps != nil && pii.ValidKind(kind) {
		if id, err := m.ps.ID(kind, value); err == nil {
			return "⟦" + kind + ":" + id + "⟧"
		}
	}
	return "⟦" + kind + "⟧"
}

// valid replaces invalid UTF-8 with U+FFFD.
func valid(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}
