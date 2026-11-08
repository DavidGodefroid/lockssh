// Package outmask masks a command's output before it leaves the console:
// what the profile's detectors find becomes a keyed pseudonym
// (⟦email:7F3KQ2M9ZD4X⟧, stable within the console run, so "the same
// address" still reads as the same), a secret becomes ⟦secret⟧, what a
// mask rule of .lockssh/pii.toml matches becomes ⟦mask:…⟧, and invalid
// UTF-8 becomes U+FFFD. A value an allow rule names stays in clear.
package outmask

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/DavidGodefroid/lockkit/pii"
)

// MaskKind is the kind of what a mask rule matches.
const MaskKind = "mask"

// Masker masks text with a set of detectors and one pseudonym epoch.
type Masker struct {
	ds    []pii.Detector
	ps    *pii.Pseudonymizer
	rules []*regexp.Regexp
	allow map[string]bool
	// broken: a rule did not compile; every text is masked whole.
	broken bool
}

// New returns a masker. ps may be nil: every match is then redacted by
// kind only.
func New(ds []pii.Detector, ps *pii.Pseudonymizer) *Masker { return &Masker{ds: ds, ps: ps} }

// ErrBadRule: a mask rule does not compile (the policy in force parsed
// when it was approved). The masker then masks every text whole.
var ErrBadRule = errors.New("outmask: a mask rule does not compile")

// WithRules adds the PII rules (config.PIIRules, canonical): mask are
// regular expressions, allow "kind:value" texts with a normalised value.
// A rule that does not compile fails closed: ErrBadRule, and the masker
// masks every text whole.
func (m *Masker) WithRules(mask, allow []string) (*Masker, error) {
	n := *m
	n.rules, n.allow = nil, nil
	for _, r := range mask {
		re, err := regexp.Compile(r)
		if err != nil {
			n.broken = true
			return &n, ErrBadRule
		}
		n.rules = append(n.rules, re)
	}
	if len(allow) > 0 {
		n.allow = make(map[string]bool, len(allow))
		for _, a := range allow {
			n.allow[a] = true
		}
	}
	return &n, nil
}

// Result is one masked text and what was masked in it.
type Result struct {
	Text string
	// Kinds counts the masked values by kind.
	Kinds map[string]int
}

// Mask masks s.
func (m *Masker) Mask(s string) Result {
	if m.broken {
		if s == "" {
			return Result{}
		}
		return Result{Text: "⟦" + MaskKind + "⟧", Kinds: map[string]int{MaskKind: 1}}
	}
	spans := m.spans(s)
	var b strings.Builder
	b.Grow(len(s))
	kinds := map[string]int{}
	last := 0
	for _, sp := range spans {
		b.WriteString(valid(s[last:sp.Start]))
		b.WriteString(m.placeholder(sp.Kind, s[sp.Start:sp.End]))
		kinds[sp.Kind]++
		last = sp.End
	}
	b.WriteString(valid(s[last:]))
	if len(kinds) == 0 {
		kinds = nil
	}
	return Result{Text: b.String(), Kinds: kinds}
}

// spans are the ranges of s to mask, sorted and disjoint: the detectors'
// matches but the allowed ones, and the mask rules' matches. Overlapping
// ranges merge into one, so no byte of either leaks; a merged range that
// holds a secret is a secret.
func (m *Masker) spans(s string) []pii.Match {
	var all []pii.Match
	for _, mt := range pii.FindInViews(s, m.ds) {
		if mt.Start < 0 || mt.End > len(s) || mt.Start >= mt.End {
			continue
		}
		if m.allow != nil && mt.Kind != "secret" && m.allow[mt.Kind+":"+pii.Normalise(mt.Kind, s[mt.Start:mt.End])] {
			continue
		}
		all = append(all, mt)
	}
	for _, re := range m.rules {
		for _, ix := range re.FindAllStringIndex(s, -1) {
			if ix[0] < ix[1] {
				all = append(all, pii.Match{Start: ix[0], End: ix[1], Kind: MaskKind})
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Start != all[j].Start {
			return all[i].Start < all[j].Start
		}
		return all[i].End > all[j].End
	})
	var out []pii.Match
	for _, mt := range all {
		if n := len(out); n > 0 && mt.Start < out[n-1].End {
			cur := &out[n-1]
			cur.End = max(cur.End, mt.End)
			if mt.Kind == "secret" {
				cur.Kind = "secret"
			}
			continue
		}
		out = append(out, mt)
	}
	return out
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
