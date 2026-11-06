// Package command checks the argv an agent asks the console to run, turns
// it into the remote command line, and matches it against a profile's
// allow rules. The agent never writes shell syntax: every argument is
// quoted for a POSIX shell, so ";", "|" or "$(...)" stay literal
// arguments.
package command

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bounds of one argv.
const (
	MaxArgs     = 64
	MaxArgBytes = 4096
	MaxBytes    = 16 << 10
)

// Check validates argv: 1 to MaxArgs arguments, valid UTF-8, no NUL and no
// control or format character but tab, argv[0] not empty. Its errors name
// the argument's position, never its text.
func Check(argv []string) error {
	if len(argv) == 0 {
		return errors.New("argv is empty: give the program and its arguments")
	}
	if len(argv) > MaxArgs {
		return fmt.Errorf("argv has more than %d arguments", MaxArgs)
	}
	total := 0
	for i, a := range argv {
		if len(a) > MaxArgBytes {
			return fmt.Errorf("argument %d is longer than %d bytes", i+1, MaxArgBytes)
		}
		total += len(a)
		if !utf8.ValidString(a) {
			return fmt.Errorf("argument %d is not valid UTF-8", i+1)
		}
		for _, r := range a {
			if r == '\t' {
				continue
			}
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
				return fmt.Errorf("argument %d holds a control or invisible character", i+1)
			}
		}
	}
	if total > MaxBytes {
		return fmt.Errorf("argv is longer than %d bytes", MaxBytes)
	}
	if argv[0] == "" {
		return errors.New("argument 1 (the program) is empty")
	}
	return nil
}

// Quote quotes s for a POSIX shell: single quotes, each ' written '\”.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Line is the remote command line of argv: every argument quoted. The
// server's login shell reads it; it cannot run anything but argv[0] with
// argv[1:] as its arguments.
func Line(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = Quote(a)
	}
	return strings.Join(q, " ")
}

// Display is argv for a screen: arguments that need quoting are quoted,
// the others shown as they are.
func Display(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a != "" && strings.IndexFunc(a, needsQuote) < 0 {
			out[i] = a
		} else {
			out[i] = Quote(a)
		}
	}
	return strings.Join(out, " ")
}

func needsQuote(r rune) bool {
	return !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-_./=:,@+%", r))
}

// Rule is one allow rule: an argv pattern.
type Rule struct {
	tokens []string
	// rest: the last token was "**", matching zero or more arguments.
	rest bool
	text string
}

// String is the rule's canonical text (tokens joined by one space).
func (r Rule) String() string { return r.text }

// ParseRule parses an allow rule: tokens separated by spaces. A token with
// *, ? or [ is a glob over one argument (path.Match: * and ? never match
// "/"); a last token ** matches
// zero or more remaining arguments. The first token is the program: it is a
// literal (no glob), so that a rule never opens another program. Its errors
// never quote the rule.
func ParseRule(s string) (Rule, error) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return Rule{}, errors.New("an allow rule is empty")
	}
	if err := Check(f); err != nil {
		return Rule{}, fmt.Errorf("an allow rule: %v", err)
	}
	if isGlob(f[0]) || f[0] == "**" {
		return Rule{}, errors.New("an allow rule's first token (the program) must be a literal, not a glob")
	}
	r := Rule{text: strings.Join(f, " ")}
	for i, t := range f {
		if t == "**" {
			if i != len(f)-1 {
				return Rule{}, errors.New(`an allow rule may hold "**" only as its last token`)
			}
			r.rest = true
			break
		}
		if strings.Contains(t, "**") {
			return Rule{}, errors.New(`"**" must be a token of its own, the last one`)
		}
		if isGlob(t) {
			if _, err := path.Match(t, ""); err != nil {
				return Rule{}, errors.New("an allow rule holds a malformed glob")
			}
		}
		r.tokens = append(r.tokens, t)
	}
	return r, nil
}

func isGlob(t string) bool { return strings.ContainsAny(t, "*?[") }

// Match reports whether argv matches the rule.
func (r Rule) Match(argv []string) bool {
	if len(argv) < len(r.tokens) || (!r.rest && len(argv) != len(r.tokens)) {
		return false
	}
	for i, t := range r.tokens {
		a := argv[i]
		if !isGlob(t) {
			if a != t {
				return false
			}
			continue
		}
		// path.Match: * and ? never match "/", so "/var/log/*" does not
		// reach "/var/log/../../etc/shadow".
		ok, err := path.Match(t, a)
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// Rules is a list of allow rules.
type Rules []Rule

// ParseRules parses each rule; the error names the rule's position.
func ParseRules(texts []string) (Rules, error) {
	out := make(Rules, 0, len(texts))
	for i, t := range texts {
		r, err := ParseRule(t)
		if err != nil {
			return nil, fmt.Errorf("allow[%d]: %v", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Find returns the first rule argv matches.
func (rs Rules) Find(argv []string) (Rule, bool) {
	for _, r := range rs {
		if r.Match(argv) {
			return r, true
		}
	}
	return Rule{}, false
}

// Canonical is the canonical text of each rule text that parses; others are
// kept as they are (ParseRules refuses them).
func Canonical(texts []string) []string {
	out := make([]string, 0, len(texts))
	for _, t := range texts {
		out = append(out, strings.Join(strings.Fields(t), " "))
	}
	return out
}
