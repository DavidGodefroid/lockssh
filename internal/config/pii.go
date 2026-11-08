package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/lockssh/internal/product"
)

// Bounds of the PII rules of .lockssh/pii.toml.
const (
	MaxPIIRules     = 200
	MaxPIIRuleBytes = 512
)

// PIIFile is the name of the PII rules file: in the project's .lockssh
// directory, else next to the user config.
const PIIFile = "pii.toml"

// PIIRules are the PII rules of a project, in canonical text form. Mask
// rules are RE2 regular expressions: what one matches in a command's
// output is masked, whatever the detectors say. Allow rules are
// "kind:value": a value a detector of that kind finds and the human wants
// in clear (an address of the project's own, a support mailbox). Adding a
// mask rule tightens (the agent may, with lockssh_pii_add); adding an allow
// rule loosens and goes through the policy review.
type PIIRules struct {
	Mask  []string
	Allow []string
}

type rawMask struct {
	Pattern string `toml:"pattern"`
}

type rawAllow struct {
	Kind  string `toml:"kind"`
	Value string `toml:"value"`
}

type rawPII struct {
	Mask  []rawMask  `toml:"mask,omitempty"`
	Allow []rawAllow `toml:"allow,omitempty"`
}

// LoadPII reads a PII rules file; a missing file is no rules. Errors name
// the rule's position, never its text (an allow value is personal data).
func LoadPII(path string) (PIIRules, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return PIIRules{}, nil
	}
	if err != nil {
		return PIIRules{}, fmt.Errorf("pii rules: %w", err)
	}
	var raw rawPII
	if _, err := kconfig.Decode(product.P, data, path, &raw); err != nil {
		return PIIRules{}, err
	}
	if len(raw.Mask)+len(raw.Allow) > MaxPIIRules {
		return PIIRules{}, fmt.Errorf("pii rules: %s: more than %d rules", path, MaxPIIRules)
	}
	var out PIIRules
	for i, r := range raw.Mask {
		m, err := ParseMask(r.Pattern)
		if err != nil {
			return PIIRules{}, fmt.Errorf("pii rules: %s: mask rule %d: %w", path, i+1, err)
		}
		out.Mask = append(out.Mask, m)
	}
	for i, r := range raw.Allow {
		a, err := ParseAllow(r.Kind + ":" + r.Value)
		if err != nil {
			return PIIRules{}, fmt.Errorf("pii rules: %s: allow rule %d: %w", path, i+1, err)
		}
		out.Allow = append(out.Allow, a)
	}
	out.Mask, out.Allow = kconfig.SortedSet(out.Mask), kconfig.SortedSet(out.Allow)
	return out, nil
}

// ParseMask checks a mask rule: an RE2 regular expression of at most
// MaxPIIRuleBytes that does not match the empty string. It returns its
// canonical text (the expression, trimmed). Its errors never quote it.
func ParseMask(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return "", errors.New("a mask rule is empty: want a regular expression (RE2), such as cust-[0-9]{6}")
	case len(s) > MaxPIIRuleBytes:
		return "", fmt.Errorf("a mask rule is longer than %d bytes", MaxPIIRuleBytes)
	case !utf8.ValidString(s):
		return "", errors.New("a mask rule is not valid UTF-8")
	}
	re, err := regexp.Compile(s)
	if err != nil {
		return "", errors.New("a mask rule is not a valid regular expression (RE2 syntax)")
	}
	if re.MatchString("") {
		return "", errors.New("a mask rule matches the empty string: it would mask nothing")
	}
	return s, nil
}

// ParseAllow checks an allow rule "kind:value": kind a detector's name but
// secret (a credential is never shown), value not empty. It returns the
// canonical text, kind:value with the value normalised as the detector's
// pseudonyms are (pii.Normalise: an email lower case, an IP canonical).
// Its errors never quote the value.
func ParseAllow(s string) (string, error) {
	kind, value, ok := strings.Cut(strings.TrimSpace(s), ":")
	value = strings.TrimSpace(value)
	switch {
	case !ok || value == "":
		return "", errors.New(`an allow rule wants a kind and a value ("ip:10.0.0.1")`)
	case len(value) > MaxPIIRuleBytes:
		return "", fmt.Errorf("an allow rule's value is longer than %d bytes", MaxPIIRuleBytes)
	case !utf8.ValidString(value) || strings.ContainsAny(value, "\n\r\x00"):
		return "", errors.New("an allow rule's value holds invalid UTF-8 or a line break")
	case kind == "secret":
		return "", errors.New("a secret is never allowed in clear")
	}
	if _, err := pii.Detectors([]string{kind}); err != nil || !pii.ValidKind(kind) {
		return "", errors.New("an allow rule's kind is not a detector (email, phone, iban, card, ip, …)")
	}
	return kind + ":" + pii.Normalise(kind, value), nil
}

// PIIPath is the PII rules file of a console: .lockssh/pii.toml in the
// project root, else pii.toml next to the user config ("" when neither).
func PIIPath(root, userConfig string) string {
	if root != "" {
		return filepath.Join(root, product.P.ProjectDir(), PIIFile)
	}
	if userConfig != "" {
		return filepath.Join(filepath.Dir(userConfig), PIIFile)
	}
	return ""
}

// appendMu serialises AppendMask: the count and the duplicate check stay
// true until the rule is written.
var appendMu sync.Mutex

// AppendMask appends a mask rule (canonical, ParseMask) to the rules file
// as it is on disk, creating it. A rule already in the file is a no-op;
// an add that would take the file beyond MaxPIIRules (mask and allow rules,
// as LoadPII counts them) is refused, and so is an add to a file that does
// not parse: the file always stays loadable.
func AppendMask(path, pattern string) error {
	appendMu.Lock()
	defer appendMu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("pii rules: %w", err)
	}
	var raw rawPII
	if _, err := kconfig.Decode(product.P, data, path, &raw); err != nil {
		return err
	}
	for _, r := range raw.Mask {
		if strings.TrimSpace(r.Pattern) == pattern {
			return nil
		}
	}
	if len(raw.Mask)+len(raw.Allow) >= MaxPIIRules {
		return fmt.Errorf("pii rules: the rules file holds %d rules, the most it may: ask the human to remove some from %s", MaxPIIRules, PIIFile)
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(rawPII{Mask: []rawMask{{Pattern: pattern}}}); err != nil {
		return fmt.Errorf("pii rules: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("pii rules: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("pii rules: %w", err)
	}
	if _, err := f.Write(append([]byte("\n"), buf.Bytes()...)); err != nil {
		f.Close()
		return fmt.Errorf("pii rules: %w", err)
	}
	return f.Close()
}
