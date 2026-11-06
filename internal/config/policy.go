package config

import (
	"fmt"
	"strconv"
	"strings"

	kconfig "github.com/DavidGodefroid/lockkit/config"
)

// Policy is the security-relevant view of one profile: what the console
// fingerprints, compares with the last approved one and asks the human
// about before applying any loosening.
type Policy struct {
	Profile Profile `json:"profile"`
}

var _ kconfig.Policy = Policy{}

// NewPolicy builds the canonical policy of p.
func NewPolicy(p Profile) Policy { return Canonical(Policy{Profile: p}) }

// Canonical sorts and de-duplicates the lists of p: its JSON is the
// fingerprinted form.
func Canonical(p Policy) Policy {
	p.Profile.Detectors = kconfig.SortedSet(p.Profile.Detectors)
	p.Profile.Allow = kconfig.SortedSet(p.Profile.Allow)
	p.Profile.Auto = p.Profile.Auto.canonical()
	return p
}

// Diff lists the changes from approved to p and marks each loosening: a new
// allow rule, exec turned on, another known_hosts file, a removed
// detector, a larger output cap, a longer request timeout, an auto rule
// made looser (deny < ask < auto), and the shared rules of the profile base
// (kconfig.DiffBase: the login, the SSH target, production, credentials).
func (p Policy) Diff(approved kconfig.Policy) []kconfig.Change {
	a, ok := approved.(Policy)
	if !ok {
		return []kconfig.Change{{Field: "policy", Old: fmt.Sprintf("%T", approved), New: "lockssh", Loosens: true}}
	}
	a, c := Canonical(a), Canonical(p)
	ap, cp := a.Profile, c.Profile
	out := kconfig.DiffBase(ap.Base, cp.Base)
	if ap.KnownHosts != cp.KnownHosts {
		out = append(out, kconfig.Change{Field: "known_hosts", Old: orDefault(ap.KnownHosts), New: orDefault(cp.KnownHosts), Loosens: true})
	}
	if ap.Exec != cp.Exec {
		out = append(out, kconfig.Change{Field: "exec", Old: strconv.FormatBool(ap.Exec), New: strconv.FormatBool(cp.Exec), Loosens: cp.Exec})
	}
	out = append(out, kconfig.SetDiff("allow", ap.Allow, cp.Allow, false)...)
	out = append(out, kconfig.SetDiff("detectors", ap.Detectors, cp.Detectors, true)...)
	out = append(out, diffAuto(ap.Auto, cp.Auto)...)
	al, cl := ap.Limits, cp.Limits
	if al.MaxOutputBytes != cl.MaxOutputBytes {
		out = append(out, kconfig.Change{Field: "limits.max_output_bytes", Old: strconv.Itoa(al.MaxOutputBytes), New: strconv.Itoa(cl.MaxOutputBytes), Loosens: cl.MaxOutputBytes > al.MaxOutputBytes})
	}
	if al.RequestTimeout != cl.RequestTimeout {
		out = append(out, kconfig.Change{Field: "limits.request_timeout", Old: al.RequestTimeout.String(), New: cl.RequestTimeout.String(), Loosens: cl.RequestTimeout > al.RequestTimeout})
	}
	return out
}

func orDefault(kh string) string {
	if kh == "" {
		return "(the console account's ~/.ssh/known_hosts)"
	}
	return kh
}

// Describe is the policy as lines for the console's status screen.
func (p Policy) Describe() []string {
	pr := Canonical(p).Profile
	lines := []string{
		"ssh: " + kconfig.SSHString(pr.SSH),
		"known_hosts: " + orDefault(pr.KnownHosts),
		fmt.Sprintf("production: %t · credentials: %s", pr.Production, pr.Credentials),
	}
	if len(pr.Allow) == 0 {
		lines = append(lines, "allow: none")
	}
	for _, r := range pr.Allow {
		lines = append(lines, "allow: "+r)
	}
	exec := "exec: off (a command outside allow is refused)"
	if pr.Exec {
		exec = "exec: ON (a command outside allow may be asked; each one is decided on the approval hub)"
	}
	lines = append(lines, exec,
		fmt.Sprintf("limits: request_timeout %s · max_output_bytes %d", pr.Limits.RequestTimeout, pr.Limits.MaxOutputBytes),
		fmt.Sprintf("session: idle %s · max %s", pr.IdleTimeout, pr.MaxSession),
		"detectors: "+strings.Join(pr.Detectors, ", "),
		"auto rules (lox run): "+pr.Auto.String(),
	)
	return lines
}
