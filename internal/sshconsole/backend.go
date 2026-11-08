// Package sshconsole is lockssh's console backend for lockkit: its IPC
// methods (op.plan, op.run), the SSH connection behind them, the account
// check, its policy. lockkit's console holds the terminal, the approval
// screens, the hub, the modes and the audit log.
package sshconsole

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sync"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/pii"
	"github.com/DavidGodefroid/lockkit/sanitize"

	"github.com/DavidGodefroid/lockssh/internal/config"
	"github.com/DavidGodefroid/lockssh/internal/product"
)

// IPC methods of lockssh, beyond lockkit's own.
const (
	MethodRun  = "op.run"
	MethodPlan = "op.plan"
)

// Options locate the profile a console serves.
type Options struct {
	Profile string
	// Root is the project root ("" for a profile of the user config).
	Root string
	// UserConfig is the user config file ("" for none).
	UserConfig string
	// StateDir is the state base of the console (console.Options.StateDir;
	// "" is kit.StateBase()): Connect reads the approved policy there.
	StateDir string
	// IO answers the host key question (the console's terminal).
	IO console.IO
	// Home is the console account's home ("" is os.UserHomeDir()): "~/"
	// in key and the default known_hosts file.
	Home string
}

// Backend implements console.Backend.
type Backend struct {
	o Options

	mu sync.Mutex
	// cur is the session Connect opened last. lockkit may hand Env.Session
	// back wrapped (a Vault lease), so handlers use cur, the session the
	// console vouches for once Env.Session returned without error.
	cur *session
	// granted is the session whose connect ticket was approved, in hub
	// mode (ensureConnect), under the policy of fingerprint grantedFP;
	// humanFP is the fingerprint of the policy under which a human last
	// approved a connect ticket in this console run. connMu serialises
	// the asking, so that the requests of one session share one ticket.
	connMu    sync.Mutex
	granted   *session
	grantedFP string
	humanFP   string
	// clock is the time of the connect tickets (nil: time.Now).
	clock func() time.Time

	// epoch keys the pseudonyms of the console run: the same value masks
	// to the same pseudonym in every output of the run, and to another one
	// in the next run. Memory only.
	epoch *pii.Pseudonymizer
}

// New returns the backend of o.Profile.
func New(o Options) (*Backend, error) {
	ep, err := pii.NewEpoch(time.Now())
	if err != nil {
		return nil, err
	}
	return &Backend{o: o, epoch: ep}, nil
}

var _ console.Backend = (*Backend)(nil)

// Sanitizer scrubs lockssh's error text: URL userinfo, after the secrets
// lockkit knows.
func Sanitizer() *sanitize.Sanitizer {
	return sanitize.New(sanitize.URLUserinfo, regexp.MustCompile(`(?i)password[=:]\s*\S+`))
}

// Methods implements console.Backend.
func (b *Backend) Methods() map[string]console.Handler {
	return map[string]console.Handler{MethodRun: b.run, MethodPlan: b.plan}
}

// LoadPolicy implements console.Backend: the profile from the config files,
// in canonical form.
func (b *Backend) LoadPolicy() (console.Policy, error) {
	var profiles map[string]config.Profile
	var err error
	if b.o.Root != "" {
		profiles, _, err = config.LoadFrom(b.o.Root, b.o.UserConfig)
	} else if b.o.UserConfig != "" {
		profiles, err = config.LoadFile(b.o.UserConfig)
	} else {
		err = errors.New("no config file")
	}
	if err != nil {
		return nil, err
	}
	pr, ok := profiles[b.o.Profile]
	if !ok {
		return nil, fmt.Errorf("no profile %q in the config files", b.o.Profile)
	}
	pol := config.NewPolicy(pr)
	if path := b.piiPath(); path != "" {
		r, err := config.LoadPII(path)
		if err != nil {
			return nil, err
		}
		pol = pol.WithPII(r)
	}
	return Policy{pol}, nil
}

// piiPath is the PII rules file of the console's profile ("" for none).
func (b *Backend) piiPath() string { return config.PIIPath(b.o.Root, b.o.UserConfig) }

var _ console.PIIBackend = (*Backend)(nil)

// PIIRules implements console.PIIBackend: the mask and allow rules of the
// policy (.lockssh/pii.toml).
func (b *Backend) PIIRules(p console.Policy) (mask, allow []string) {
	pol, ok := p.(Policy)
	if !ok {
		return nil, nil
	}
	return slices.Clone(pol.Mask), slices.Clone(pol.Allow)
}

// CheckMask implements console.PIIBackend: a mask rule is a regular
// expression (RE2) that does not match the empty string.
func (b *Backend) CheckMask(pattern string) (string, error) { return config.ParseMask(pattern) }

// SaveMask implements console.PIIBackend: the rule is appended to the
// rules file on disk, once, and never beyond config.MaxPIIRules.
func (b *Backend) SaveMask(pattern string) error {
	path := b.piiPath()
	if path == "" {
		return errors.New("no rules file: start the console in a project")
	}
	m, err := config.ParseMask(pattern)
	if err != nil {
		return err
	}
	return config.AppendMask(path, m)
}

// WithMask implements console.PIIBackend.
func (b *Backend) WithMask(p console.Policy, pattern string) console.Policy {
	pol, ok := p.(Policy)
	if !ok {
		return p
	}
	return Policy{pol.WithPII(config.PIIRules{Mask: append(slices.Clone(pol.Mask), pattern), Allow: pol.Allow})}
}

// inForce is the approved policy (the console saves it before it
// connects), else the files' policy.
func (b *Backend) inForce() (Policy, error) {
	state := b.o.StateDir
	if state == "" {
		var err error
		if state, err = kit.StateBase(); err != nil {
			return Policy{}, err
		}
	}
	var ap Policy
	ok, err := kconfig.LoadApproved(product.P, state, kconfig.ApprovedKey(b.o.Root, b.o.Profile), &ap)
	if err != nil {
		return Policy{}, err
	}
	if ok {
		return ap, nil
	}
	cur, err := b.LoadPolicy()
	if err != nil {
		return Policy{}, err
	}
	return cur.(Policy), nil
}

func (b *Backend) session() *session {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cur
}

// Checks implements console.Backend: a root login can do anything on the
// host; lockkit refuses it on production and asks for a typed "continue"
// elsewhere.
func (b *Backend) Checks(_ context.Context, _ console.Session) []console.Finding {
	s := b.session()
	if s == nil {
		return []console.Finding{{Refuse: true, Text: "no SSH session to check"}}
	}
	switch s.uid {
	case "0":
		return []console.Finding{{Text: "the SSH account is root (uid 0): every command the agent is allowed runs with every privilege; use an account of its own with only the rights the allow list needs"}}
	case "":
		return []console.Finding{{Text: "the SSH account's uid could not be read (`id -u` failed): the console cannot tell whether it is root"}}
	}
	return nil
}

// Status implements console.Backend: the SSH side of the session and the
// profile's command rules, from the approved policy.
func (b *Backend) Status(console.Session) any {
	s := b.session()
	if s == nil {
		return nil
	}
	out := map[string]any{"host_key": s.hostKey, "user": s.user, "uid": s.uid}
	if pol, err := b.inForce(); err == nil {
		pr := pol.Policy.Profile
		out["allow"] = nonNil(pr.Allow)
		out["exec"] = pr.Exec
		out["auto"] = pr.Auto.Effective()
		out["max_output_bytes"] = pr.Limits.MaxOutputBytes
		out["request_timeout"] = pr.Limits.RequestTimeout.String()
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
