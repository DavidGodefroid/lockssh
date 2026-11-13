package config

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/managed"
	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/lockssh/internal/command"
	"github.com/DavidGodefroid/lockssh/internal/product"
)

// Tool is lockssh's section of the company's managed file.
const Tool = "lockssh"

// Managed keys lockssh cites besides its bounds.
const (
	keyBounds        = Tool + "." + managed.KindBounds
	keyVaultRequired = "family.vault.required"
)

// Managed is the [lockssh] section of the company's managed file
// (lockfamily's docs/managed.md), parsed and checked, with the [family]
// rules lockssh enforces. The precedence is lockkit's: managed bounds and
// profiles > project file > user file > managed defaults > built-in
// defaults. A nil *Managed is no managed file: every method then leaves
// the configuration as it is.
type Managed struct {
	File *managed.File

	defaults    *rawProfile
	defaultsSet definedFunc
	profiles    map[string]Profile
	bounds      *bounds
	// vaultRequired is [family] vault.required: credentials = "vault" only.
	vaultRequired bool
}

// definedFunc reports a key a table sets ("limits", "max_session").
type definedFunc func(key ...string) bool

// bounds are [lockssh.bounds], checked.
type bounds struct {
	production     bool
	hosts          []string
	knownHosts     *string
	auth           []string
	credentials    []string
	exec           *bool
	allow          []string
	allowSet       bool
	auto           AutoRules
	credentialsTTL time.Duration
	maxOutputBytes int
	requestTimeout time.Duration
	idleTimeout    time.Duration
	maxSession     time.Duration
	detectors      []string
	masks          []string
	maskRes        []*regexp.Regexp
}

// LoadManaged reads the machine's managed file (managed.Load) and parses
// its [lockssh] section. No file is nil and no error; a refused file (badly
// owned, invalid, badly signed) or an invalid section is an error: the
// caller refuses to go on.
func LoadManaged(ctx context.Context) (*Managed, error) {
	f, err := managed.Load(ctx)
	if err != nil {
		return nil, err
	}
	return NewManaged(f)
}

// NewManaged parses the [lockssh] section of f: nil for a nil f. A
// default or a managed profile beyond the bounds is an error.
func NewManaged(f *managed.File) (*Managed, error) {
	if f == nil {
		return nil, nil
	}
	m := &Managed{File: f, vaultRequired: f.Family.Vault != nil && f.Family.Vault.Required}
	var rb mBounds[*mAuto]
	ok, err := f.Decode(&rb, Tool, managed.KindBounds)
	if err != nil {
		// A preset is no bound: say so rather than a type error.
		var preset mBounds[*string]
		if _, err2 := f.Decode(&preset, Tool, managed.KindBounds); err2 == nil && preset.Auto != nil {
			return nil, fmt.Errorf("managed: %s.auto: a preset (%q) bounds nothing: set a table of actions (%s)", keyBounds, FullAuto, strings.Join(AutoActions, ", "))
		}
		return nil, err
	}
	if ok {
		if m.bounds, err = parseBounds(rb); err != nil {
			return nil, fmt.Errorf("managed: %s: %w", keyBounds, err)
		}
	}
	ok, d, set, err := decodeManagedProfile(f, Tool, managed.KindDefaults)
	if err != nil {
		return nil, err
	}
	if ok {
		m.defaults, m.defaultsSet = &d, set
		if err := m.checkDefaults(); err != nil {
			return nil, err
		}
	}
	names := f.Profiles(Tool)
	m.profiles = make(map[string]Profile, len(names))
	for _, n := range names {
		_, r, set, err := decodeManagedProfile(f, Tool, managed.KindProfiles, n)
		if err != nil {
			return nil, err
		}
		p, err := m.build(n, r, set)
		if err != nil {
			return nil, fmt.Errorf("managed: %s.%s.%s: %w", Tool, managed.KindProfiles, n, err)
		}
		if vs := m.Violations(NewPolicy(p)); len(vs) > 0 {
			return nil, fmt.Errorf("managed: %s.%s.%s is beyond the managed bounds: %s", Tool, managed.KindProfiles, n, vs[0])
		}
		m.profiles[n] = p
	}
	return m, nil
}

// The managed tables as managed.File.Decode reads them: strictly, into
// typed fields only (it refuses the keys of a free table), every key a
// pointer so that a key the table sets is known. The auto key is a table
// of actions, or the full-auto preset in a profile (mProfile[*string]).
type (
	mAuto struct {
		Connect *string `toml:"connect"`
		Run     *string `toml:"run"`
		Exec    *string `toml:"exec"`
		Unmask  *string `toml:"unmask"`
	}
	mLimits struct {
		RequestTimeout *string `toml:"request_timeout"`
		MaxOutputBytes *int    `toml:"max_output_bytes"`
		IdleTimeout    *string `toml:"idle_timeout"`
		MaxSession     *string `toml:"max_session"`
	}
	mProfile[A any] struct {
		Host           *string   `toml:"host"`
		Port           *int      `toml:"port"`
		User           *string   `toml:"user"`
		Auth           *string   `toml:"auth"`
		Key            *string   `toml:"key"`
		KnownHosts     *string   `toml:"known_hosts"`
		Credentials    *string   `toml:"credentials"`
		VaultPath      *string   `toml:"vault_path"`
		CredentialsTTL *string   `toml:"credentials_ttl"`
		Production     *bool     `toml:"production"`
		Exec           *bool     `toml:"exec"`
		Allow          *[]string `toml:"allow"`
		Detectors      *[]string `toml:"detectors"`
		Limits         *mLimits  `toml:"limits"`
		Auto           A         `toml:"auto"`
	}
	mBounds[A any] struct {
		Production     bool      `toml:"production"`
		Hosts          []string  `toml:"hosts"`
		KnownHosts     *string   `toml:"known_hosts"`
		Auth           []string  `toml:"auth"`
		Credentials    []string  `toml:"credentials"`
		Exec           *bool     `toml:"exec"`
		Allow          *[]string `toml:"allow"`
		Auto           A         `toml:"auto"`
		CredentialsTTL string    `toml:"credentials_ttl"`
		Limits         rawLimits `toml:"limits"`
		Detectors      []string  `toml:"detectors"`
		PIIMask        []rawMask `toml:"pii_mask"`
	}
)

func (a *mAuto) table() map[string]any {
	out := map[string]any{}
	for _, f := range []struct {
		k string
		v *string
	}{{ActConnect, a.Connect}, {ActRun, a.Run}, {ActExec, a.Exec}, {ActUnmask, a.Unmask}} {
		if f.v != nil {
			out[f.k] = *f.v
		}
	}
	return out
}

// decodeManagedProfile decodes the profile-shaped table of f at key: the
// raw profile and the keys it sets.
func decodeManagedProfile(f *managed.File, key ...string) (bool, rawProfile, definedFunc, error) {
	var t mProfile[*mAuto]
	var auto any
	ok, err := f.Decode(&t, key...)
	switch {
	case err == nil && t.Auto != nil:
		auto = t.Auto.table()
	case err != nil:
		// auto = "full-auto" does not decode as a table.
		var s mProfile[*string]
		if ok, err = f.Decode(&s, key...); err != nil {
			_, err = f.Decode(&t, key...)
			return false, rawProfile{}, nil, err
		}
		t = mProfile[*mAuto]{Host: s.Host, Port: s.Port, User: s.User, Auth: s.Auth, Key: s.Key, KnownHosts: s.KnownHosts,
			Credentials: s.Credentials, VaultPath: s.VaultPath, CredentialsTTL: s.CredentialsTTL, Production: s.Production,
			Exec: s.Exec, Allow: s.Allow, Detectors: s.Detectors, Limits: s.Limits}
		if s.Auto != nil {
			auto = *s.Auto
		}
	}
	if !ok {
		return false, rawProfile{}, nil, nil
	}
	var r rawProfile
	set := map[string]bool{}
	str := func(k string, src *string, dst *string) {
		if src != nil {
			*dst, set[k] = *src, true
		}
	}
	str("host", t.Host, &r.Host)
	str("user", t.User, &r.User)
	str("auth", t.Auth, &r.Auth)
	str("key", t.Key, &r.Key)
	str("known_hosts", t.KnownHosts, &r.KnownHosts)
	str("credentials", t.Credentials, &r.Credentials)
	str("vault_path", t.VaultPath, &r.VaultPath)
	str("credentials_ttl", t.CredentialsTTL, &r.CredentialsTTL)
	if t.Port != nil {
		r.Port, set["port"] = *t.Port, true
	}
	if t.Production != nil {
		r.Production, set["production"] = *t.Production, true
	}
	if t.Exec != nil {
		r.Exec, set["exec"] = *t.Exec, true
	}
	if t.Allow != nil {
		r.Allow, set["allow"] = *t.Allow, true
	}
	if t.Detectors != nil {
		r.Detectors, set["detectors"] = *t.Detectors, true
	}
	if auto != nil {
		r.Auto.v, set["auto"] = auto, true
	}
	if l := t.Limits; l != nil {
		str("limits.request_timeout", l.RequestTimeout, &r.Limits.RequestTimeout)
		str("limits.idle_timeout", l.IdleTimeout, &r.Limits.IdleTimeout)
		str("limits.max_session", l.MaxSession, &r.Limits.MaxSession)
		if l.MaxOutputBytes != nil {
			r.Limits.MaxOutputBytes, set["limits.max_output_bytes"] = *l.MaxOutputBytes, true
		}
	}
	for _, f := range []struct{ key, val string }{{"host", r.Host}, {"user", r.User}, {"key", r.Key},
		{"known_hosts", r.KnownHosts}, {"vault_path", r.VaultPath}} {
		if err := kconfig.CheckValue(product.P, f.key, f.val); err != nil {
			return false, rawProfile{}, nil, fmt.Errorf("managed: [%s]: %v", strings.Join(key, "."), err)
		}
	}
	return true, r, func(key ...string) bool {
		k := strings.Join(key, ".")
		if set[k] {
			return true
		}
		for s := range set {
			if strings.HasPrefix(s, k+".") {
				return true
			}
		}
		return false
	}, nil
}

func parseBounds(rb mBounds[*mAuto]) (*bounds, error) {
	b := &bounds{production: rb.Production, knownHosts: rb.KnownHosts, exec: rb.Exec}
	if rb.KnownHosts != nil {
		if err := kconfig.CheckValue(product.P, "known_hosts", *rb.KnownHosts); err != nil {
			return nil, fmt.Errorf("known_hosts: %v", err)
		}
	}
	for _, h := range rb.Hosts {
		if h == "" || strings.ContainsAny(h, "@/ :") {
			return nil, errors.New("hosts: want host name patterns (*, ?), such as \"*.corp.example\"")
		}
		if _, err := path.Match(h, ""); err != nil {
			return nil, errors.New("hosts: a pattern is not valid (*, ? and [...] only)")
		}
	}
	if rb.Hosts != nil {
		b.hosts = kconfig.SortedSet(rb.Hosts)
	}
	for _, a := range rb.Auth {
		if a != AuthKey && a != AuthPassword {
			return nil, errors.New(`auth: want "key" and/or "password"`)
		}
	}
	if rb.Auth != nil {
		b.auth = kconfig.SortedSet(rb.Auth)
	}
	for _, c := range rb.Credentials {
		switch c {
		case CredentialsNone, kconfig.CredentialsAsk, kconfig.CredentialsKeychain, kconfig.CredentialsVault:
		default:
			return nil, errors.New("credentials: want none, ask, keychain and/or vault")
		}
	}
	if rb.Credentials != nil {
		b.credentials = kconfig.SortedSet(rb.Credentials)
	}
	if rb.Allow != nil {
		b.allow, b.allowSet = command.Canonical(*rb.Allow), true
		if _, err := command.ParseRules(b.allow); err != nil {
			return nil, fmt.Errorf("allow: %v", err)
		}
		b.allow = kconfig.SortedSet(b.allow)
	}
	var rawA any
	if rb.Auto != nil {
		rawA = rb.Auto.table()
	}
	auto, err := parseAuto(rawA)
	if err != nil {
		return nil, err
	}
	b.auto = auto
	for _, f := range []struct {
		key, val string
		dst      *time.Duration
	}{
		{"credentials_ttl", rb.CredentialsTTL, &b.credentialsTTL},
		{"limits.request_timeout", rb.Limits.RequestTimeout, &b.requestTimeout},
		{"limits.idle_timeout", rb.Limits.IdleTimeout, &b.idleTimeout},
		{"limits.max_session", rb.Limits.MaxSession, &b.maxSession},
	} {
		if f.val == "" {
			continue
		}
		d, err := time.ParseDuration(f.val)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("%s: want a positive duration such as \"30s\" or \"20m\"", f.key)
		}
		*f.dst = d
	}
	if rb.Limits.MaxOutputBytes < 0 {
		return nil, errors.New("limits.max_output_bytes must not be negative")
	}
	b.maxOutputBytes = rb.Limits.MaxOutputBytes
	if rb.Detectors != nil {
		if _, err := pii.Detectors(rb.Detectors); err != nil {
			return nil, fmt.Errorf("detectors: %v", err)
		}
		b.detectors = kconfig.SortedSet(rb.Detectors)
	}
	if len(rb.PIIMask) > MaxPIIRules {
		return nil, fmt.Errorf("pii_mask: more than %d rules", MaxPIIRules)
	}
	for i, r := range rb.PIIMask {
		mk, err := ParseMask(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("pii_mask rule %d: %w", i+1, err)
		}
		b.masks = append(b.masks, mk)
	}
	b.masks = kconfig.SortedSet(b.masks)
	for _, mk := range b.masks {
		b.maskRes = append(b.maskRes, regexp.MustCompile(mk))
	}
	if len(b.masks) == 0 {
		b.masks = nil
	}
	return b, nil
}

// fillDefaults sets the keys of r that the profile's table does not set
// (set) to the managed defaults that set them.
func (m *Managed) fillDefaults(r rawProfile, set definedFunc) rawProfile {
	if m == nil || m.defaults == nil {
		return r
	}
	d, dset := *m.defaults, m.defaultsSet
	take := func(key ...string) bool { return !set(key...) && dset(key...) }
	if take("host") {
		r.Host = d.Host
	}
	if take("port") {
		r.Port = d.Port
	}
	if take("user") {
		r.User = d.User
	}
	if take("auth") {
		r.Auth = d.Auth
	}
	if take("key") {
		r.Key = d.Key
	}
	if take("known_hosts") {
		r.KnownHosts = d.KnownHosts
	}
	if take("credentials") {
		r.Credentials = d.Credentials
	}
	if take("vault_path") {
		r.VaultPath = d.VaultPath
	}
	if take("credentials_ttl") {
		r.CredentialsTTL = d.CredentialsTTL
	}
	if take("production") {
		r.Production = d.Production
	}
	if take("exec") {
		r.Exec = d.Exec
	}
	if take("allow") {
		r.Allow = slices.Clone(d.Allow)
	}
	if take("detectors") {
		r.Detectors = slices.Clone(d.Detectors)
	}
	if take("auto") {
		r.Auto = d.Auto
	}
	if take("limits", "request_timeout") {
		r.Limits.RequestTimeout = d.Limits.RequestTimeout
	}
	if take("limits", "max_output_bytes") {
		r.Limits.MaxOutputBytes = d.Limits.MaxOutputBytes
	}
	if take("limits", "idle_timeout") {
		r.Limits.IdleTimeout = d.Limits.IdleTimeout
	}
	if take("limits", "max_session") {
		r.Limits.MaxSession = d.Limits.MaxSession
	}
	return r
}

// build is buildProfile after the managed defaults, with the required
// detectors added.
func (m *Managed) build(name string, r rawProfile, set definedFunc) (Profile, error) {
	r = m.fillDefaults(r, set)
	detectorsSet := set("detectors") || (m != nil && m.defaults != nil && m.defaultsSet("detectors"))
	p, err := buildProfile(name, r, detectorsSet)
	if err != nil {
		return Profile{}, err
	}
	if m != nil && m.bounds != nil && len(m.bounds.detectors) > 0 {
		p.Detectors = kconfig.SortedSet(append(p.Detectors, m.bounds.detectors...))
	}
	return p, nil
}

// checkDefaults refuses a managed default beyond the bounds: the defaults
// are built as a profile (with placeholders for the target keys they leave
// unset), and only the violations of keys they set count.
func (m *Managed) checkDefaults() error {
	d := *m.defaults
	if d.Host == "" {
		d.Host = "managed-defaults"
	}
	if d.User == "" {
		d.User = "managed-defaults"
	}
	if d.Key == "" && (d.Auth == "" || d.Auth == AuthKey) {
		d.Key = "managed-defaults"
	}
	p, err := buildProfile("managed-defaults", d, m.defaultsSet("detectors"))
	if err != nil {
		return fmt.Errorf("managed: %s.%s: %w", Tool, managed.KindDefaults, err)
	}
	for _, v := range m.Violations(NewPolicy(p)) {
		if m.defaultsSet(defaultKey(v.Field)...) {
			v.Profile = Tool + "." + managed.KindDefaults
			return fmt.Errorf("managed: a default is beyond the managed bounds: %s", v)
		}
	}
	return nil
}

// defaultKey is the profile key of a Diff field ("ssh.host" is host,
// "auto.exec" is auto, "limits.max_session" is limits.max_session).
func defaultKey(field string) []string {
	field = strings.TrimPrefix(field, "ssh.")
	if strings.HasPrefix(field, "auto.") {
		return []string{"auto"}
	}
	return strings.Split(field, ".")
}

// Profiles are the managed profiles, as built (nil without a file).
func (m *Managed) Profiles() map[string]Profile {
	if m == nil {
		return nil
	}
	return m.profiles
}

// ProfileNames are the managed profiles' names, sorted.
func (m *Managed) ProfileNames() []string {
	if m == nil {
		return nil
	}
	return m.File.Profiles(Tool)
}

// Masks are the always-on PII mask rules (lockssh.bounds.pii_mask), in
// canonical form.
func (m *Managed) Masks() []string {
	if m == nil || m.bounds == nil {
		return nil
	}
	return slices.Clone(m.bounds.masks)
}

// WithPII is r with the managed mask rules added. An allow rule whose
// value a managed mask rule matches is refused: it would ask to show in
// clear what the company masks.
func (m *Managed) WithPII(r PIIRules) (PIIRules, error) {
	if m == nil || m.bounds == nil || len(m.bounds.masks) == 0 {
		return r, nil
	}
	for i, a := range r.Allow {
		_, value, _ := strings.Cut(a, ":")
		for _, re := range m.bounds.maskRes {
			if re.MatchString(value) {
				// The value is personal data: never quoted.
				return PIIRules{}, fmt.Errorf("pii rules: allow rule %d would show in clear a value %s.pii_mask masks: remove it", i+1, keyBounds)
			}
		}
	}
	r.Mask = kconfig.SortedSet(append(slices.Clone(r.Mask), m.bounds.masks...))
	return r, nil
}

// Bounds are the managed bounds applied to p: managed.Bounds with p at
// its ceiling, and the violations of the allowlist bounds that Diff cannot
// express (hosts, auth, credentials, family.vault.required). A nil
// Ceiling bounds nothing.
func (m *Managed) Bounds(p Policy) (managed.Bounds, []managed.Violation) {
	out := managed.Bounds{Tool: Tool, Profile: p.Profile.Name}
	if m == nil {
		return out, nil
	}
	pr := p.Profile
	var vs []managed.Violation
	cite := func(key, field, value string, allowed []string) {
		vs = append(vs, managed.Violation{Key: key, Profile: pr.Name, Field: field, Value: value, Bound: strings.Join(allowed, ", ")})
	}
	if m.vaultRequired && pr.Credentials != kconfig.CredentialsVault {
		cite(keyVaultRequired, "credentials", pr.Credentials, []string{kconfig.CredentialsVault})
	}
	b := m.bounds
	if b == nil {
		return out, vs
	}
	if b.hosts != nil && !slices.ContainsFunc(b.hosts, func(pat string) bool { ok, _ := path.Match(pat, pr.Host()); return ok }) {
		cite(keyBounds+".hosts", "host", pr.Host(), b.hosts)
	}
	if b.auth != nil && !slices.Contains(b.auth, pr.Auth()) {
		cite(keyBounds+".auth", "auth", pr.Auth(), b.auth)
	}
	if b.credentials != nil && !slices.Contains(b.credentials, pr.Credentials) {
		cite(keyBounds+".credentials", "credentials", pr.Credentials, b.credentials)
	}
	c := Canonical(p)
	cp := &c.Profile
	cp.Allow, cp.Detectors = slices.Clone(cp.Allow), slices.Clone(cp.Detectors)
	if b.production {
		cp.Production = true
	}
	if b.knownHosts != nil {
		cp.KnownHosts = *b.knownHosts
	}
	if b.exec != nil {
		cp.Exec = *b.exec
	}
	if b.allowSet {
		cp.Allow = slices.Clone(b.allow)
	}
	for _, act := range AutoActions {
		if v := *b.auto.field(act); v != "" {
			*cp.Auto.field(act) = v
		}
	}
	if b.credentialsTTL > 0 {
		cp.CredentialsTTL = b.credentialsTTL
	}
	if b.maxOutputBytes > 0 {
		cp.Limits.MaxOutputBytes = b.maxOutputBytes
	}
	if b.requestTimeout > 0 {
		cp.Limits.RequestTimeout = b.requestTimeout
	}
	if b.idleTimeout > 0 {
		cp.IdleTimeout = b.idleTimeout
	}
	if b.maxSession > 0 {
		cp.MaxSession = b.maxSession
	}
	out.Ceiling = Canonical(c)
	return out, vs
}

// Violations are every field of p beyond the managed bounds: the
// allowlist bounds first, then managed.Check against the ceiling.
func (m *Managed) Violations(p Policy) []managed.Violation {
	b, vs := m.Bounds(p)
	return append(vs, managed.Check(p, b)...)
}

// Describe is the [lockssh] section in force, as lines for `lockssh
// managed show`: the bounds, then the defaults.
func (m *Managed) Describe() []string {
	if m == nil {
		return nil
	}
	var out []string
	if m.vaultRequired {
		out = append(out, keyVaultRequired+" = true (credentials = vault only)")
	}
	if b := m.bounds; b != nil {
		add := func(key, val string) { out = append(out, keyBounds+"."+key+" = "+val) }
		list := func(s []string) string { return "[" + strings.Join(s, ", ") + "]" }
		if b.production {
			add("production", "true")
		}
		if b.hosts != nil {
			add("hosts", list(b.hosts))
		}
		if b.knownHosts != nil {
			add("known_hosts", orDefault(*b.knownHosts))
		}
		if b.auth != nil {
			add("auth", list(b.auth))
		}
		if b.credentials != nil {
			add("credentials", list(b.credentials))
		}
		if b.exec != nil {
			add("exec", strconv.FormatBool(*b.exec))
		}
		if b.allowSet {
			add("allow", list(b.allow))
		}
		for _, act := range AutoActions {
			if v := *b.auto.field(act); v != "" {
				add("auto."+act, string(v))
			}
		}
		for _, d := range []struct {
			key string
			v   time.Duration
		}{{"credentials_ttl", b.credentialsTTL}, {"limits.request_timeout", b.requestTimeout},
			{"limits.idle_timeout", b.idleTimeout}, {"limits.max_session", b.maxSession}} {
			if d.v > 0 {
				add(d.key, d.v.String())
			}
		}
		if b.maxOutputBytes > 0 {
			add("limits.max_output_bytes", strconv.Itoa(b.maxOutputBytes))
		}
		if b.detectors != nil {
			add("detectors", list(b.detectors))
		}
		if len(b.masks) > 0 {
			add("pii_mask", fmt.Sprintf("%d rule(s)", len(b.masks)))
		}
	}
	if m.defaults != nil {
		var keys []string
		for _, k := range []string{"host", "port", "user", "auth", "key", "known_hosts", "credentials", "vault_path",
			"credentials_ttl", "production", "exec", "allow", "detectors", "auto", "limits"} {
			if m.defaultsSet(k) {
				keys = append(keys, k)
			}
		}
		out = append(out, Tool+"."+managed.KindDefaults+": "+strings.Join(keys, ", "))
	}
	return out
}
