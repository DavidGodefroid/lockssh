// Package config loads lockssh profiles from the project and user config
// files, applies the defaults, refuses anything that looks like a secret,
// and computes the security-relevant policy of a profile. The file lookup,
// the secret-safe decoding, the shared profile base and the diff helpers
// are lockkit's.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/lockssh/internal/command"
	"github.com/DavidGodefroid/lockssh/internal/product"
)

// Authentication methods of a profile.
const (
	AuthKey      = kconfig.SSHAuthKey
	AuthPassword = kconfig.SSHAuthPassword
)

// CredentialsNone is the credentials mode of an unencrypted key: the
// console asks for nothing.
const CredentialsNone = console.CredentialsNone

// Limits bound one command.
type Limits struct {
	// RequestTimeout ends a command that runs longer (its session is
	// closed; the result says timed_out).
	RequestTimeout time.Duration `json:"request_timeout"`
	// MaxOutputBytes caps stdout and stderr, each, before masking.
	MaxOutputBytes int `json:"max_output_bytes"`
}

// Profile is one SSH host with its policy. It never holds a secret. Its
// SSH target is Base.SSH (host, port, user, auth, key, credentials), so
// that lockkit's console treats a change of any of them as a connection
// change.
type Profile struct {
	Name string `json:"name"`
	kconfig.Base
	// KnownHosts is the known_hosts file the host key is checked against;
	// "" is the console account's ~/.ssh/known_hosts, where an unknown key
	// may be trusted on the console.
	KnownHosts string `json:"known_hosts,omitempty"`
	// Exec lets the agent ask for a command no allow rule matches (each
	// one a ticket the human decides).
	Exec bool `json:"exec"`
	// Allow are the allow rules in canonical text form, sorted.
	Allow     []string `json:"allow"`
	Detectors []string `json:"detectors"`
	Limits    Limits   `json:"limits"`
	// Auto are the profile's auto rules (`lox run`'s auto mode).
	Auto AutoRules `json:"auto,omitzero"`
}

type rawLimits struct {
	RequestTimeout string `toml:"request_timeout"`
	MaxOutputBytes int    `toml:"max_output_bytes"`
	IdleTimeout    string `toml:"idle_timeout"`
	MaxSession     string `toml:"max_session"`
}

type rawProfile struct {
	Host           string    `toml:"host"`
	Port           int       `toml:"port"`
	User           string    `toml:"user"`
	Auth           string    `toml:"auth"`
	Key            string    `toml:"key"`
	KnownHosts     string    `toml:"known_hosts"`
	Credentials    string    `toml:"credentials"`
	VaultPath      string    `toml:"vault_path"`
	CredentialsTTL string    `toml:"credentials_ttl"`
	Production     bool      `toml:"production"`
	Exec           bool      `toml:"exec"`
	Allow          []string  `toml:"allow"`
	Detectors      []string  `toml:"detectors"`
	Limits         rawLimits `toml:"limits"`
	// Auto is "full-auto" or a table of action = auto|ask|deny.
	Auto rawAuto `toml:"auto"`
}

type rawFile struct {
	Profiles map[string]rawProfile `toml:"profiles"`
}

// Load reads the project config (found by walking up from cwd) and the user
// config. On a profile name present in both, the project profile wins as a
// whole. It also returns the project root ("" when none).
func Load(cwd string) (map[string]Profile, string, error) {
	userPath, _ := kconfig.UserConfigPath(product.P)
	return LoadFrom(cwd, userPath)
}

// LoadFrom is Load with an explicit user config path ("" for none). A
// missing user config file is not an error.
func LoadFrom(cwd, userConfigPath string) (map[string]Profile, string, error) {
	out := map[string]Profile{}
	if userConfigPath != "" {
		ps, err := loadFile(userConfigPath)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, "", err
		}
		for n, p := range ps {
			out[n] = p
		}
	}
	root, ok := kconfig.FindProjectRoot(product.P, cwd)
	if !ok {
		return out, "", nil
	}
	ps, err := loadFile(kconfig.ProjectConfigPath(product.P, root))
	if err != nil {
		return nil, "", err
	}
	for n, p := range ps {
		out[n] = p
	}
	return out, root, nil
}

// LoadFile reads the profiles of one config file.
func LoadFile(path string) (map[string]Profile, error) { return loadFile(path) }

func loadFile(path string) (map[string]Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return ParseProfiles(data, filepath.Clean(path))
}

// ParseProfiles decodes and validates config data; name labels errors.
// Errors never quote a value that could hold a secret.
func ParseProfiles(data []byte, name string) (map[string]Profile, error) {
	var raw rawFile
	md, err := kconfig.Decode(product.P, data, name, &raw)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(raw.Profiles))
	for pn := range raw.Profiles {
		names = append(names, pn)
	}
	sort.Strings(names)
	out := make(map[string]Profile, len(names))
	for _, pn := range names {
		p, err := buildProfile(pn, raw.Profiles[pn], md.IsDefined("profiles", pn, "detectors"))
		if err != nil {
			return nil, fmt.Errorf("config: %s: %w", name, err)
		}
		out[pn] = p
	}
	return out, nil
}

func buildProfile(name string, r rawProfile, detectorsSet bool) (Profile, error) {
	if err := kconfig.CheckProfileName(name, r.Production); err != nil {
		return Profile{}, err
	}
	errf := func(format string, a ...any) error {
		return fmt.Errorf("profile %q: "+format, append([]any{name}, a...)...)
	}
	for _, f := range []struct{ key, val string }{{"host", r.Host}, {"user", r.User}, {"key", r.Key},
		{"known_hosts", r.KnownHosts}, {"vault_path", r.VaultPath}} {
		if err := kconfig.CheckValue(product.P, f.key, f.val); err != nil {
			return Profile{}, errf("%v", err)
		}
	}
	switch {
	case r.Host == "":
		return Profile{}, errf("host is required")
	case strings.ContainsAny(r.Host, "@/ :") && !strings.HasPrefix(r.Host, "["):
		return Profile{}, errf("host: a host name or an address only (no user, port, path or scheme)")
	case r.User == "":
		return Profile{}, errf("user is required (the SSH login)")
	case r.Port < 0 || r.Port > 65535:
		return Profile{}, errf("port out of range")
	}
	host := strings.TrimSuffix(strings.TrimPrefix(r.Host, "["), "]")
	auth := r.Auth
	if auth == "" {
		auth = AuthKey
	}
	switch auth {
	case AuthKey:
		if r.Key == "" {
			return Profile{}, errf(`key is required with auth = "key" (the private key file, in the console account)`)
		}
	case AuthPassword:
		if r.Key != "" {
			return Profile{}, errf(`key is only used with auth = "key"`)
		}
	default:
		return Profile{}, errf(`auth must be "key" or "password"`)
	}
	cred := r.Credentials
	switch cred {
	case "":
		cred = kconfig.CredentialsAsk
		if auth == AuthKey {
			cred = CredentialsNone
		}
	case CredentialsNone:
		if auth == AuthPassword {
			return Profile{}, errf(`credentials = "none" needs auth = "key" (an unencrypted key); a password is asked, read from the keychain or from Vault`)
		}
	case kconfig.CredentialsAsk, kconfig.CredentialsKeychain, kconfig.CredentialsVault:
	default:
		// Not echoed: a secret pasted here must not reach the terminal.
		return Profile{}, errf("unknown credentials mode (want none, ask, keychain or vault)")
	}
	if cred == kconfig.CredentialsVault {
		if r.VaultPath == "" {
			return Profile{}, errf(`credentials = "vault" needs vault_path, such as "secret/data/lockssh/web"`)
		}
		if strings.HasPrefix(r.VaultPath, "-") || strings.HasPrefix(r.VaultPath, "/") || strings.IndexFunc(r.VaultPath, unicode.IsSpace) >= 0 {
			return Profile{}, errf("vault_path: want a path without spaces, not starting with '-' or '/'")
		}
	} else if r.VaultPath != "" {
		return Profile{}, errf(`vault_path is only used with credentials = "vault"`)
	}
	port := r.Port
	if port == 0 {
		port = kconfig.DefaultSSHPort
	}
	p := Profile{
		Name: name,
		Base: kconfig.Base{
			User: r.User, Credentials: cred, VaultPath: r.VaultPath, Production: r.Production,
			SSH: &kconfig.SSHProfile{Host: host, Port: port, User: r.User, Auth: auth, Key: r.Key, Credentials: cred},
		},
		KnownHosts: r.KnownHosts,
		Exec:       r.Exec,
		Allow:      command.Canonical(r.Allow),
		Detectors:  r.Detectors,
		Limits:     Limits{MaxOutputBytes: r.Limits.MaxOutputBytes},
	}
	if _, err := command.ParseRules(p.Allow); err != nil {
		return Profile{}, errf("%v", err)
	}
	if _, err := pii.Detectors(p.Detectors); err != nil {
		return Profile{}, errf("detectors: %v", err)
	}
	for _, f := range []struct {
		key, val string
		dst      *time.Duration
	}{
		{"request_timeout", r.Limits.RequestTimeout, &p.Limits.RequestTimeout},
		{"idle_timeout", r.Limits.IdleTimeout, &p.IdleTimeout},
		{"max_session", r.Limits.MaxSession, &p.MaxSession},
	} {
		if f.val == "" {
			continue
		}
		d, err := time.ParseDuration(f.val)
		if err != nil || d <= 0 {
			return Profile{}, errf("limits.%s: want a positive duration such as \"30s\" or \"20m\"", f.key)
		}
		*f.dst = d
	}
	if r.CredentialsTTL != "" {
		d, err := time.ParseDuration(r.CredentialsTTL)
		if err != nil || d < time.Minute {
			return Profile{}, errf("credentials_ttl: want a duration of at least 1m, such as \"20m\" or \"1h\"")
		}
		p.CredentialsTTL = d
	}
	if p.Limits.MaxOutputBytes < 0 {
		return Profile{}, errf("limits.max_output_bytes must not be negative")
	}
	if p.Limits.MaxOutputBytes > MaxOutputCeiling {
		return Profile{}, errf("limits.max_output_bytes (%d) is above its ceiling %d", p.Limits.MaxOutputBytes, MaxOutputCeiling)
	}
	if p.Limits.RequestTimeout > MaxRequestTimeout {
		return Profile{}, errf("limits.request_timeout (%s) is above its ceiling %s", p.Limits.RequestTimeout, MaxRequestTimeout)
	}
	auto, err := parseAuto(r.Auto.v)
	if err != nil {
		return Profile{}, errf("%v", err)
	}
	if r.Production && auto.Rule(ActExec) == AutoAuto {
		// A write on production is always a human's decision: lox run's
		// auto mode must never approve a prod-write ticket.
		return Profile{}, errf(`auto.exec = "auto" (or auto = %q) is refused on a production profile: a command outside the allow list is a write, decided by a human; use "ask" or "deny"`, FullAuto)
	}
	p.Auto = auto.canonical()

	applyDefaults(&p, detectorsSet)
	switch {
	case p.MaxSession < MinIdleTimeout || p.MaxSession > MaxMaxSession:
		return Profile{}, errf("limits.max_session (%s) must be between %s and %s", p.MaxSession, MinIdleTimeout, MaxMaxSession)
	case p.IdleTimeout < MinIdleTimeout:
		return Profile{}, errf("limits.idle_timeout (%s) is below %s", p.IdleTimeout, MinIdleTimeout)
	case p.IdleTimeout > p.MaxSession:
		return Profile{}, errf("limits.idle_timeout (%s) is above limits.max_session (%s)", p.IdleTimeout, p.MaxSession)
	}
	return p, nil
}

// Host is the profile's SSH host.
func (p Profile) Host() string {
	if p.SSH == nil {
		return ""
	}
	return p.SSH.Host
}

// Port is the profile's SSH port.
func (p Profile) Port() int {
	if p.SSH == nil {
		return kconfig.DefaultSSHPort
	}
	return p.SSH.Port
}

// Auth is the profile's SSH authentication method.
func (p Profile) Auth() string {
	if p.SSH == nil {
		return ""
	}
	return p.SSH.Auth
}

// Key is the profile's private key file ("" with password auth).
func (p Profile) Key() string {
	if p.SSH == nil {
		return ""
	}
	return p.SSH.Key
}
