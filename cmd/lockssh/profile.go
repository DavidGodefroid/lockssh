package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/DavidGodefroid/lockkit/agentwire"
	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/verbs"

	"github.com/DavidGodefroid/lockssh/internal/config"
	"github.com/DavidGodefroid/lockssh/internal/product"
)

// defaultProfile is the profile name when --profile is absent.
const defaultProfile = "dev"

const profileAddUsage = `lockssh profile add [--non-interactive] [--json] [--project DIR] [--profile NAME] [--production]
                          [--credentials none|ask|vault [--vault-path P]] --host HOST [--port N] --user USER
                          [--auth key|password] [--key FILE] [--known-hosts FILE] [--allow "RULE"]... [--exec]`

// newProfile is a profile as `profile add` writes it.
type newProfile struct {
	Host        string   `toml:"host"`
	Port        int      `toml:"port,omitempty"`
	User        string   `toml:"user"`
	Auth        string   `toml:"auth"`
	Key         string   `toml:"key,omitempty"`
	KnownHosts  string   `toml:"known_hosts,omitempty"`
	Credentials string   `toml:"credentials,omitempty"`
	VaultPath   string   `toml:"vault_path,omitempty"`
	Production  bool     `toml:"production,omitempty"`
	Exec        bool     `toml:"exec,omitempty"`
	Allow       []string `toml:"allow"`
}

// defaultKey is the key file offered by the interactive form.
const defaultKey = "~/.ssh/id_ed25519"

// stringList is a repeatable flag; String renders every value, as
// verbs.RefuseSecrets needs.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// errExists: the profile is already in the project's config. The name is
// not quoted (it may be a secret typed at the wrong prompt).
var errExists = errors.New("a profile of that name is already in the project's config; nothing written")

// failedError is a failure that is not the caller's: a file not written.
type failedError struct{ error }

// configError is a project config that does not parse.
type configError struct{ error }

// verbCode is the verbs.Error code and the exit status of err.
func verbCode(err error) (string, int) {
	var fe failedError
	var ce configError
	switch {
	case errors.Is(err, errExists):
		return verbs.CodeExists, exitUsage
	case errors.Is(err, verbs.ErrSecret):
		return verbs.CodeSecret, exitUsage
	case errors.As(err, &fe):
		return verbs.CodeFailed, exitFail
	case errors.As(err, &ce):
		return verbs.CodeFailed, exitUsage
	}
	return verbs.CodeUsage, exitUsage
}

// verbFail reports the failure of a launcher verb on stderr (with the
// usage for a usage error) and, with --json, as one verbs.Error on stdout.
func verbFail(e env, cmd, usage string, asJSON bool, err error) int {
	code, exit := verbCode(err)
	fmt.Fprintf(e.stderr, "lockssh %s: %v\n", cmd, err)
	if code == verbs.CodeUsage && usage != "" {
		fmt.Fprintf(e.stderr, "usage: %s\n", usage)
	}
	if asJSON {
		_ = verbs.WriteJSON(e.stdout, verbs.Error{Lock: product.P.Name, Code: code, Error: err.Error()})
	}
	return exit
}

// runProfile is `lockssh profile <subcommand>`: add or rules.
func runProfile(e env, args []string) int {
	if len(args) > 0 && args[0] == "rules" {
		return runProfileRules(e, args[1:])
	}
	if len(args) == 0 || args[0] != "add" {
		// The subcommand is not quoted: it may be a token pasted in the
		// wrong place.
		return verbFail(e, "profile", profileAddUsage+"\n       "+profileRulesUsage, verbs.WantsJSON(args), errors.New("unknown subcommand; want add or rules"))
	}
	return runProfileAdd(e, args[1:])
}

// runProfileAdd is `lockssh profile add` (lockkit GUIDE §14): it adds one
// SSH host profile to the project's .lockssh/config.toml, from its flags
// and, without --non-interactive, from the answers to what they did not
// give. No form takes, asks for or writes a secret.
func runProfileAdd(e env, args []string) int {
	const cmd = "profile add"
	asJSON := verbs.WantsJSON(args)
	fail := func(err error) int { return verbFail(e, cmd, profileAddUsage, asJSON, err) }
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	nonInteractive := fs.Bool(verbs.FlagNonInteractive, false, "never ask")
	fs.Bool(verbs.FlagJSON, false, "one line of JSON on stdout")
	project := fs.String(verbs.FlagProject, "", "project directory")
	name := fs.String(verbs.FlagProfile, "", "profile name")
	production := fs.Bool(verbs.FlagProduction, false, "a production profile")
	credentials := fs.String(verbs.FlagCredentials, "", "none, ask or vault")
	vaultPath := fs.String(verbs.FlagVaultPath, "", "Vault path of the passphrase or password")
	host := fs.String("host", "", "SSH host")
	port := fs.Int("port", 0, "SSH port (default 22)")
	user := fs.String("user", "", "SSH login")
	auth := fs.String("auth", "", "key or password")
	key := fs.String("key", "", "private key file, in the console account")
	knownHosts := fs.String("known-hosts", "", "known_hosts file (default: the console account's)")
	var allow stringList
	fs.Var(&allow, "allow", "allow rule (repeatable), such as \"systemctl status *\"")
	exec := fs.Bool("exec", false, "let the agent ask for commands outside the allow list")
	if err := verbs.Parse(product.P, fs, args); err != nil {
		return fail(err)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if !*nonInteractive && !e.tty {
		return fail(errors.New("profile add asks in a terminal: run it in one, or give --non-interactive and the flags"))
	}

	root := agentwire.ProjectRoot(product.P, e.cwd)
	if *project != "" {
		abs, err := filepath.Abs(*project)
		if err != nil {
			return fail(errors.New("--project: invalid directory"))
		}
		root = abs
	}
	path := kconfig.ProjectConfigPath(product.P, root)
	existing := map[string]config.Profile{}
	if data, err := os.ReadFile(path); err == nil {
		if existing, err = config.ParseProfiles(data, path); err != nil {
			return fail(configError{err})
		}
	}
	checkName := func(n string, prod bool) error {
		if err := kconfig.CheckProfileName(n, prod); err != nil {
			return err
		}
		if _, dup := existing[n]; dup {
			return errExists
		}
		return nil
	}

	np := newProfile{Host: *host, Port: *port, User: *user, Auth: *auth, Key: *key, KnownHosts: *knownHosts,
		Production: *production, Exec: *exec, Allow: []string(allow)}
	if set[verbs.FlagCredentials] && *credentials == config.CredentialsNone {
		if set[verbs.FlagVaultPath] {
			return fail(errors.New("--vault-path goes with --credentials vault"))
		}
		np.Credentials = config.CredentialsNone
	} else if set[verbs.FlagCredentials] || set[verbs.FlagVaultPath] {
		cred, err := verbs.Credentials(*credentials, *vaultPath)
		if err != nil {
			return fail(err)
		}
		np.Credentials = cred
		if cred == kconfig.CredentialsVault {
			np.VaultPath = *vaultPath
		}
	}
	pname := *name
	if pname != "" {
		if err := checkName(pname, np.Production); err != nil {
			return fail(fmt.Errorf("--%s: %w", verbs.FlagProfile, err))
		}
	}
	out := e.stdout
	if asJSON {
		out = e.stderr
	}
	if *nonInteractive {
		if pname == "" {
			pname = defaultProfile
		}
		switch {
		case np.Host == "":
			return fail(errors.New("--host is required with --non-interactive"))
		case np.User == "":
			return fail(errors.New("--user is required with --non-interactive"))
		}
		if np.Auth == "" {
			np.Auth = config.AuthKey
		}
		if np.Auth == config.AuthKey && np.Key == "" {
			return fail(errors.New("--key is required with --auth key (the default)"))
		}
	} else {
		in := bufio.NewReader(e.stdin)
		ask := func(prompt, def string) (string, error) {
			fmt.Fprint(out, prompt)
			line, err := in.ReadString('\n')
			if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
				return "", errors.New("no answer")
			}
			if line = strings.TrimSpace(line); line == "" {
				return def, nil
			}
			return line, nil
		}
		var err error
		if pname, err = askProfile(ask, e.inContainer(), set, pname, &np, checkName); err != nil {
			return fail(err)
		}
	}
	if np.Credentials == "" {
		np.Credentials = config.CredentialsNone
		if np.Auth == config.AuthPassword {
			np.Credentials = kconfig.CredentialsAsk
		}
	}
	if np.Allow == nil {
		np.Allow = []string{}
	}
	if err := checkContainer(e.inContainer(), np); err != nil {
		return fail(err)
	}
	if err := checkName(pname, np.Production); err != nil {
		return fail(err)
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(map[string]map[string]newProfile{"profiles": {pname: np}}); err != nil {
		return fail(failedError{err})
	}
	if _, err := config.ParseProfiles(buf.Bytes(), "the new profile"); err != nil {
		return fail(err)
	}
	if err := appendProfile(path, buf.Bytes()); err != nil {
		return fail(failedError{err})
	}
	fmt.Fprintf(out, "Profile %s written to %s (%d allow rules, exec %t; no secret in the file).\n", pname, path, len(np.Allow), np.Exec)
	fmt.Fprintf(out, "Its console is started with its hub by lox run (lox add lockssh NAME, profile %s, project %s), from lockhub's release after v0.10.1, the first with the lockssh type (lockhub#133)\n", pname, root)
	fmt.Fprintln(out, "Wire your agents with: lockssh init <agent>")
	if asJSON {
		_ = verbs.WriteJSON(e.stdout, verbs.Profile{Lock: product.P.Name, Profile: pname, Config: path,
			Production: np.Production, Credentials: np.Credentials})
	}
	return exitOK
}

// appendProfile appends the encoded profile to the config file at path.
func appendProfile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.Write(append([]byte("\n"), data...))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// inContainer reports a process in a Docker or Podman container.
func (e env) inContainer() bool {
	if e.container != nil {
		return e.container()
	}
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// checkContainer refuses, in a container, the keychain, which a container
// does not have.
func checkContainer(container bool, np newProfile) error {
	if container && np.Credentials == kconfig.CredentialsKeychain {
		return errors.New("a container has no keychain: use none, ask or vault")
	}
	return nil
}

// askProfile asks for what the flags (set) did not give, into np, and
// returns the profile name (name when --profile gave it). checkName checks
// the name as soon as it is typed. It never asks for the secret.
func askProfile(ask func(prompt, def string) (string, error), container bool, set map[string]bool, name string, np *newProfile, checkName func(string, bool) error) (string, error) {
	var err error
	q := func(flagName string, dst *string, prompt, def string) {
		if err == nil && !set[flagName] {
			*dst, err = ask(prompt, def)
		}
	}
	var port, prod, rules, exec string
	if name == "" {
		q(verbs.FlagProfile, &name, "Profile name ["+defaultProfile+"]: ", defaultProfile)
		if err == nil {
			err = checkName(name, np.Production)
		}
	}
	q("host", &np.Host, "SSH host (a name or an address, no user or port): ", "")
	q("port", &port, "SSH port [22]: ", "22")
	q("user", &np.User, "SSH login: ", "")
	q("auth", &np.Auth, "Authentication: key or password [key]: ", config.AuthKey)
	if err == nil && np.Auth == config.AuthKey {
		q("key", &np.Key, "Private key file, in the console account ["+defaultKey+"]: ", defaultKey)
	}
	creds, def := "none (an unencrypted key), ask, keychain or vault", config.CredentialsNone
	if np.Auth == config.AuthPassword {
		creds, def = "ask, keychain or vault", kconfig.CredentialsAsk
	}
	if container {
		creds = strings.Replace(creds, ", keychain", "", 1)
	}
	if np.Credentials == "" {
		q(verbs.FlagCredentials, &np.Credentials, "Credentials (the key's passphrase or the password): "+creds+" ["+def+"]: ", def)
		if np.Credentials == kconfig.CredentialsVault {
			q(verbs.FlagVaultPath, &np.VaultPath, "Vault path, such as secret/data/lockssh/web: ", "")
		}
	}
	q("allow", &rules, "Allow rules, separated by commas (commands that run at once), such as uptime, df -h, systemctl status *: ", "")
	q("exec", &exec, "Let the agent ask for other commands, each decided by you? [y/N] ", "n")
	q(verbs.FlagProduction, &prod, "Production? [y/N] ", "n")
	if err != nil {
		return "", err
	}
	if np.Host == "" || np.User == "" {
		return "", errors.New("the host and the login are required")
	}
	if !set["port"] {
		n, perr := strconv.Atoi(strings.TrimSpace(port))
		if perr != nil || n < 1 || n > 65535 {
			return "", errors.New("the port must be a number from 1 to 65535")
		}
		if n != 22 {
			np.Port = n
		}
	}
	if !set["allow"] {
		for _, r := range strings.Split(rules, ",") {
			if r = strings.TrimSpace(r); r != "" {
				np.Allow = append(np.Allow, r)
			}
		}
	}
	if !set["exec"] {
		np.Exec = yes(exec)
	}
	if !set[verbs.FlagProduction] {
		np.Production = yes(prod)
	}
	return name, nil
}

func yes(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes"
}
