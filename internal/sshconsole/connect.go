package sshconsole

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/secrets"
	"github.com/DavidGodefroid/lockkit/tunnel"

	"github.com/DavidGodefroid/lockssh/internal/config"
	"github.com/DavidGodefroid/lockssh/internal/product"
)

// session is one SSH login to the profile's host.
type session struct {
	tun *tunnel.Tunnel
	// hostKey is the SHA256 fingerprint of the host key; user the login;
	// uid what `id -u` answered at login ("" when it failed).
	hostKey, user, uid string
	// detach forgets the session in its backend once it closes.
	detach func()
}

// Close implements console.Session.
func (s *session) Close() error {
	if s.detach != nil {
		s.detach()
	}
	if s.tun != nil {
		return s.tun.Close()
	}
	return nil
}

// checkTimeout bounds the console's own `id -u` at login.
const checkTimeout = 10 * time.Second

// Connect implements console.Backend: one SSH login to the host of the
// approved profile (never an unconfirmed edit), then `id -u` for Checks.
func (b *Backend) Connect(ctx context.Context, c console.Credentials) (console.Session, error) {
	pol, err := b.inForce()
	if err != nil {
		return nil, err
	}
	pr := pol.Policy.Profile
	if pr.Auto.Rule(config.ActConnect) == config.AutoDeny {
		return nil, fmt.Errorf("connect: %s", autoRefusal(pr, config.ActConnect).Reason)
	}
	if pr.SSH == nil {
		return nil, errors.New("connect: the profile has no SSH target")
	}
	home := b.o.Home
	if home == "" {
		if home, err = os.UserHomeDir(); err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}
	}
	hk, algs, err := b.hostKeyCheck(ctx, pr, home)
	if err != nil {
		return nil, err
	}
	target := *pr.SSH
	target.User = pr.User
	if c.User != "" {
		target.User = c.User
	}
	secret := bytes.Clone(c.Secret)
	defer secrets.Wipe(secret)
	t, err := tunnel.Open(ctx, tunnel.Options{
		Profile: target, Home: home, HostKey: hk, HostKeyAlgorithms: algs, ClientName: product.P.Name,
		Secret: func(string) ([]byte, error) {
			if len(secret) == 0 {
				return nil, errors.New("no secret: set credentials to ask, keychain or vault for an encrypted key or a password")
			}
			return bytes.Clone(secret), nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	s := &session{tun: t, hostKey: t.HostKey(), user: target.User}
	cctx, cancel := context.WithTimeout(ctx, checkTimeout)
	res, err := execute(cctx, t, []string{"id", "-u"}, 64)
	cancel()
	if err == nil && res.exit != nil && *res.exit == 0 {
		if uid := strings.TrimSpace(string(res.stdout)); isDigits(uid) {
			s.uid = uid
		}
	}
	s.detach = func() {
		b.mu.Lock()
		if b.cur == s {
			b.cur = nil
		}
		b.mu.Unlock()
	}
	b.mu.Lock()
	b.cur = s
	b.mu.Unlock()
	return s, nil
}

func isDigits(s string) bool {
	if s == "" || len(s) > 10 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// hostKeyCheck verifies the host key against the profile's known_hosts
// file. With the default file (the console account's ~/.ssh/known_hosts),
// an unknown key is trusted only on the human's answer on the console
// ("yes", or on production the last 8 characters of its fingerprint) and
// recorded; with a file the profile names, an unknown key is refused. A
// changed key is always refused.
func (b *Backend) hostKeyCheck(ctx context.Context, pr config.Profile, home string) (ssh.HostKeyCallback, []string, error) {
	path, def := knownHostsPath(pr, home)
	var confirm tunnel.Confirm
	if def {
		confirm = b.confirmer(ctx, pr, path)
	} else if _, err := os.Stat(path); err != nil {
		// Named, not quoted: the path is the profile's.
		return nil, nil, errors.New("connect: known_hosts: the file the profile names cannot be read in the lockssh account")
	}
	hk, err := tunnel.KnownHosts(path, confirm)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: known_hosts: %w", err)
	}
	algs, err := tunnel.HostKeyAlgorithms(path, *pr.SSH)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: known_hosts: %w", err)
	}
	return hk, algs, nil
}

// knownHostsPath is the known_hosts file of the profile, and whether it is
// the console account's default one (where an unknown key may be trusted).
func knownHostsPath(pr config.Profile, home string) (string, bool) {
	if pr.KnownHosts == "" {
		return tunnel.KnownHostsPath(home), true
	}
	if rest, ok := strings.CutPrefix(pr.KnownHosts, "~/"); ok {
		return filepath.Join(home, rest), false
	}
	return pr.KnownHosts, false
}

// confirmer asks the human on the console to trust an unknown host key.
func (b *Backend) confirmer(ctx context.Context, pr config.Profile, path string) tunnel.Confirm {
	return func(host, keyType, fp string) bool {
		if b.o.IO == nil {
			return false
		}
		b.o.IO.Println(fmt.Sprintf("The authenticity of %s can't be established.", sanitize.Terminal(host, false)))
		b.o.IO.Println(fmt.Sprintf("%s key fingerprint is %s", sanitize.Terminal(keyType, false), sanitize.Terminal(fp, false)))
		prompt, expected := "Trust this key and add it to "+sanitize.Terminal(path, false)+"? [yes/N] ", "yes"
		if pr.Production {
			if len(fp) < 8 {
				return false
			}
			prompt, expected = "Type the last 8 characters of the fingerprint to trust it: ", fp[len(fp)-8:]
		}
		r := console.NewTypedApprover(b.o.IO).Approve(ctx, console.Decision{Prompt: prompt, Expected: expected, Production: true})
		return r.Outcome == console.Approved
	}
}
