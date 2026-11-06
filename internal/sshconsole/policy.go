package sshconsole

import (
	"net"
	"strconv"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/console"

	"github.com/DavidGodefroid/lockssh/internal/config"
)

// Policy is the console's view of a profile's policy: config.Policy plus
// the profile lockkit's console needs. Its JSON is config.Policy's, so the
// approved store holds the same document.
type Policy struct {
	config.Policy
}

var _ console.Policy = Policy{}

// Diff implements config.Policy on the wrapped policies.
func (p Policy) Diff(approved kconfig.Policy) []kconfig.Change {
	if a, ok := approved.(Policy); ok {
		approved = a.Policy
	}
	return p.Policy.Diff(approved)
}

// Profile implements console.Policy.
func (p Policy) Profile() console.Profile {
	pr := p.Policy.Profile
	return console.Profile{
		Name: pr.Name, Production: pr.Production, Where: where(pr),
		Host: pr.Host(), Port: pr.Port(), DefaultPort: kconfig.DefaultSSHPort,
		User: pr.User, Credentials: pr.Credentials, VaultPath: pr.VaultPath, CredentialsTTL: pr.CredentialsTTL,
		IdleTimeout: pr.IdleTimeout, MaxSession: pr.MaxSession,
	}
}

// where is user@host:port.
func where(pr config.Profile) string { return pr.User + "@" + hostPort(pr) }

// hostPort is host:port of the profile.
func hostPort(pr config.Profile) string {
	return net.JoinHostPort(pr.Host(), strconv.Itoa(pr.Port()))
}
