// Package product declares lockssh's names for lockkit.
package product

import "github.com/DavidGodefroid/lockkit/kit"

// P is lockssh as a lockkit product: its binary, directories, console
// account, clients group, keychain service and environment prefix.
var P = kit.Product{
	Name:            "lockssh",
	Tagline:         "Your AI runs the command. You hold the key.",
	Account:         "lockssh",
	ClientsGroup:    "lockssh-clients",
	KeychainService: "lockssh",
	EnvPrefix:       "LOCKSSH_",
}
