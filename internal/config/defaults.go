package config

import (
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
)

// Ceilings of the per-command limits.
const (
	MaxOutputCeiling  = 512 << 10
	MaxRequestTimeout = 10 * time.Minute
)

// Bounds of the session limits: MinIdleTimeout <= idle_timeout <=
// max_session <= MaxMaxSession.
const (
	MinIdleTimeout = time.Minute
	MaxMaxSession  = 24 * time.Hour
)

// DefaultDetectors is the detector set of a profile that sets none: the
// usual personal values, public IP addresses (command output is full of
// them) and secrets (a config file or an environment dump). National id
// detectors are opt-in.
func DefaultDetectors() []string {
	return []string{"card", "email", "iban", "ip", "phone", "secret"}
}

// DefaultLimits returns the limits applied to unset limit fields.
func DefaultLimits() Limits {
	return Limits{RequestTimeout: 30 * time.Second, MaxOutputBytes: 64 << 10}
}

// Default session limits.
const (
	DefaultIdleTimeout = 20 * time.Minute
	DefaultMaxSession  = 4 * time.Hour
)

// applyDefaults fills the unset fields of p. detectorsSet reports a
// detectors key present in the file: an explicit empty list is kept.
func applyDefaults(p *Profile, detectorsSet bool) {
	if !detectorsSet {
		p.Detectors = DefaultDetectors()
	}
	d := DefaultLimits()
	if p.Limits.RequestTimeout == 0 {
		p.Limits.RequestTimeout = d.RequestTimeout
	}
	if p.Limits.MaxOutputBytes == 0 {
		p.Limits.MaxOutputBytes = d.MaxOutputBytes
	}
	if p.MaxSession == 0 {
		p.MaxSession = DefaultMaxSession
	}
	if p.IdleTimeout == 0 {
		p.IdleTimeout = min(DefaultIdleTimeout, p.MaxSession)
	}
	p.Detectors = kconfig.SortedSet(p.Detectors)
	p.Allow = kconfig.SortedSet(p.Allow)
}
