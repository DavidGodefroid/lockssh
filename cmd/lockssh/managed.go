package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/verbs"

	"github.com/DavidGodefroid/lockssh/internal/config"
	"github.com/DavidGodefroid/lockssh/internal/product"
)

const (
	managedShowUsage  = "lockssh managed show"
	managedCheckUsage = "lockssh managed check [--profile P] [--project DIR]"
	// noManaged is what managed show, managed check and doctor print when
	// the machine has no managed file.
	noManaged = "no managed configuration"
)

// runManaged is `lockssh managed show|check`: the company's managed
// configuration (lockfamily's docs/managed.md) as lockssh applies it.
func runManaged(e env, args []string) int {
	switch {
	case len(args) > 0 && args[0] == "show":
		return runManagedShow(e, args[1:])
	case len(args) > 0 && args[0] == "check":
		return runManagedCheck(e, args[1:])
	}
	// The subcommand is not quoted: it may be a token pasted in the wrong
	// place.
	return usageFail(e, "managed", managedShowUsage+"\n       "+managedCheckUsage, "unknown subcommand; want show or check")
}

// runManagedShow prints the managed file: where it is, whose it is, its
// fingerprint and signature, the [lockssh] bounds and defaults in force and
// the managed profiles. No file: noManaged, exit 0. A refused file (badly
// owned, invalid, badly signed): lockkit's error, exit 3.
func runManagedShow(e env, args []string) int {
	if len(args) > 0 {
		return usageFail(e, "managed show", managedShowUsage, "wrong arguments")
	}
	m, err := config.LoadManaged(context.Background())
	if err != nil {
		fmt.Fprintln(e.stderr, "lockssh managed show:", sanitize.Terminal(err.Error(), false))
		return exitUsage
	}
	if m == nil {
		fmt.Fprintln(e.stdout, noManaged)
		return exitOK
	}
	f := m.File
	signed := "no"
	if f.Signed {
		signed = "yes"
	}
	lines := []string{
		f.Describe(),
		"path: " + f.Path,
		"organisation: " + f.Organisation,
		"fingerprint: sha256:" + f.Fingerprint,
		"signed: " + signed,
	}
	if d := m.Describe(); len(d) > 0 {
		lines = append(lines, d...)
	} else {
		lines = append(lines, "lockssh: no bounds and no defaults")
	}
	lines = append(lines, "managed profiles: "+orNone(m.ProfileNames()))
	for _, l := range lines {
		fmt.Fprintln(e.stdout, sanitize.Terminal(l, false))
	}
	return exitOK
}

// runManagedCheck loads the config files and the managed file as the
// console does and checks every profile (or the one named) against the
// managed bounds. It opens no connection and reads no credential. Its
// output and exit code are a contract (lox runs it before it starts the
// lock): one "blocked by company policy: …" line per violation and exit
// 3, else one "within the company policy: …" line and exit 0; noManaged
// and exit 0 without a managed file; a file or config refused: the error
// on stderr and exit 3.
func runManagedCheck(e env, args []string) int {
	fs := flag.NewFlagSet("managed check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	only := fs.String("profile", "", "check one profile")
	project := fs.String("project", "", "project directory (default: the current directory)")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) > 0 {
		return usageFail(e, "managed check", managedCheckUsage, "wrong arguments")
	}
	fail := func(err error) int {
		fmt.Fprintln(e.stderr, "lockssh managed check:", sanitize.Terminal(err.Error(), false))
		return exitUsage
	}
	m, err := config.LoadManaged(context.Background())
	if err != nil {
		return fail(err)
	}
	if m == nil {
		fmt.Fprintln(e.stdout, noManaged)
		return exitOK
	}
	cwd := e.cwd
	if *project != "" {
		if cwd, err = filepath.Abs(*project); err != nil {
			return fail(err)
		}
	}
	userCfg := e.userConfig
	if userCfg == "" {
		userCfg, _ = kconfig.UserConfigPath(product.P)
	}
	ps, root, err := config.LoadWith(cwd, userCfg, m)
	if err != nil {
		return fail(err)
	}
	names := profileNames(ps)
	if *only != "" {
		if err := checkProfileArg(ps, *only); err != nil {
			return fail(err)
		}
		names = []string{*only}
	}
	if len(names) == 0 {
		return fail(errors.New("no profile is configured"))
	}
	pii, err := config.LoadPII(config.PIIPath(root, userCfg))
	if err != nil {
		return fail(err)
	}
	if pii, err = m.WithPII(pii); err != nil {
		return fail(err)
	}
	blocked := 0
	for _, n := range names {
		for _, v := range m.Violations(config.NewPolicy(ps[n]).WithPII(pii)) {
			fmt.Fprintln(e.stdout, sanitize.Terminal(v.String(), false))
			blocked++
		}
	}
	if blocked > 0 {
		return exitUsage
	}
	fmt.Fprintln(e.stdout, "within the company policy: "+strings.Join(names, ", "))
	return exitOK
}

// managedLine is doctor's managed check: the file's Describe line,
// noManaged, or the reason it is refused.
func managedLine() (status, detail string) {
	m, err := config.LoadManaged(context.Background())
	switch {
	case err != nil:
		return verbs.StatusFail, sanitize.Terminal(err.Error(), false)
	case m == nil:
		return verbs.StatusOK, noManaged
	}
	return verbs.StatusOK, sanitize.Terminal(m.File.Describe(), false)
}
