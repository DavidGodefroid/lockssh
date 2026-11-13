# Changelog

All notable changes to lockssh. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) (no stability promise before 1.0).

## [Unreleased]

### Changed

- Releases are no longer GitHub pre-releases: a plain `vX.Y.Z` tag is
  published as a full release marked Latest, and only a tag with a
  pre-release suffix (`vX.Y.Z-rc.N`) stays a pre-release, as for the other
  Locks. v0.2.0 is now marked Latest (#28).

## [0.2.0] - 2026-11-13

### Fixed

- The launcher mounts the machine's managed directory (`/etc/lockfamily`,
  `/Library/Application Support/lockfamily` on macOS) read-only on
  `/etc/lockfamily` in its containers, as `lox run` does in its locks:
  `lockssh managed show`, `managed check`, `doctor` and the other commands
  run from the host see the company's managed configuration (#25).

### Changed

- lockkit v0.19.0 (from v0.14.1): package `managed` and its console
  integration; `lockssh init`'s allow note is lockkit's new default text
  (#17). From v0.19.0, lockkit's default PII detectors can mask more, or
  under another kind: a French NIR whose digits pass Luhn is masked as a
  NIR, no longer as a card number; `phone` also finds a national number
  after a phone word and 12-digit German mobiles; `be_niss` takes other
  separators after `NISS`/`rijksregister`; an e-mail local part may hold
  an apostrophe.

### Added

- Homebrew: `brew install davidgodefroid/tap/lockssh` (homebrew-tap#6), at
  v0.1.0. The release workflow's `tap` job warns on the run when
  `TAP_DISPATCH_TOKEN` is not set, instead of skipping the bump silently (#6).
- The company's managed configuration: lockssh enforces the `[lockssh]`
  section of the Lock Family's `managed.toml` (bounds the user may tighten
  but never loosen, managed defaults, managed profiles, always-on detectors
  and `pii_mask` rules, `[family] vault.required`), refused before any
  prompt at start and at every policy poll. New `lockssh managed show` and
  `lockssh managed check` (exit 3 on a violation, which lox runs before it
  starts the lock), a `managed` line in `lockssh doctor`, and
  `docs/configuration.md` (#17).
- The website in `site/`, at https://davidgodefroid.github.io/lockssh/
  (home, install, how it works, security, FAQ), checked by
  `scripts/check-site.py` and deployed by the `pages` workflow; a test
  keeps the commands, flags and MCP tools it names to lockssh's own.
- `docs/decisions.md`: what lockssh guards, what the agent may do over SSH,
  and the changes still to make (production `auto.exec`, globs that match
  no option and no `..` segment, the warning on programs that run code
  from their arguments, PII allow list, `version --json`).
- PII rules in `.lockssh/pii.toml`, through the reviewed policy: mask rules
  (RE2 regular expressions masked in every output, `⟦mask:…⟧`) and allow
  rules (`kind:value`, a detected value kept in clear; never a secret).
  `lockssh_pii_list` / `lockssh_pii_add` and `lockssh pii list|add`; adding
  a mask rule applies at once, a new allow rule or a removed mask rule
  waits for the policy review (#4).
- The policy review warns on an allow rule that gives a glob or `**` to a
  program that can run code, write or start another command from its
  arguments (base name, version suffix stripped: `python3.11` is `python`;
  the table of decisions.md plus `dd`, `tee`, `ash`, `yash`, `sudoedit`,
  `npx`, `yarn`, `java`, `jshell`), on a glob that chooses an option, and on
  a glob after a literal `--` (#4).
- `lockssh version --json` with the console protocol major (#5).
- Golden tests of every launcher verb's output that `lox add` reads
  (`version --json`, `profile add --json` and its refusals, `profile rules
  --json`, `doctor --json`, `doctor --fix --yes --json`, `init claude`), in
  `cmd/lockssh/testdata/` (#5).

### Changed

- The README quick start is `lox init`, `lox add lockssh`, then `lox run`
  (#11): the lockssh lock type is on lockhub's main branch (lockhub#133), in
  its release after v0.10.1. The docs, `profile add` and the launcher name
  that release instead of "not released yet".
- **Security (#4).** Globs and `**` in allow rules never match an argument
  starting with `-` or `+` (unless the glob starts with the same character,
  or follows a literal `--`) nor a `.`/`..` path segment they cover:
  `git log *` no longer allows `--output=…`, `cat /var/log/*/*/*` no
  longer reaches `/var/log/../../etc/shadow`, `less *` no longer `+!id`.
- **Security (#4).** The remote line runs argv[0] through `exec`, so a rule
  can never run a shell builtin (`eval`, `.`, `trap`…); an argv[0] starting
  with `-` or `+` is refused (`E_BAD_ARGV`), and an allow rule naming a
  builtin-only program is refused when the policy loads.
- **Security (#4).** On a production profile, `auto.exec = "auto"` and
  `auto = "full-auto"` are refused when the policy loads, and an exec
  ticket on production is never auto-approved.
- Overlapping masked values merge into one placeholder, so no byte of the
  longer one shows.

- Docs, agent assets, the launcher and the console's messages name `lox run`
  (`lox up` is deprecated since lockhub v0.10.0), and say that no lockhub
  release starts a lockssh console yet: that comes with the lockssh lock
  type (lockhub#133).
- lockkit v0.14.1 (its console texts name `lox run`).

## [0.1.0] - 2026-11-06

First pre-release. Builds on lockkit v0.14.0 (`tunnel.Tunnel.NewSession`);
the console is hub-attached only, started by `lox up` / `lox run`. lockssh
is not a `lox add` type yet (lockhub#133), nor in lea (lea#325), the
Homebrew tap (homebrew-tap#6) or the Lock Family installer
(lockfamily#27).

### Added

- Profiles: one SSH host each (`host`, `port`, `user`, `auth` key or
  password, `key`, `credentials` none / ask / keychain / vault,
  `known_hosts`, `production`), allow rules, `exec`, detectors, limits,
  auto rules; the policy review of lockkit (the AI tightens, the human
  loosens).
- The console: one SSH login through lockkit's tunnel (host key trusted on
  the console or pinned in a known_hosts file, key or password auth), the
  account check (`id -u`: a root login is a finding), hub mode only.
- `op.run` / `op.plan`: an argv, quoted for the server's shell (no shell
  syntax from the agent); allow-listed commands run at once, others are
  refused (`E_NOT_ALLOWED`) or, with `exec = true`, decided on a signed
  ticket (kind action, verb exec, risk write / prod-write); clear output on
  its own ticket (read-pii, never auto); per-profile auto rules (`connect`,
  `run`, `exec`, `unmask`); timeout (SIGKILL) and output caps.
- Masking of stdout and stderr: keyed pseudonyms for what the detectors find
  (`⟦email:…⟧`), `⟦secret⟧` for credentials.
- Clients: `lockssh status`, `run`, `request`, `logout`, `mcp` (tools
  `lockssh_status`, `lockssh_run`, `lockssh_request_change`); launcher verbs
  `init <agent>`, `profile add [--non-interactive --json]`, `profile rules
  --json`, `doctor [--fix [--yes]] [--json]`.
- The Docker image (console 10041, `lockssh-clients` 10040, agent 10042),
  its launcher and install script, the signed release (archives, checksums,
  multi-arch image), an end-to-end test against an OpenSSH container.
