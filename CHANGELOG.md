# Changelog

All notable changes to lockssh. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) (no stability promise before 1.0).

## [Unreleased]

### Added

- `docs/decisions.md`: what lockssh guards, what the agent may do over SSH,
  and the changes still to make (production `auto.exec`, globs that match
  no option and no `..` segment, the warning on programs that run code
  from their arguments, PII allow list, `version --json`).

### Changed

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
