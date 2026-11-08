# lockssh security model

lockssh lets an AI agent run commands on a server over SSH. Its promise is
narrow: **the agent never holds the SSH key or password, never opens an SSH
connection, and runs only what the human allowed, with the output masked
before it leaves the console.**

## Parties

| Party | Holds | Can |
|---|---|---|
| The human | the console's terminal, lockhub (`lox run`) | approve the policy and its loosenings, decide tickets, trust a host key, unmask |
| The console (`lockssh` account, own container) | the key or password, the SSH connection, the approved policy, the audit log | run an argv on the host, mask its output |
| The agent (`lockssh-clients`, or an `--allowed-uids` uid) | a socket in a read-only volume | ask the console; propose a policy change |
| The server | the SSH account's rights | run what it is sent |

The boundary between the agent and the console is the operating system's:
separate accounts, the kernel's peer credentials on the socket, separate
containers. The [lockkit](https://github.com/DavidGodefroid/lockkit)
console framework holds it; lockssh adds the SSH side.

## What lockssh enforces

- **The key never reaches the agent.** It lives in the console account's
  home volume (mode 0600, refused otherwise), and a passphrase or password
  is asked by the console, read from the keychain or from Vault, wiped after
  use. Nothing the agent can read (the socket volume, the project, a
  result, an error, the audit log) carries it; errors are scrubbed.
- **No shell syntax from the agent.** The agent sends an argv; the console
  quotes every argument in POSIX single quotes. The server's login shell
  reads one simple command: argv[0] with argv[1:] as its arguments. No PTY,
  no stdin, no port, agent or X11 forwarding, no subsystem.
- **Only allowed commands run unasked.** A command runs at once only when an
  allow rule of the approved policy matches it (and its auto rule is
  `auto`). Anything else is refused, or, on a profile with `exec = true`,
  waits for a human's decision on a signed ticket bound to the argv, the
  agent, and the policy fingerprint; it runs once.
- **The policy is the human's.** The approved policy is the one in force; an
  agent that edits `.lockssh/config.toml` loosens nothing until the human
  approves the diff in the console.
- **Bounded runs.** Each command has a timeout (it is then sent SIGKILL and
  its session closed) and an output cap per stream.
- **Masked output.** Every byte of stdout and stderr goes through lockkit's
  detectors before it leaves the console; values become keyed pseudonyms,
  secrets `⟦secret⟧`. Clear output needs the human's switch in the console
  and a decided ticket, never an auto rule.
- **Host keys.** Unknown keys are trusted only by the human on the
  console; changed keys are refused.
- **Audit.** Every request, refusal, decision and run is in an append-only,
  hash-chained log, with the command masked, never the output.

## What lockssh does not do

- **It does not know what a program does.** An allow rule allows a program
  with arguments; a program that runs other programs or writes files from
  its arguments (`find -exec`, `awk`, `less`, `vim`, `tar`, `sudo`, `env`,
  `sh -c`, `xargs`, `git` with hooks) turns a narrow rule into a shell. Allow
  such programs only with literal arguments, never with `*` or `**`.
  [decisions.md](decisions.md#programs-that-run-code-from-their-arguments)
  lists them; a later release warns on such a rule and keeps globs off
  options and `..` segments.
- **It does not resolve paths on the host.** A rule's path is text: a
  symlink under an allowed directory reads wherever it points.
- **It does not confine the SSH account.** What a command can do is what
  the account can do. Use an account of its own with only the rights the
  allow list needs; a root login is refused on production and asks a typed
  `continue` elsewhere.
- **It does not mask what its detectors miss.** Person names, postal
  addresses, free-text personal data and secrets without a known shape or
  label reach the agent. Command output can be anything: prefer commands
  whose output you know (status, counts, metrics) over reading files.
- **It does not prevent exfiltration by an allowed command.** An allowed
  command that sends data elsewhere (`curl`, a mail command) does so.
- **It does not separate you from your own account.** Whoever runs
  `docker` commands as you can attach to the console or read its volume;
  run the agent in a container of its own without the Docker socket (lea)
  for that boundary.

## Why it is built this way

[decisions.md](decisions.md) gives each design decision and its rationale.

## Reporting

See [SECURITY.md](../SECURITY.md).
