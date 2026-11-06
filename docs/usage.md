# Using lockssh

lockssh lets an AI agent run commands on a server over SSH without ever
holding the key. A console, held by a human in its own account and
container, holds the SSH key or password and the only SSH connection. The
agent asks it, over MCP or the `lockssh` CLI, to run an argv; the console
runs it when a rule of the profile allows it, asks the human otherwise (on
lockhub, through `lox run`), and returns the exit status and the output,
masked.

- [Profiles](#profiles)
- [Allow rules](#allow-rules)
- [What runs, what waits, what is refused](#what-runs-what-waits-what-is-refused)
- [Output](#output)
- [Auto rules](#auto-rules)
- [The console](#the-console)
- [Client commands and MCP tools](#client-commands-and-mcp-tools)
- [Launcher verbs](#launcher-verbs)
- [Refusal codes](#refusal-codes)

## Profiles

A profile is one SSH host, in `.lockssh/config.toml` (the project) or
`~/.config/lockssh/config.toml` (your account). It never holds a secret.

```toml
[profiles.web]
host        = "web1.example.com"   # a name or an address, no user, port or scheme ("[::1]" for IPv6)
port        = 22                   # default 22
user        = "deploy"             # the SSH login (required)
auth        = "key"                # key (default) | password
key         = "~/.ssh/id_ed25519"  # with auth = "key"; in the console account ("~/" is its home)
credentials = "none"               # key: none (unencrypted, the default) | ask | keychain | vault
                                   # password: ask (the default) | keychain | vault
vault_path  = ""                   # with credentials = "vault"
known_hosts = ""                   # "" = the console account's ~/.ssh/known_hosts
production  = false
exec        = false                # true: a command outside allow may be asked
allow       = ["uptime", "df -h", "systemctl status *", "journalctl -u * -n * --no-pager"]
detectors   = ["card", "email", "iban", "ip", "phone", "secret"]   # the default

[profiles.web.limits]
request_timeout  = "30s"           # a command running longer is killed (ceiling 10m)
max_output_bytes = 65536           # per stream, before masking (ceiling 512 KiB)
idle_timeout     = "20m"
max_session      = "4h"

[profiles.web.auto]                # lox run's auto rules (below)
connect = "ask"
run     = "auto"
exec    = "ask"
unmask  = "ask"
```

The secret is the key's passphrase or the SSH password. `ask` is asked by
the console at its start (masked), `keychain` read from the OS keychain
(not in a container), `vault` read from Vault at `vault_path` with the
Vault token the console asks at its start.

**Host key.** With no `known_hosts`, the console checks the host key
against its own account's `~/.ssh/known_hosts`; a key it has never seen is
shown on the console and trusted only on the human's answer (`yes`, or on
production the last 8 characters of its fingerprint), then recorded. With a
`known_hosts` file, a key the file does not hold is refused. A changed key
is always refused.

**Policy.** Every security-relevant field is part of the profile's policy.
The console shows it at its first start and asks the human to approve it;
afterwards a change that tightens applies at once, and a change that
loosens (a new allow rule, exec turned on, another host, user, key or
known_hosts, a removed detector, a larger limit, a looser auto rule) waits
for the human in the console (`:review`). An agent that edits the file
loosens nothing.

## Allow rules

An allow rule is an argv pattern, its tokens separated by spaces:

| Token | Matches |
|---|---|
| `status` | exactly that argument |
| `*`, `nginx*`, `*.service`, `[ab]?` | one argument, as a glob ([path.Match](https://pkg.go.dev/path#Match)): `*` and `?` never match `/` |
| `**` (last token only) | zero or more remaining arguments |

The first token, the program, is always literal. Examples:

| Rule | Allows | Not |
|---|---|---|
| `uptime` | `uptime` | `uptime -p` |
| `systemctl status *` | `systemctl status nginx` | `systemctl restart nginx`, `systemctl status a b` |
| `cat /var/log/*` | `cat /var/log/syslog` | `cat /var/log/../../etc/shadow`, `cat /var/log/nginx/error.log` |
| `journalctl -u * -n * --no-pager` | `journalctl -u nginx -n 50 --no-pager` | `journalctl -u nginx` |
| `echo **` | `echo`, `echo a b c` | |

A rule allows a program with the arguments it names; it cannot know what
the program does with them. Some programs run other programs or write
files from their own arguments (`find -exec`, `awk`, `vim`, `less`,
`tar --to-command`, `sudo`, `env`, `sh -c`): never allow them with a glob or
`**`.

## What runs, what waits, what is refused

The agent sends an argv: the program and its arguments, one string each.
There is no shell: the console quotes every argument for the server's login
shell, so `;`, `|`, `>`, `$VAR`, `$(...)`, `*.log` and `~` are passed as
literal arguments. An argv holds 1 to 64 arguments, each at most 4 KiB, at
most 16 KiB in all, with no control or invisible character but tab.

| Request | What happens |
|---|---|
| an allow rule matches | runs at once (rule `run = "auto"`, the default); with `run = "ask"`, a ticket |
| no rule matches, `exec = false` | refused, `E_NOT_ALLOWED`; nothing runs |
| no rule matches, `exec = true` | a ticket (risk `write`, `prod-write` on production), decided by the human |
| `unmask` (output in clear) | only once the human allowed it in the console (`:unmask` or `--allow-unmask`); then a ticket (risk `read-pii`), never decided by an auto rule |

A ticket goes to lockhub: the agent gets `pending` with the ticket id, ends
its turn, and runs the same argv again with `ticket` once told it is
decided. The decided ticket runs the stored request once, for the agent
that asked it, under the policy it was asked under (`E_STALE` otherwise).

The first request of each SSH session, and the first after the approved
policy changed, also waits for a connect ticket (`connect = "ask"`: the
first of each console run is a human's).

## Output

The result holds `exit_status` (or `signal`, or `timed_out`), `stdout`,
`stderr`, `stdout_truncated` / `stderr_truncated` (cut at
`max_output_bytes` before masking), `duration_ms`, and `masked`, the count
of masked values by kind.

What the profile's detectors find becomes a keyed pseudonym:
`⟦email:7F3KQ2M9ZD4X⟧`, the same for the same value during one console
run, another in the next run. Secrets (`password=...`, tokens, PEM keys,
URL userinfo...) become `⟦secret⟧`. Invalid UTF-8 becomes U+FFFD. What
the detectors do not recognise (names, addresses in free text, file
contents of unknown shapes) is **not** masked: choose the allow list
accordingly. See [docs/security-model.md](security-model.md).

## Auto rules

`lox run`'s auto mode decides tickets by rule. Each action takes `auto`,
`ask` or `deny`; `auto = "full-auto"` sets them all to `auto`.

| Action | Default | Meaning |
|---|---|---|
| `connect` | ask | use the SSH session (the first connection of each console run is always a human's under `ask`) |
| `run` | auto | an allow-listed command; `auto` runs it without a ticket |
| `exec` | ask | a command outside the allow list (exec on) |
| `unmask` | ask | clear output; never approved by an auto rule, only `deny` changes it |

`deny` is enforced by the console whatever the decider does; `ask` signs
the ticket `never_auto`. `lockssh profile rules --json` prints the rules
`lox run` applies (the approved policy's).

## The console

`lox up` starts the console: `lockssh console --hub URL --hub-key-file FILE
--instance NAME [--profile P] [--project DIR] [--allow-unmask]
[--show-results] [--allowed-uids UID,...]`. It refuses to start without its
hub. At its start it shows the policy for approval, asks the secret, logs
in, trusts or checks the host key, runs `id -u` (a root login is refused on
production and asks a typed `continue` elsewhere), then serves the socket
until logout, `:quit`, the idle timeout or the maximum session. Its keys:
`:review`, `:status`, `:results` / Ctrl-O (clear output on the console
only), `:unmask`, `:quit`. Every request, decision and run is in its
append-only, hash-chained audit log, with the command masked and never its
output.

## Client commands and MCP tools

| CLI | MCP tool | |
|---|---|---|
| `lockssh status` | `lockssh_status` | the console of each profile, its allow rules, exec, the SSH account |
| `lockssh run [--intent T] [--dry-run] [--ticket T] [--unmask] [--] PROGRAM [ARG]...` | `lockssh_run` (`argv`, `intent`, `dry_run`, `ticket`, `unmask`) | run a command; flags come before the program |
| `lockssh request "CHANGE"` | `lockssh_request_change` | queue a policy change for the human |
| `lockssh logout` | | end the console session |
| `lockssh mcp` | | the MCP server on stdin/stdout |

All take `--profile P` (when several are configured) and `--instance NAME`
(when lea mounts several lockssh locks). Exit codes: 0 ok, 1 refused,
denied or failed, 2 no console, 3 usage or configuration error.

## Launcher verbs

What `lox add` calls (the lockkit verbs contract):

```
lockssh profile add --non-interactive --json --profile NAME [--production] [--credentials none|ask|vault --vault-path P]
                    --host HOST [--port N] --user USER [--auth key|password] [--key FILE] [--known-hosts FILE]
                    [--allow "RULE"]... [--exec]
lockssh init claude
lockssh doctor --fix --yes --json
```

`profile add` never takes, asks for or writes a secret; an existing
profile is never rewritten (`exists`). `init <agent>` wires Claude Code,
Codex, Cursor or Gemini CLI in the project. `doctor` checks the config,
the separated setup, the consoles, the project's `.lockssh` and the agent
wiring.

## Refusal codes

| Code | Meaning | What to do |
|---|---|---|
| `E_BAD_ARGV` | empty program, control character, too many or too long arguments | rewrite the argv |
| `E_NOT_ALLOWED` | no allow rule matches and exec is off | use an allowed command, or ask the user for a rule |
| `E_AUTO_DENIED` | the profile's auto rules deny this action | only the user changes them |
| `E_UNMASK_OFF` | clear output is off in this console | work with the masked output, or ask the user |
| `E_STALE` | the profile changed after the approval | ask again |
| `E_POLICY` | no policy in force, or it does not parse | ask the user |
