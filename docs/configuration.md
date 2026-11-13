# Configuration

Profiles, allow rules, PII rules and auto rules are in
[usage.md](usage.md). This page covers what sits above them: the company's
managed configuration.

## Managed configuration

A company can bound every lockssh profile of a machine with one file, the
Lock Family's `managed.toml` (schema and deployment: lockfamily's
[docs/managed.md](https://github.com/DavidGodefroid/lockfamily/blob/main/docs/managed.md)).
lockssh reads its `[lockssh]` section and its `[family]` rules. A user may
tighten what the file allows, never loosen it, and no human can approve
past it: the console refuses a profile beyond the bounds before any prompt,
at start and at every policy poll (2 s), and audits the refusal
`refused-managed`.

| Where | Path |
|---|---|
| Linux | `/etc/lockfamily/managed.toml` |
| macOS | `/Library/Application Support/lockfamily/managed.toml` |
| a lock in a `lox run` container | mounted by lox at `/etc/lockfamily/managed.toml` |

The file and its directory must be owned by root and writable by root only;
an optional cosign signature (`managed.toml.sigstore.json`) is checked
against the company identity in `signer.toml`. A badly owned, invalid or
badly signed file is a refusal to start, never a file ignored. No file is no
managed policy: lockssh behaves as without this page.

Precedence, from the strongest:

    hard-coded floor > managed bounds and profiles > project file
      > user file > managed defaults > built-in defaults

```toml
version = 1
organisation = "Example Corp"

[family]
vault = { address = "https://vault.example.com", required = true }

[lockssh.bounds]
production      = true
hosts           = ["*.corp.example"]
known_hosts     = "/etc/lockfamily/known_hosts"
auth            = ["key"]
credentials     = ["none", "vault"]
exec            = false
allow           = ["uptime", "df -h", "systemctl status *"]
auto            = { exec = "ask", unmask = "deny" }
credentials_ttl = "1h"
detectors       = ["email", "ip", "secret"]
limits          = { max_output_bytes = 65536, request_timeout = "30s", idle_timeout = "20m", max_session = "4h" }

[[lockssh.bounds.pii_mask]]
pattern = "cust-[0-9]{6}"

[lockssh.defaults]
known_hosts = "/etc/lockfamily/known_hosts"
limits      = { max_session = "2h" }

[lockssh.profiles.prod-web]
host        = "web1.corp.example"
user        = "ops"
key         = "/etc/lockfamily/lockssh/id_ed25519"
known_hosts = "/etc/lockfamily/known_hosts"
production  = true
allow       = ["uptime", "systemctl status *"]
```

### Bounds

`[lockssh.bounds]`: every key is optional; a key left out bounds nothing.

| Key | Type | Looser than the bound (refused) |
|---|---|---|
| `production` | `true` | a profile with `production = false` |
| `hosts` | host name patterns (`*`, `?`, `[...]`) | a `host` no pattern matches |
| `known_hosts` | path, enforced | any other `known_hosts`, the default one included |
| `auth` | allowed list (`"key"`, `"password"`) | an `auth` outside the list |
| `credentials` | allowed list (`none`, `ask`, `keychain`, `vault`) | a `credentials` mode outside the list |
| `exec` | `false` | `exec = true` |
| `allow` | allowed list of rules | an allow rule not in the list (the profile's must be a subset) |
| `auto.<action>` (`connect`, `run`, `exec`, `unmask`) | `deny`, `ask` or `auto`: a ceiling | a looser rule (`deny` < `ask` < `auto`); `auto = "full-auto"` in a bound is refused, set a table |
| `credentials_ttl` | duration, ceiling | a longer one, or none |
| `limits.max_output_bytes`, `limits.request_timeout` | ceiling | a larger one |
| `limits.idle_timeout`, `limits.max_session` | ceiling | a longer one |
| `detectors` | required set | nothing: added to every profile at load |
| `pii_mask` | `[[lockssh.bounds.pii_mask]] pattern = "<RE2>"`, as `[[mask]]` in `pii.toml` (200 rules, 512 bytes each) | nothing: masked in every output; a `pii.toml` allow rule whose value one matches is refused at load |

`[family] vault.required = true` acts as `credentials = ["vault"]`, cited
as `family.vault.required`.

A duration or a size beyond its bound is refused, never clamped. A
violation names the managed key:

    blocked by company policy: lockssh.bounds.exec = false (profile dev: exec = true)

### Defaults and profiles

- `[lockssh.defaults]` takes the profile keys (`limits.*` and `auto`
  included). A key a profile leaves unset takes the managed default before
  the built-in one; a value set in the user or project file wins. A default
  beyond the bounds is a load error.
- `[lockssh.profiles.<name>]` has exactly the profile keys. A managed
  profile is served as written (the managed defaults fill what it leaves
  unset) and wins as a whole: a project or user profile of the same name is
  refused, so rename yours. A managed profile beyond the bounds is a load
  error.

### Commands

- `lockssh managed show`: the file's path, organisation, fingerprint and
  signature, the `[lockssh]` bounds and defaults in force, and the managed
  profile names. No file: `no managed configuration` (exit 0); a refused
  file: lockkit's error (exit 3).
- `lockssh managed check [--profile P] [--project DIR]`: loads the config
  files and the managed file as the console does and checks every profile
  (or the one named). One `blocked by company policy: …` line per violation
  and exit 3; otherwise `within the company policy: <profiles>` and exit 0.
  It opens no connection and reads no credential. lox runs it before it
  starts the lock: its output and exit codes are a contract.
- `lockssh doctor` reports the file first (`managed`): its `Managed by
  <organisation> (sha256:…)` line, `no managed configuration`, or why it is
  refused.
- The console prints `Managed by <organisation> (sha256:…)` at start,
  records the fingerprint with every approval (`managed_sha256` in
  `approved/<key>.json`) and every audit record, and exits 3 when the
  managed file refuses the start.
