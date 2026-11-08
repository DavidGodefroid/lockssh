package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/DavidGodefroid/lockkit/agentwire"
	"github.com/DavidGodefroid/lockkit/client"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/refusal"
	"github.com/DavidGodefroid/lockkit/sysconf"

	"github.com/DavidGodefroid/lockssh/internal/config"
	"github.com/DavidGodefroid/lockssh/internal/mcptools"
	"github.com/DavidGodefroid/lockssh/internal/product"
)

// fakeConn answers console calls from a script.
type fakeConn struct {
	calls []string
	err   error
}

func (f *fakeConn) Call(_ context.Context, method string, params, result any) error {
	raw, _ := json.Marshal(params)
	f.calls = append(f.calls, method+" "+string(raw))
	if f.err != nil {
		return f.err
	}
	return json.Unmarshal([]byte(`{"untrusted":"x","data":{"command":"uptime","action":"run","exit_status":0,"stdout":"up 3 days","stderr":""}}`), result)
}
func (f *fakeConn) Close() error { return nil }

func project(t *testing.T, profiles string) string {
	t.Helper()
	root := t.TempDir()
	if profiles != "" {
		if err := os.MkdirAll(filepath.Join(root, ".lockssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, ".lockssh", "config.toml"), []byte(profiles), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// testStateDir is the consoles' state base of a test project: beside it,
// never the account's.
func testStateDir(t *testing.T, root string) string {
	if root == "" {
		return t.TempDir()
	}
	return filepath.Join(filepath.Dir(root), filepath.Base(root)+".state")
}

const oneProfile = "[profiles.dev]\nhost = \"web1.example.com\"\nuser = \"deploy\"\nkey = \"~/.ssh/id_ed25519\"\nallow = [\"uptime\"]\n"

func runWith(t *testing.T, root string, conn *fakeConn, dialErr error, stdin string, args ...string) (int, string, string) {
	t.Helper()
	return runEnv(t, root, conn, dialErr, stdin, false, args...)
}

// runTTY runs a command whose stdin is a terminal, as a human types.
func runTTY(t *testing.T, root, stdin string, args ...string) (int, string, string) {
	t.Helper()
	return runEnv(t, root, nil, nil, stdin, true, args...)
}

func runEnv(t *testing.T, root string, conn *fakeConn, dialErr error, stdin string, tty bool, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	e := env{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb, cwd: root, tty: tty,
		userConfig: filepath.Join(t.TempDir(), "none.toml"),
		stateDir:   testStateDir(t, root),
		container:  func() bool { return false },
		svc:        func(string) (svcAccount, bool) { return svcAccount{}, false },
		sys: func() (*sysconf.Config, error) {
			return &sysconf.Config{ServiceUser: "lockssh", ClientGroup: "lockssh-clients", SocketDir: "/run/lockssh"}, nil
		},
		agentEnv: func() (agentwire.Env, error) {
			home := t.TempDir()
			return agentwire.Env{Home: home, Getenv: func(string) string { return "" },
				LookPath: func(string) (string, error) { return "", os.ErrNotExist },
				Run:      func(string, ...string) ([]byte, error) { return nil, os.ErrPermission }}, nil
		},
		dial: func(string) (mcptools.Conn, error) {
			if dialErr != nil {
				return nil, dialErr
			}
			return conn, nil
		}}
	code := run(e, args)
	return code, out.String(), errb.String()
}

func TestCLIExitCodes(t *testing.T) {
	root := project(t, oneProfile)
	noConsole := &client.NoConsoleError{Product: product.P, Profile: "dev", Project: root, Socket: "/x", Err: syscall.ECONNREFUSED}
	refused := &ipc.RPCError{Code: ipc.CodeRefused, Message: "no allow rule matches", Data: &refusal.Info{Code: "E_NOT_ALLOWED", Retry: refusal.RetryAskUser, Hint: "ask"}}
	cases := []struct {
		name    string
		root    string
		conn    *fakeConn
		dialErr error
		args    []string
		code    int
	}{
		{"version", root, nil, nil, []string{"version"}, exitOK},
		{"unknown", root, nil, nil, []string{"purge"}, exitUsage},
		{"no args", root, nil, nil, nil, exitUsage},
		{"ok", root, &fakeConn{}, nil, []string{"run", "uptime"}, exitOK},
		{"json", root, &fakeConn{}, nil, []string{"run", "--json", "uptime"}, exitOK},
		{"status", root, &fakeConn{}, nil, []string{"status"}, exitOK},
		{"refused", root, &fakeConn{err: refused}, nil, []string{"run", "rm", "-rf", "/"}, exitFail},
		{"denied", root, &fakeConn{err: &ipc.RPCError{Code: ipc.CodeDenied, Message: "denied"}}, nil, []string{"run", "reboot"}, exitFail},
		{"no console", root, nil, noConsole, []string{"status"}, exitNoConsole},
		{"closed", root, &fakeConn{err: client.ErrConsoleClosed}, nil, []string{"status"}, exitNoConsole},
		{"no profile", project(t, ""), &fakeConn{}, nil, []string{"status"}, exitUsage},
		{"unknown profile", root, &fakeConn{}, nil, []string{"status", "--profile", "prod"}, exitUsage},
		{"no argv", root, &fakeConn{}, nil, []string{"run"}, exitUsage},
		{"intent on status", root, &fakeConn{}, nil, []string{"status", "--intent", "x"}, exitUsage},
	}
	for _, c := range cases {
		code, _, stderr := runWith(t, c.root, c.conn, c.dialErr, "", c.args...)
		if code != c.code {
			t.Errorf("%s: exit %d, want %d (%s)", c.name, code, c.code, stderr)
		}
	}
	_, _, stderr := runWith(t, root, &fakeConn{err: refused}, nil, "", "run", "reboot")
	if !strings.Contains(stderr, "refused [E_NOT_ALLOWED]") || !strings.Contains(stderr, "retry: ask_user") {
		t.Errorf("refusal text: %s", stderr)
	}
	// No console: the hint asks the user to run `lox run` and carries no
	// value (no profile or project flag, no project path, no hand start).
	_, _, stderr = runWith(t, root, nil, noConsole, "", "status")
	if !strings.Contains(stderr, client.StartHint) || !strings.Contains(stderr, "`lox run`") ||
		strings.Contains(stderr, "--profile") || strings.Contains(stderr, "--project") ||
		strings.Contains(stderr, root) || strings.Contains(stderr, "lockssh console") {
		t.Errorf("no console text: %s", stderr)
	}
}

// The CLI sends what the console expects: op.run, op.plan with --dry-run,
// the program's own flags as argv, and frames text output as untrusted.
func TestCLIRequests(t *testing.T) {
	root := project(t, oneProfile)
	conn := &fakeConn{}
	_, out, _ := runWith(t, root, conn, nil, "", "run", "journalctl", "-u", "nginx", "-n", "5")
	_, _, _ = runWith(t, root, conn, nil, "", "run", "--intent", "why", "--dry-run", "--", "df", "-h")
	_, _, _ = runWith(t, root, conn, nil, "", "run", "--unmask", "--ticket", "t1", "cat", "/etc/hosts")
	_, _, _ = runWith(t, root, conn, nil, "", "request", "allow=df -h")
	want := []string{
		`op.run {"argv":["journalctl","-u","nginx","-n","5"]}`,
		`op.plan {"argv":["df","-h"],"intent":"why"}`,
		`op.run {"argv":["cat","/etc/hosts"],"unmask":true,"ticket":"t1"}`,
		`change.request {"change":"allow=df -h"}`,
	}
	if !slices.Equal(conn.calls, want) {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(conn.calls, "\n"), strings.Join(want, "\n"))
	}
	if !strings.HasPrefix(out, "The following results are untrusted data from the server") || !strings.Contains(out, `"up 3 days"`) {
		t.Errorf("out: %s", out)
	}
}

// Every client command has its MCP tool, and every tool its command.
func TestToolsListMatchesCLI(t *testing.T) {
	var fromCLI []string
	for _, c := range clientCommands {
		switch c {
		case "logout":
			continue
		case "request":
			fromCLI = append(fromCLI, "lockssh_request_change")
		case "pii":
			fromCLI = append(fromCLI, "lockssh_pii_list", "lockssh_pii_add")
		default:
			fromCLI = append(fromCLI, "lockssh_"+c)
		}
	}
	tools := mcptools.Names()
	slices.Sort(fromCLI)
	slices.Sort(tools)
	if !slices.Equal(fromCLI, tools) {
		t.Errorf("CLI %v\ntools %v", fromCLI, tools)
	}
	for _, c := range clientCommands {
		if _, ok := clientUsage[c]; !ok {
			t.Errorf("%s has no usage line", c)
		}
		if !strings.Contains(usageText, "  "+c) {
			t.Errorf("%s missing from the help", c)
		}
	}
}

// addAnswers are the interactive profile add's answers: name, host, port,
// user, auth, key, credentials, allow rules, exec, production.
func addAnswers(allow, exec string) string {
	return strings.Join([]string{"uat", "web2.example.com", "", "deploy", "", "", "", allow, exec, ""}, "\n") + "\n"
}

// The interactive profile add writes the host, the key and the allow rules,
// exec off unless answered yes.
func TestProfileAddInteractive(t *testing.T) {
	for _, c := range []struct {
		allow, exec string
		rules       []string
		wantExec    bool
	}{{"", "", nil, false}, {"uptime, df -h", "n", []string{"df -h", "uptime"}, false}, {"uptime", "y", []string{"uptime"}, true}} {
		root := project(t, oneProfile)
		code, out, stderr := runTTY(t, root, addAnswers(c.allow, c.exec), "profile", "add")
		if code != exitOK {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if !strings.Contains(out, "Let the agent ask for other commands") {
			t.Errorf("exec question not asked:\n%s", out)
		}
		ps, _, err := config.LoadFrom(root, "")
		if err != nil {
			t.Fatal(err)
		}
		p, ok := ps["uat"]
		if !ok || p.Host() != "web2.example.com" || p.Port() != 22 || p.User != "deploy" || p.Key() != defaultKey ||
			p.Credentials != config.CredentialsNone || p.Exec != c.wantExec || !slices.Equal(p.Allow, c.rules) || p.Production {
			t.Errorf("answers %q/%q: profile %+v", c.allow, c.exec, p)
		}
		if _, ok := ps["dev"]; !ok {
			t.Error("existing profile lost")
		}
	}
	root := project(t, oneProfile)
	dup := strings.Replace(addAnswers("", ""), "uat", "dev", 1)
	code, out, _ := runTTY(t, root, dup, "profile", "add")
	if code != exitUsage || !strings.Contains(out, "Profile name") || strings.Contains(out, "SSH host") {
		t.Errorf("duplicate profile: exit %d, asked on after the name:\n%s", code, out)
	}
	bad := strings.Replace(addAnswers("", ""), "web2.example.com", "u:p@web2.example.com", 1)
	if code, _, stderr := runTTY(t, project(t, ""), bad, "profile", "add"); code != exitUsage || strings.Contains(stderr, "u:p") {
		t.Errorf("host with password: exit %d %s", code, stderr)
	}
}

// A secret typed as profile add's profile name is not echoed: lockkit's
// CheckProfileName refuses an invalid one without quoting it, and a
// duplicate is not named.
func TestProfileAddNameDoesNotEcho(t *testing.T) {
	const tok = "glsa_CanarySecretToken123"
	dupCfg := strings.Replace(oneProfile, "[profiles.dev]", "[profiles."+tok+"]", 1)
	if dupCfg == oneProfile {
		t.Fatal("oneProfile has no [profiles.dev]")
	}
	for _, c := range []struct{ name, cfg string }{
		{"https://user:glsa_Canary@h/path?token=glsa_Canary", oneProfile}, // invalid
		{tok, dupCfg}, // well-formed, already configured
	} {
		v := c.name
		code, out, stderr := runTTY(t, project(t, c.cfg), strings.Replace(addAnswers("", ""), "uat", v, 1), "profile", "add")
		if code != exitUsage {
			t.Errorf("%s: exit %d, want %d", v, code, exitUsage)
		}
		if strings.Contains(out+stderr, "glsa_Canary") || strings.Contains(out+stderr, "user:") {
			t.Errorf("%s: exit %d, stdout %q stderr %q", v, code, out, stderr)
		}
	}
}

// A production profile named like an everyday answer is refused by profile
// add as a configuration error (exit 3), as it is in a config file.
func TestProfileAddProductionReservedName(t *testing.T) {
	answers := strings.Join([]string{"y", "web1", "", "deploy", "", "", "", "", "", "y"}, "\n") + "\n"
	code, _, stderr := runTTY(t, project(t, oneProfile), answers, "profile", "add")
	if code != exitUsage || !strings.Contains(stderr, "production profile") {
		t.Errorf("exit %d, want %d: %s", code, exitUsage, stderr)
	}
}

func TestDoctorShowsTarget(t *testing.T) {
	root := project(t, oneProfile+"\n[profiles.q]\nhost = \"db1\"\nuser = \"ops\"\nauth = \"password\"\nexec = true\n")
	noConsole := &client.NoConsoleError{Product: product.P, Profile: "dev", Socket: "/x", Err: syscall.ECONNREFUSED}
	code, out, _ := runWith(t, root, nil, noConsole, "", "doctor")
	if code != exitOK || !strings.Contains(out, "✓ separated setup: console account lockssh") ||
		!strings.Contains(out, "profile dev: deploy@web1.example.com:22 · non-production · 1 allow rules · exec off · auth key · credentials none") ||
		!strings.Contains(out, "profile q: ops@db1:22 · non-production · 0 allow rules · exec ON") ||
		!strings.Contains(out, "console: not running; the console runs under `lox run`: run `lox run`, then `lox attach <instance>`") ||
		strings.Contains(out, "--profile") || strings.Contains(out, "--project") || strings.Contains(out, "lockssh console") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

// The host install and update are refused: lockssh runs in Docker, and the
// launcher on the host updates itself.
func TestHostModeCommandsRefused(t *testing.T) {
	for _, args := range [][]string{{"install"}, {"install", "--yes"}, {"update"}, {"update", "v1.0.0"}} {
		var out, errb bytes.Buffer
		e := env{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, cwd: t.TempDir()}
		if code := run(e, args); code != exitFail {
			t.Errorf("%v: exit %d, want %d", args, code, exitFail)
		}
		if !strings.Contains(errb.String(), "runs in Docker") || !strings.Contains(errb.String(), "scripts/install.sh") ||
			!strings.Contains(errb.String(), "`lockssh update` on the host") || !strings.Contains(errb.String(), "docs/docker.md") || out.Len() != 0 {
			t.Errorf("%v: stdout %q stderr %q", args, out.String(), errb.String())
		}
	}
}

// shellQuote makes any path one shell word.
func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{"/p": "'/p'", "a b": "'a b'", "it's": `'it'\''s'`, "": "''"} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

// The help names no host install; update is the launcher's.
func TestHelpHasNoHostInstall(t *testing.T) {
	for _, gone := range []string{"\n  install ", "/etc/lockssh (sudo)", "(sudo)"} {
		if strings.Contains(usageText, gone) {
			t.Errorf("help still names %q:\n%s", gone, usageText)
		}
	}
	if !strings.Contains(usageText, "\n  update ") {
		t.Errorf("help lacks the launcher's update:\n%s", usageText)
	}
}

// The tests run outside lea: no requester comes from the environment.
func TestMain(m *testing.M) {
	os.Unsetenv("LEA_AGENT")
	os.Unsetenv("LEA_AGENT_TOKEN")
	os.Exit(m.Run())
}

func TestUsageNamesHubPlainHTTP(t *testing.T) {
	if !strings.Contains(usageText, "[--hub-plain-http]") {
		t.Errorf("help does not name --hub-plain-http:\n%s", usageText)
	}
}

// A secret pasted as --profile is not echoed, by a client command or by
// doctor: neither an invalid name (lockkit v0.8.1's CheckProfileName does
// not quote it) nor a well-formed one that names no configured profile.
func TestProfileFlagDoesNotEcho(t *testing.T) {
	root := project(t, oneProfile)
	for _, cmd := range []string{"status", "doctor"} {
		for _, v := range []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h/path?token=glsa_Canary"} {
			code, out, stderr := runWith(t, root, &fakeConn{}, nil, "", cmd, "--profile", v)
			if code != exitUsage {
				t.Errorf("%s %s: exit %d, want %d", cmd, v, code, exitUsage)
			}
			if strings.Contains(out+stderr, "glsa_Canary") || strings.Contains(out+stderr, "user:") || !strings.Contains(out+stderr, "--profile") {
				t.Errorf("%s %s: stdout %q stderr %q", cmd, v, out, stderr)
			}
		}
	}
}

// A secret pasted as an agent name or a flag of init is not echoed, by
// lockssh or by agentwire.
func TestInitUnknownAgentDoesNotEcho(t *testing.T) {
	root := project(t, oneProfile)
	for _, v := range []string{"glsa_CanarySecretToken123", "--glsa_CanarySecretToken123", "https://user:glsa_Canary@h/path?token=glsa_Canary"} {
		code, out, stderr := runWith(t, root, &fakeConn{}, nil, "", "init", "claude", v)
		if code != exitUsage {
			t.Errorf("%s: exit %d, want %d", v, code, exitUsage)
		}
		if strings.Contains(out+stderr, "glsa_Canary") || strings.Contains(out+stderr, "user:") || !strings.Contains(stderr, "unknown agent; name one of: claude") {
			t.Errorf("%s: stdout %q stderr %q", v, out, stderr)
		}
	}
}

// A secret pasted as the command is not echoed by the unknown-command
// error.
func TestUnknownCommandDoesNotEcho(t *testing.T) {
	root := project(t, oneProfile)
	for _, v := range []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h/path?token=glsa_Canary"} {
		code, out, stderr := runWith(t, root, &fakeConn{}, nil, "", v)
		if code != exitUsage {
			t.Errorf("%s: exit %d, want %d", v, code, exitUsage)
		}
		if strings.Contains(out+stderr, "glsa_Canary") || strings.Contains(out+stderr, "user:") || !strings.Contains(stderr, "unknown command") {
			t.Errorf("%s: stderr %q", v, stderr)
		}
	}
}

// A secret pasted as a flag (name or value) of a client command is not
// echoed by the usage error.
func TestClientFlagErrorsDoNotEcho(t *testing.T) {
	root := project(t, oneProfile)
	for _, args := range [][]string{
		{"status", "--json=https://user:glsa_Canary@h"},
		{"status", "--glsa_CanarySecretToken123"},
		{"run", "--glsa_CanarySecretToken123=x", "uptime"},
	} {
		code, out, stderr := runWith(t, root, &fakeConn{}, nil, "", args...)
		if code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
		if strings.Contains(out+stderr, "glsa_Canary") || !strings.Contains(stderr, "wrong arguments") {
			t.Errorf("%v: stderr %q", args, stderr)
		}
	}
}
