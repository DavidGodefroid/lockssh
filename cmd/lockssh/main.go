// Command lockssh lets an AI agent run commands on a server over SSH
// through a console the human holds: the key never reaches the agent, the
// allow-listed commands run at once, any other one waits for the human,
// and the output is masked.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/DavidGodefroid/lockkit/agentwire"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/sysconf"

	"github.com/DavidGodefroid/lockssh/internal/mcptools"
)

// version is set at build time (-X main.version=...).
var version = "dev"

// Exit codes: 0 ok, 1 refused/denied/failed, 2 no console, 3 usage or
// configuration error.
const (
	exitOK        = 0
	exitFail      = 1
	exitNoConsole = 2
	exitUsage     = 3
)

// env is what a command reads and writes; tests replace it.
type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	cwd            string
	// tty reports whether stdin is a terminal.
	tty bool
	// dial connects to the console of a profile; nil is the real socket.
	dial func(profile string) (mcptools.Conn, error)
	// userConfig is the user config file; "" is the real one.
	userConfig string
	// home holds the hub instance key; "" is the account's home.
	home string
	// stateDir is the state base the consoles keep their approved
	// policies in; "" is kit.StateBase().
	stateDir string
	// agentEnv is the account the agents are wired for; nil is the real
	// one.
	agentEnv func() (agentwire.Env, error)
	// root runs doctor --fix's script as root; nil is sudo sh -c.
	root func(script string) error
	// sys reads the separated setup; nil is lockkit's sysconf.Load.
	sys func() (*sysconf.Config, error)
	// container reports a process in a container; nil is the real check.
	container func() bool
	// euid is the effective uid; nil is os.Geteuid.
	euid func() int
	// svc looks up the console account; nil is the real lookup.
	svc func(name string) (svcAccount, bool)
	// getenv reads the environment; nil is os.Getenv.
	getenv func(name string) string
	// leaveRoot makes doctor, run as root, the agent account; nil is the
	// real switch.
	leaveRoot func() error
}

const usageText = `usage: lockssh <command> [arguments]

Human commands
  profile add [--non-interactive] [--json] [--project DIR] [--profile NAME] [--production]
             [--credentials none|ask|vault [--vault-path P]] --host HOST [--port N] --user USER
             [--auth key|password] [--key FILE] [--known-hosts FILE] [--allow "RULE"]... [--exec]
                                        add an SSH host profile to the project (asks for what
                                        the flags do not give; never for a secret)
  profile rules [--json] [--project DIR] [--profile NAME]
                                        the profiles' auto rules (connect, run, exec, unmask:
                                        auto, ask or deny), as lox run applies them
  console   --hub URL [--hub-plain-http] --hub-key-file FILE --instance NAME (hub instance name)
             [--profile P] [--project DIR] [--allow-unmask] [--show-results]
             [--allowed-uids UID,...]
                                        run the console, attached to lockhub, which decides
                                        requests (launched by lox up)
  hub-key    --instance NAME (hub instance name)
                                        print the instance key for lockhub to pin
  doctor     [--profile P] [--instance NAME] [--fix [--yes]] [--json]
                                        check the config, the consoles, the project's
                                        .lockssh and the agent wiring
  init       [claude|codex|cursor|gemini ...]
                                        wire agents to lockssh in the project (never asks)
  update     [vX.Y.Z]                   update the launcher and its image (on the host;
                                        cosign signature and checksum checked)

Client commands (--profile P, --json)
  --instance NAME  the lock to reach when lea mounts several (default: LOCKSSH_INSTANCE, else the one in LEA_LOCKSSH_INSTANCES); not the hub instance name of console/hub-key
  status
  run           [--intent TEXT] [--unmask] [--dry-run] [--ticket T] [--] PROGRAM [ARG]...
                                        run a command on the host (argv, no shell; masked
                                        output); flags before the program
  request       "allow=..."             queue a change for the human (never applied)
  logout
  mcp           [--profile P] [--instance NAME]  MCP server on stdin/stdout

Other
  version, help

Exit codes  0 ok · 1 refused/denied/failed · 2 no console · 3 usage/config error
`

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "lockssh:", err)
		os.Exit(exitFail)
	}
	os.Exit(run(env{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, cwd: cwd,
		tty: term.IsTerminal(int(os.Stdin.Fd()))}, os.Args[1:]))
}

// clientCommands are the commands that talk to a console.
var clientCommands = []string{"status", "run", "request", "logout"}

func run(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(e.stderr, usageText)
		return exitUsage
	}
	switch cmd := args[0]; cmd {
	case "version", "--version":
		fmt.Fprintln(e.stdout, "lockssh "+version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(e.stdout, usageText)
		return exitOK
	case "console":
		return runConsole(e, args[1:])
	case "mcp":
		return runMCP(e, args[1:])
	case "profile":
		return runProfile(e, args[1:])
	case "doctor":
		return runDoctor(e, args[1:])
	case "init":
		return runInit(e, args[1:])
	case "hub-key":
		return runHubKey(e, args[1:])
	case "install", "update":
		fmt.Fprintln(e.stderr, hostModeRefusal(cmd))
		return exitFail
	default:
		for _, c := range clientCommands {
			if c == cmd {
				return runClient(e, cmd, args[1:])
			}
		}
		// The command is not quoted: it may be a token pasted in the
		// wrong place.
		fmt.Fprintf(e.stderr, "lockssh: unknown command; the commands are:\n\n%s", usageText)
		return exitUsage
	}
}

// hostModeRefusal is printed for the command of the former host install
// (install), and for update, which only the launcher runs. lockssh runs in
// Docker: the launcher on the host (scripts/lockssh) runs every command in
// the image and updates itself and the image.
func hostModeRefusal(cmd string) string {
	return "lockssh " + cmd + ": the host install is gone: lockssh runs in Docker. " +
		"Install the launcher with scripts/install.sh; `lockssh update` on the host updates it and its image; " +
		"see docs/docker.md"
}

// usageFail prints a usage error.
func usageFail(e env, cmd, usage, msg string) int {
	fmt.Fprintf(e.stderr, "lockssh %s: %s\nusage: %s\n", cmd, msg, strings.TrimSpace(usage))
	return exitUsage
}

// runHubKey is `lockssh hub-key --instance NAME`: the instance's public key,
// made on the first call in the console account's home, for `lox up`.
func runHubKey(e env, args []string) int {
	home := e.home
	if home == "" {
		var err error
		if home, err = os.UserHomeDir(); err != nil {
			fmt.Fprintln(e.stderr, "lockssh hub-key:", err)
			return exitFail
		}
	}
	if err := hubclient.HubKeyCommand(e.stdout, home, args); err != nil {
		fmt.Fprintln(e.stderr, "lockssh hub-key:", err)
		return exitUsage
	}
	return exitOK
}
