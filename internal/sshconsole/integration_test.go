//go:build integration

package sshconsole

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/tunnel"
)

// A real OpenSSH server and its login shell: the quoted argv reaches the
// program exactly, whatever shell syntax it holds, a timeout kills the
// command, and the exit status comes back.
//
//	go test -tags integration ./internal/sshconsole/
func TestOpenSSH(t *testing.T) {
	home := t.TempDir()
	tun, _ := openSSH(t, home, "lockssh-it-sshd")
	defer tun.Close()
	argv := []string{"printf", "%s|", "a; rm -rf /tmp/nothing", "$(id)", "it's", "`whoami`", "*", "~", "$HOME", "a\tb", "\"q\"", "\\n"}
	res, err := execute(context.Background(), tun, argv, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join(argv[2:], "|") + "|"
	if string(res.stdout) != want || res.exit == nil || *res.exit != 0 {
		t.Errorf("stdout %q exit %v stderr %q, want %q", res.stdout, res.exit, res.stderr, want)
	}
	res, err = execute(context.Background(), tun, []string{"sh", "-c", "exit 7"}, 64)
	if err != nil || res.exit == nil || *res.exit != 7 {
		t.Errorf("exit 7: %+v %v", res, err)
	}
	// argv[0] goes through exec: a builtin of that name never runs, and
	// nothing after it does (127: no such program on the PATH).
	for _, b := range [][]string{{"eval", "echo pwned"}, {"builtin", "echo", "pwned"}, {".", "/dev/stdin"}, {"trap", "echo pwned", "EXIT"}} {
		res, err := execute(context.Background(), tun, b, 1<<10)
		if err != nil || strings.Contains(string(res.stdout), "pwned") || res.exit == nil || *res.exit == 0 {
			t.Errorf("%q: %+v %v", b, res, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	res, err = execute(ctx, tun, []string{"sleep", "30"}, 64)
	if err != nil || !res.timedOut || time.Since(start) > 10*time.Second {
		t.Errorf("timeout: %+v %v", res, err)
	}
	// The tunnel still runs commands after a killed one.
	if res, err := execute(context.Background(), tun, []string{"id", "-un"}, 64); err != nil || strings.TrimSpace(string(res.stdout)) != "deploy" {
		t.Errorf("after timeout: %+v %v", res, err)
	}
}

// openSSH starts an OpenSSH server container (name) that accepts the
// client key of home for deploy, and opens a tunnel to it, trusting its
// host key into home/known_hosts. It returns the tunnel and the port.
func openSSH(t *testing.T, home, name string) (*tunnel.Tunnel, int) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	pub := clientKey(t, home)
	exec.Command("docker", "rm", "-f", name).Run()
	out, err := exec.Command("docker", "run", "-d", "--name", name, "-p", "127.0.0.1::2222",
		"-e", "PUBLIC_KEY="+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), "-e", "USER_NAME=deploy",
		"lscr.io/linuxserver/openssh-server:latest").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	pp, err := exec.Command("docker", "port", name, "2222/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, ps, _ := net.SplitHostPort(strings.TrimSpace(strings.Split(string(pp), "\n")[0]))
	port, _ := strconv.Atoi(ps)
	prof := kconfig.SSHProfile{Host: "127.0.0.1", Port: port, User: "deploy", Auth: kconfig.SSHAuthKey,
		Key: filepath.Join(home, ".ssh", "id_ed25519"), Credentials: "none"}
	kh := filepath.Join(home, "known_hosts")
	os.WriteFile(kh, nil, 0o600)
	hk, err := tunnel.KnownHosts(kh, func(string, string, string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		tun, err := tunnel.Open(context.Background(), tunnel.Options{Profile: prof, Home: home, HostKey: hk, ClientName: "lockssh"})
		if err == nil {
			return tun, port
		}
		if time.Now().After(deadline) {
			t.Fatalf("no sshd: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
}
