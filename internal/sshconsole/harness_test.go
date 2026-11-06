//go:build unix

package sshconsole

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"

	"github.com/DavidGodefroid/lockssh/internal/product"
)

// fakeHost is an SSH server whose exec requests run fake programs: it
// splits the command line as a POSIX shell splits single-quoted words, so
// a test sees exactly the argv the remote shell would.
type fakeHost struct {
	mu      sync.Mutex
	addr    string
	hostKey ssh.Signer
	// lines are the command lines received, in order.
	lines []string
	uid   string
}

func newFakeHost(t *testing.T, clientKey ssh.PublicKey) *fakeHost {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHost{hostKey: signer, uid: "1000"}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), clientKey.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("no")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = ln.Addr().String()
	var conns []net.Conn
	var cmu sync.Mutex
	t.Cleanup(func() {
		ln.Close()
		cmu.Lock()
		for _, c := range conns {
			c.Close()
		}
		cmu.Unlock()
	})
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			cmu.Lock()
			conns = append(conns, nc)
			cmu.Unlock()
			go h.serve(nc, cfg)
		}
	}()
	return h
}

func (h *fakeHost) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go h.session(ch, creqs)
	}
}

func (h *fakeHost) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		switch r.Type {
		case "exec":
			var cmd struct{ Command string }
			if ssh.Unmarshal(r.Payload, &cmd) != nil {
				r.Reply(false, nil)
				return
			}
			r.Reply(true, nil)
			h.mu.Lock()
			h.lines = append(h.lines, cmd.Command)
			h.mu.Unlock()
			killed := make(chan struct{})
			go func() {
				for r := range reqs {
					if r.Type == "signal" {
						close(killed)
						return
					}
				}
			}()
			argv, ok := splitQuoted(cmd.Command)
			status, sig := 127, ""
			if ok {
				status, sig = h.program(ch, argv, killed)
			} else {
				fmt.Fprintln(ch.Stderr(), "sh: unbalanced quotes")
				status = 2
			}
			if sig != "" {
				ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
					Signal     string
					CoreDumped bool
					Error      string
					Lang       string
				}{Signal: sig}))
			} else {
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
			}
			return
		default:
			r.Reply(false, nil)
		}
	}
}

// program runs a fake program: its exit status, or the signal that ended
// it.
func (h *fakeHost) program(ch ssh.Channel, argv []string, killed <-chan struct{}) (int, string) {
	switch argv[0] {
	case "id":
		h.mu.Lock()
		uid := h.uid
		h.mu.Unlock()
		fmt.Fprintln(ch, uid)
	case "uptime":
		fmt.Fprintln(ch, "up 3 days, ops contact alice@example.com from 8.8.8.8, password=correct-horse-battery")
	case "echo":
		fmt.Fprintln(ch, strings.Join(argv[1:], " "))
	case "fail":
		fmt.Fprintln(ch.Stderr(), "failed for bob@example.com")
		return 3, ""
	case "big":
		ch.Write(bytes.Repeat([]byte("x"), 200<<10))
	case "sleep":
		select {
		case <-killed:
			return 0, "KILL"
		case <-time.After(30 * time.Second):
		}
	case "rm", "reboot", "cat":
		fmt.Fprintln(ch, "ran "+strings.Join(argv, " "))
	default:
		fmt.Fprintln(ch.Stderr(), "sh: "+argv[0]+": not found")
		return 127, ""
	}
	return 0, ""
}

func (h *fakeHost) received() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.lines...)
}

// splitQuoted splits a line of single-quoted words separated by spaces,
// with '\” for a quote, as a POSIX shell does.
func splitQuoted(s string) ([]string, bool) {
	var out []string
	var cur strings.Builder
	in, word := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case in && c == '\'':
			in = false
		case in:
			cur.WriteByte(c)
		case c == '\'':
			in, word = true, true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			word = true
		case c == ' ':
			if word {
				out = append(out, cur.String())
				cur.Reset()
				word = false
			}
		default:
			// Anything unquoted would be shell syntax: not produced by
			// command.Line.
			return nil, false
		}
	}
	if in {
		return nil, false
	}
	if word {
		out = append(out, cur.String())
	}
	return out, len(out) > 0
}

// clientKey writes an unencrypted ed25519 key at home/.ssh/id_ed25519.
func clientKey(t *testing.T, home string) ssh.PublicKey {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return sp
}

type fakeIO struct {
	mu      sync.Mutex
	out     []string
	prompts []string
	answers []string
}

func (f *fakeIO) Println(s string) { f.mu.Lock(); defer f.mu.Unlock(); f.out = append(f.out, s) }
func (f *fakeIO) Ask(_ context.Context, prompt string, _ time.Duration) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prompts = append(f.prompts, prompt)
	if len(f.answers) == 0 {
		return "", false
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	return a, true
}
func (f *fakeIO) AskSecret(_ context.Context, prompt string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prompts = append(f.prompts, prompt)
	return nil, errors.New("no secret")
}
func (f *fakeIO) promptCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.prompts) }
func (f *fakeIO) output() string   { f.mu.Lock(); defer f.mu.Unlock(); return strings.Join(f.out, "\n") }

type rig struct {
	t        *testing.T
	host     *fakeHost
	io       *fakeIO
	be       *Backend
	srv      *console.Server
	root     string
	state    string
	home     string
	peer     *ipc.Cred
	closeHub func()
}

type rigOpts struct {
	production               bool
	extra                    string // more profile lines
	allow                    []string
	exec                     bool
	answers                  []string
	allowUnmask, showResults bool
	hub                      *console.HubOptions
	now                      func() time.Time
	// tofu leaves known_hosts unset (the console account's file, empty):
	// the console asks to trust the key.
	tofu bool
}

func profileName(o rigOpts) string {
	if o.production {
		return "prod"
	}
	return "uat"
}

// writeProject writes the profile of o for host, its known_hosts file (but
// with tofu) in home.
func writeProject(t *testing.T, root, home string, host *fakeHost, o rigOpts) {
	t.Helper()
	h, p, _ := net.SplitHostPort(host.addr)
	cfg := "[profiles." + profileName(o) + "]\nhost = \"" + h + "\"\nport = " + p + "\nuser = \"deploy\"\nkey = \"~/.ssh/id_ed25519\"\n"
	if !o.tofu {
		kh := filepath.Join(home, "known_hosts.pinned")
		port, _ := strconv.Atoi(p)
		line := knownhosts.Line([]string{knownhosts.Normalize(net.JoinHostPort(h, strconv.Itoa(port)))}, host.hostKey.PublicKey())
		if err := os.WriteFile(kh, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg += "known_hosts = \"" + kh + "\"\n"
	}
	allow := o.allow
	if allow == nil {
		allow = []string{"uptime", "echo **", "fail", "big", "sleep *", "systemctl status *"}
	}
	q := make([]string, len(allow))
	for i, a := range allow {
		q[i] = strconv.Quote(a)
	}
	cfg += "allow = [" + strings.Join(q, ", ") + "]\n"
	if o.exec {
		cfg += "exec = true\n"
	}
	if o.production {
		cfg += "production = true\n"
	}
	cfg += o.extra
	dir := filepath.Join(root, ".lockssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	home := t.TempDir()
	host := newFakeHost(t, clientKey(t, home))
	r := &rig{t: t, host: host, io: &fakeIO{answers: o.answers}, root: t.TempDir(), state: t.TempDir(), home: home}
	writeProject(t, r.root, home, host, o)
	var err error
	r.be, err = New(Options{Profile: profileName(o), Root: r.root, StateDir: r.state, IO: r.io, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := r.be.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	sess, err := r.be.Connect(context.Background(), console.Credentials{User: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	log, err := audit.Open(product.P, r.state)
	if err != nil {
		t.Fatal(err)
	}
	cfg := console.ServerConfig{Product: product.P, Backend: r.be, Policy: pol, Session: sess,
		Audit: log, IO: r.io, AllowUnmask: o.allowUnmask, ShowResults: o.showResults, Sanitizer: Sanitizer(), Now: o.now}
	if o.hub != nil {
		h, err := console.OpenHub(product.P, *o.hub, r.state, o.now)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Hub, cfg.Approver = h, h.Approver(console.NewTypedApprover(r.io))
		r.be.OnHub(h)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var once sync.Once
		r.closeHub = func() {
			once.Do(func() {
				cancel()
				<-done
				if err := h.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		t.Cleanup(r.closeHub)
		go func() { defer close(done); h.Watch(ctx, r.io) }()
	}
	r.srv, err = console.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hub != nil {
		cfg.Hub.Requests(r.io, func(b audit.Base) { r.srv.AuditBase(context.Background(), b) })
	}
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rig) call(method string, params any) ipc.Response {
	r.t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		r.t.Fatal(err)
	}
	ctx := context.Background()
	if r.peer != nil {
		ctx = console.WithPeer(ctx, *r.peer)
	}
	return r.srv.Handle(ctx, ipc.Request{JSONRPC: "2.0", ID: 7, Method: method, Params: raw})
}

func (r *rig) auditLog() string {
	raw, _ := os.ReadFile(filepath.Join(r.state, product.P.Name, "audit.log"))
	return string(raw)
}

func mustOK(t *testing.T, resp ipc.Response) string {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	return string(resp.Result)
}

// output decodes op.run's result.
func output(t *testing.T, resp ipc.Response) Output {
	t.Helper()
	var res Result
	if err := json.Unmarshal([]byte(mustOK(t, resp)), &res); err != nil {
		t.Fatal(err)
	}
	if res.Untrusted != Untrusted {
		t.Errorf("untrusted framing %q", res.Untrusted)
	}
	return res.Data
}

func refusedCode(t *testing.T, resp ipc.Response) string {
	t.Helper()
	if resp.Error == nil || resp.Error.Code != ipc.CodeRefused || resp.Error.Data == nil {
		t.Fatalf("not refused: %+v %s", resp.Error, resp.Result)
	}
	return string(resp.Error.Data.Code)
}
