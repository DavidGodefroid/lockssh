//go:build unix

package sshconsole

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/ticket"
)

const hubInstance = "web"

// hubRig is a console in hub mode beside a fake lockhub that approves every
// connect ticket as a human.
func hubRig(t *testing.T, o rigOpts) (*rig, *hubtest.Hub, ed25519.PublicKey) {
	t.Helper()
	var hub *hubtest.Hub
	var pub ed25519.PublicKey
	o.hub, hub, pub = hubOptions(t)
	approveConnects(t, hub)
	return newRig(t, o), hub, pub
}

func approveConnects(t *testing.T, hub *hubtest.Hub) {
	t.Helper()
	done := make(chan struct{})
	stopped := make(chan struct{})
	t.Cleanup(func() { close(done); <-stopped })
	go func() {
		defer close(stopped)
		seen := map[string]bool{}
		for {
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
			}
			for _, id := range hub.Tickets() {
				if seen[id] {
					continue
				}
				seen[id] = true
				var tk ticket.Ticket
				if json.Unmarshal(hub.Ticket(id), &tk) == nil && tk.Kind == ticket.KindConnect {
					hub.Decide(id, ticket.Approved, "")
				}
			}
		}
	}()
}

func hubOptions(t *testing.T) (*console.HubOptions, *hubtest.Hub, ed25519.PublicKey) {
	t.Helper()
	home := t.TempDir()
	key, err := hubclient.InstanceKey(home, hubInstance)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	hub := hubtest.New(t, hubInstance, pub)
	hubKey := filepath.Join(t.TempDir(), "hub.pub")
	if err := os.WriteFile(hubKey, []byte(base64.StdEncoding.EncodeToString(hub.Pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &console.HubOptions{URL: hub.URL(), KeyFile: hubKey, Instance: hubInstance, Home: home}, hub, pub
}

type pendingOut struct{ Status, Ticket, Lock, Instance string }

func pendingOf(t *testing.T, resp ipc.Response) pendingOut {
	t.Helper()
	var p pendingOut
	if resp.Error != nil || json.Unmarshal(resp.Result, &p) != nil || p.Status != "pending" || !ticket.ValidID(p.Ticket) || p.Lock != "lockssh" || p.Instance != hubInstance {
		t.Fatalf("not pending: %+v %s", resp.Error, resp.Result)
	}
	return p
}

// runDecided runs p until its ticket's decision has arrived.
func (r *rig) runDecided(p Params) ipc.Response {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp := r.call(MethodRun, p)
		var po pendingOut
		if resp.Error != nil || json.Unmarshal(resp.Result, &po) != nil || po.Status != "pending" {
			return resp
		}
		if time.Now().After(deadline) {
			r.t.Fatal("the decision never arrived")
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// An allow-listed command runs at once in hub mode too, once the
// session's connect ticket is approved; no plan ticket is pushed.
func TestHubAllowListedRunsAfterConnect(t *testing.T) {
	r, hub, _ := hubRig(t, rigOpts{})
	out := output(t, r.call(MethodRun, Params{Argv: []string{"uptime"}}))
	if out.Action != "run" {
		t.Fatalf("output %+v", out)
	}
	kinds := map[ticket.Kind]int{}
	for _, id := range hub.Tickets() {
		var tk ticket.Ticket
		_ = json.Unmarshal(hub.Ticket(id), &tk)
		kinds[tk.Kind]++
	}
	if kinds[ticket.KindConnect] != 1 || len(kinds) != 1 {
		t.Errorf("tickets %v", kinds)
	}
	output(t, r.call(MethodRun, Params{Argv: []string{"uptime"}}))
	if n := len(hub.Tickets()); n != 1 {
		t.Errorf("the second command asked again: %d tickets", n)
	}
}

// A command outside the allow list never runs without a decided plan: the
// agent hears pending, the ticket is an action of verb exec with the
// masked screen, and the decided ticket runs it once, for its own agent.
func TestHubExecRunsOnlyOnceDecided(t *testing.T) {
	r, hub, pub := hubRig(t, rigOpts{exec: true})
	p := Params{Argv: []string{"rm", "/tmp/x", "alice@example.com"}, Intent: "clean up", Requester: ipc.Requester{Agent: "dev-1", Token: "tok-1"}}
	before := len(r.host.received())
	pd := pendingOf(t, r.call(MethodRun, p))
	tk, err := ticket.VerifyTicket(pub, hub.Ticket(pd.Ticket))
	if err != nil || tk.Kind != ticket.KindAction || tk.Risk != ticket.RiskWrite || tk.Subject == nil || tk.Subject.Verb != "exec" ||
		tk.Subject.Target != "rm" || !tk.Flags.NeverAuto {
		t.Fatalf("ticket %+v %+v %v", tk, tk.Subject, err)
	}
	screen := strings.Join(tk.Screen.Body, "\n")
	if !strings.Contains(screen, "RUN rm /tmp/x") || strings.Contains(screen, "alice@example.com") {
		t.Errorf("screen:\n%s", screen)
	}
	run := p
	run.Ticket = pd.Ticket
	pendingOf(t, r.call(MethodRun, run))
	if len(r.host.received()) != before {
		t.Fatal("ran before the decision")
	}
	hub.Decide(pd.Ticket, ticket.Approved, "")
	other := run
	other.Requester = ipc.Requester{Agent: "dev-2", Token: "tok-2"}
	if resp := r.runDecided(other); resp.Error == nil || resp.Error.Code != ipc.CodeWrongRequester {
		t.Fatalf("other agent: %+v %s", resp.Error, resp.Result)
	}
	out := output(t, r.runDecided(run))
	if out.Action != "exec" || !strings.Contains(out.Stdout, "ran rm /tmp/x") || strings.Contains(out.Stdout, "alice") {
		t.Errorf("output %+v", out)
	}
	if resp := r.call(MethodRun, run); resp.Error == nil {
		t.Error("a ticket ran twice")
	}
	if !strings.Contains(r.auditLog(), `"decided_by":"human"`) {
		t.Error("decision not audited")
	}
}

// On production an exec is prod-write; a denial runs nothing.
func TestHubProductionExecDenied(t *testing.T) {
	r, hub, pub := hubRig(t, rigOpts{exec: true, production: true})
	p := Params{Argv: []string{"reboot"}}
	pd := pendingOf(t, r.call(MethodRun, p))
	tk, err := ticket.VerifyTicket(pub, hub.Ticket(pd.Ticket))
	if err != nil || tk.Risk != ticket.RiskProdWrite || !tk.Flags.Production {
		t.Fatalf("ticket %+v %v", tk, err)
	}
	before := len(r.host.received())
	hub.Decide(pd.Ticket, ticket.Denied, "no")
	p.Ticket = pd.Ticket
	if resp := r.runDecided(p); resp.Error == nil || resp.Error.Code != ipc.CodeDenied {
		t.Fatalf("denied: %+v %s", resp.Error, resp.Result)
	}
	if len(r.host.received()) != before {
		t.Fatal("a denied command ran")
	}
}

// An unmasked output is read-pii and never auto.
func TestHubUnmaskTicket(t *testing.T) {
	r, hub, pub := hubRig(t, rigOpts{allowUnmask: true})
	pd := pendingOf(t, r.call(MethodRun, Params{Argv: []string{"uptime"}, Unmask: true}))
	tk, err := ticket.VerifyTicket(pub, hub.Ticket(pd.Ticket))
	if err != nil || tk.Risk != ticket.RiskReadPII || !tk.Flags.NeverAuto || tk.Subject.Verb != "unmask" {
		t.Fatalf("ticket %+v %v", tk, err)
	}
	hub.Decide(pd.Ticket, ticket.Approved, "")
	out := output(t, r.runDecided(Params{Argv: []string{"uptime"}, Unmask: true, Ticket: pd.Ticket}))
	if !out.Unmasked || !strings.Contains(out.Stdout, "alice@example.com") {
		t.Errorf("output %+v", out)
	}
}

// A ticket decided for one argv does not run another.
func TestHubTicketBindsArgv(t *testing.T) {
	r, hub, _ := hubRig(t, rigOpts{exec: true})
	pd := pendingOf(t, r.call(MethodRun, Params{Argv: []string{"reboot"}}))
	hub.Decide(pd.Ticket, ticket.Approved, "")
	before := len(r.host.received())
	resp := r.runDecided(Params{Argv: []string{"rm", "-rf", "/"}, Ticket: pd.Ticket})
	out := output(t, resp)
	// The stored plan runs, never the argv sent beside the ticket.
	if !strings.Contains(out.Stdout, "ran reboot") || strings.Contains(strings.Join(r.host.received()[before:], " "), "rm") {
		t.Errorf("output %+v lines %q", out, r.host.received()[before:])
	}
}
