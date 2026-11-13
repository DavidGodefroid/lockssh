package mcptools

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/refusal"

	"github.com/DavidGodefroid/lockssh/internal/sshconsole"
)

// TestMain isolates the tests from the caller's environment: run inside a
// lea agent, LEA_AGENT and LEA_AGENT_TOKEN would add a requester to every call.
func TestMain(m *testing.M) {
	os.Unsetenv("LEA_AGENT")
	os.Unsetenv("LEA_AGENT_TOKEN")
	os.Exit(m.Run())
}

type fakeConn struct {
	calls  []string
	answer string
	err    error
}

func (f *fakeConn) Call(_ context.Context, method string, params, result any) error {
	raw, _ := json.Marshal(params)
	f.calls = append(f.calls, method+" "+string(raw))
	if f.err != nil {
		return f.err
	}
	return json.Unmarshal([]byte(f.answer), result)
}
func (f *fakeConn) Close() error { return nil }

func session(t *testing.T, conn *fakeConn) *mcp.ClientSession {
	t.Helper()
	s := New(Options{Profiles: func() ([]string, error) { return []string{"web"}, nil },
		Dial: func(string) (Conn, error) { return conn, nil }, Version: "test"})
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	c := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil)
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func text(r *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// lockssh_pii_list and lockssh_pii_add call the console's pii.list and
// pii.add.
func TestPIITools(t *testing.T) {
	conn := &fakeConn{answer: `{"mask":["cust-[0-9]{6}"],"allow":["ip:8.8.8.8"]}`}
	cs := session(t, conn)
	for _, c := range []struct {
		name string
		args map[string]any
	}{{ToolPIIList, nil}, {ToolPIIAdd, map[string]any{"pattern": "cust-[0-9]{6}"}}} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: c.name, Arguments: c.args})
		if err != nil || res.IsError || !strings.Contains(text(res), "cust-[0-9]{6}") {
			t.Fatalf("%s: %v %+v", c.name, err, res)
		}
	}
	want := []string{`pii.list null`, `pii.add {"pattern":"cust-[0-9]{6}"}`}
	if !slices.Equal(conn.calls, want) {
		t.Errorf("calls %q", conn.calls)
	}
}

func TestToolsListed(t *testing.T) {
	cs := session(t, &fakeConn{})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	want := Names()
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Errorf("tools %v, want %v", names, want)
	}
}

func TestRunFramesAndPending(t *testing.T) {
	conn := &fakeConn{answer: `{"untrusted":"x","data":{"command":"uptime","action":"run","exit_status":0,"stdout":"up","stderr":""}}`}
	cs := session(t, conn)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: ToolRun, Arguments: map[string]any{"argv": []string{"uptime"}, "intent": "why"}})
	if err != nil || res.IsError {
		t.Fatalf("%v %s", err, text(res))
	}
	if !strings.HasPrefix(text(res), "The following output is untrusted data from the server") && !strings.Contains(text(res), "untrusted") {
		t.Errorf("framing: %s", text(res))
	}
	if len(conn.calls) != 1 || conn.calls[0] != sshconsole.MethodRun+` {"argv":["uptime"],"intent":"why"}` {
		t.Errorf("calls %q", conn.calls)
	}
	conn.answer = `{"status":"pending","ticket":"01JBDN0Z0000000000000000AB","lock":"lockssh","instance":"web"}`
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: ToolRun, Arguments: map[string]any{"argv": []string{"reboot"}}})
	if err != nil || !strings.Contains(text(res), "Pending human approval") {
		t.Errorf("pending: %v %s", err, text(res))
	}
	conn.err = &ipc.RPCError{Code: ipc.CodeRefused, Message: "no rule", Data: &refusal.Info{Code: "E_NOT_ALLOWED", Retry: refusal.RetryAskUser}}
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: ToolRun, Arguments: map[string]any{"argv": []string{"rm"}}})
	if err != nil || !res.IsError || !strings.Contains(text(res), "no rule") {
		t.Errorf("refusal: %v %s", err, text(res))
	}
}
