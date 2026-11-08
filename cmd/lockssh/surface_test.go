package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/ipc"
)

// pii list and pii add reach the console's pii.list and pii.add; anything
// else is a usage error.
func TestCLIPII(t *testing.T) {
	root := project(t, oneProfile)
	conn := &fakeConn{}
	for _, args := range [][]string{{"pii", "list"}, {"pii", "add", "cust-[0-9]{6}"}} {
		if code, _, stderr := runWith(t, root, conn, nil, "", args...); code != exitOK {
			t.Errorf("%q: exit %d %s", args, code, stderr)
		}
	}
	want := []string{`pii.list null`, `pii.add {"pattern":"cust-[0-9]{6}"}`}
	if !slices.Equal(conn.calls, want) {
		t.Errorf("calls %q, want %q", conn.calls, want)
	}
	for _, args := range [][]string{{"pii"}, {"pii", "purge"}, {"pii", "add"}, {"pii", "list", "x"}} {
		if code, _, _ := runWith(t, root, &fakeConn{}, nil, "", args...); code != exitUsage {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

// version --json carries the console protocol major, for lea's
// locks.lock and lockhub's contract tests.
func TestVersionJSON(t *testing.T) {
	code, out, _ := runWith(t, project(t, oneProfile), nil, nil, "", "version", "--json")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if len(v) != 3 || v["name"] != "lockssh" || v["version"] != version || v["protocol_major"] != float64(ipc.ProtocolMajor) {
		t.Errorf("version --json %s", out)
	}
	if code, out, _ := runWith(t, project(t, oneProfile), nil, nil, "", "version"); code != exitOK || strings.TrimSpace(out) != "lockssh "+version {
		t.Errorf("version: %d %q", code, out)
	}
	if code, _, _ := runWith(t, project(t, oneProfile), nil, nil, "", "version", "--yaml"); code != exitUsage {
		t.Errorf("version --yaml: exit %d", code)
	}
}
