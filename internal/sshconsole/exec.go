package sshconsole

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/DavidGodefroid/lockssh/internal/command"
)

// sessioner opens SSH sessions (a *tunnel.Tunnel).
type sessioner interface {
	NewSession() (*ssh.Session, error)
}

// execResult is what one command did, before masking.
type execResult struct {
	stdout, stderr     []byte
	outTrunc, errTrunc bool
	exit               *int
	signal             string
	timedOut           bool
	duration           time.Duration
}

// capped keeps the first max bytes written to it and counts the rest.
type capped struct {
	mu    sync.Mutex
	buf   []byte
	max   int
	trunc bool
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - len(c.buf); room > 0 {
		if len(p) > room {
			c.buf = append(c.buf, p[:room]...)
			c.trunc = true
		} else {
			c.buf = append(c.buf, p...)
		}
	} else if len(p) > 0 {
		c.trunc = true
	}
	// Never an error: a full buffer must not block the remote command on a
	// full channel window.
	return len(p), nil
}

func (c *capped) bytes() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...), c.trunc
}

// errNoExitStatus: the server closed the session without an exit status.
var errNoExitStatus = errors.New("the server closed the session without an exit status")

// execute runs argv on t in a session of its own: no PTY, no stdin, each
// argument quoted (command.Line). ctx's deadline ends it: the command is
// sent SIGKILL and its session closed; the result then says timedOut.
// stdout and stderr keep max bytes each.
func execute(ctx context.Context, t sessioner, argv []string, max int) (execResult, error) {
	start := time.Now()
	sess, err := t.NewSession()
	if err != nil {
		return execResult{}, err
	}
	defer sess.Close()
	out, errw := &capped{max: max}, &capped{max: max}
	sess.Stdout, sess.Stderr = out, errw
	if err := sess.Start(command.Line(argv)); err != nil {
		return execResult{}, err
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	var res execResult
	select {
	case err = <-done:
	case <-ctx.Done():
		res.timedOut = true
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		select {
		case err = <-done:
		case <-time.After(2 * time.Second):
			err = ctx.Err()
		}
	}
	res.duration = time.Since(start)
	res.stdout, res.outTrunc = out.bytes()
	res.stderr, res.errTrunc = errw.bytes()
	var ee *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
		zero := 0
		res.exit = &zero
	case errors.As(err, &ee):
		if sig := ee.Signal(); sig != "" {
			res.signal = sig
		} else {
			st := ee.ExitStatus()
			res.exit = &st
		}
	case errors.As(err, &missing):
		if !res.timedOut {
			return res, errNoExitStatus
		}
	case res.timedOut:
	default:
		return res, err
	}
	return res, nil
}
