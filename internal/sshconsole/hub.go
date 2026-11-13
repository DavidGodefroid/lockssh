package sshconsole

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/pii"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/refusal"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockssh/internal/config"
	"github.com/DavidGodefroid/lockssh/internal/product"
)

// hubPlanTTL is how long a hub plan waits for its decision and its run.
const hubPlanTTL = 24 * time.Hour

// hubBody is a hub plan as the plan store keeps it: the request, prepared
// again from scratch once decided.
type hubBody struct {
	Params Params `json:"params"`
}

// planInputs are what the plan hash of a request covers: the argv and
// whether its output is asked in clear, and the class it fell in under the
// policy in force (the action and the rule that matched). The policy
// fingerprint is bound beside it.
type planInputs struct {
	Argv   []string `json:"argv"`
	Unmask bool     `json:"unmask"`
	Action string   `json:"action"`
	Rule   string   `json:"rule"`
}

func planInputsOf(p Params, pp *prep) planInputs {
	in := planInputs{Argv: p.Argv, Unmask: p.Unmask}
	if pp != nil {
		in.Action, in.Rule = pp.action, pp.rule
	}
	return in
}

// policyFP is the fingerprint of the policy in force, in the ticket's form.
func policyFP(pol Policy) string { return "sha256:" + kconfig.Fingerprint(pol.Policy) }

// screenDetectors mask personal data on the hub's screen and in the audit
// log's command.
var screenDetectors = func() []pii.Detector {
	ds, err := pii.Detectors([]string{"secret", "email", "phone", "iban", "card"})
	if err != nil {
		panic(err)
	}
	return ds
}()

// riskOf is the risk class of a request's ticket: a command outside the
// allow list may change the host (write, prod-write on production); an
// allow-listed one asked in clear is read-pii; masked, read.
func riskOf(pp *prep) ticket.Risk {
	switch {
	case pp.action == config.ActExec && pp.pol.Policy.Profile.Production:
		return ticket.RiskProdWrite
	case pp.action == config.ActExec:
		return ticket.RiskWrite
	case pp.unmask:
		return ticket.RiskReadPII
	}
	return ticket.RiskRead
}

// subjectOf is the structured request of a ticket: the profile, the action
// as the verb, the program's base name as the target when it is a valid,
// unmasked target (an action ticket names no endpoint: the profile does).
func subjectOf(pp *prep) *ticket.Subject {
	verb := pp.action
	if pp.unmask && verb == config.ActRun {
		verb = config.ActUnmask
	}
	s := &ticket.Subject{Profile: pp.pol.Policy.Profile.Name, Verb: verb}
	target := programName(pp.argv)
	if m, ok := pii.Detect(target, screenDetectors).(string); ok && m == target {
		s.Target = target
	}
	if s.Validate(ticket.KindAction) != nil {
		s.Target = ""
	}
	return s
}

// hubPlan turns a request that needs a decision into a plan decided on the
// hub: stored, bound to the peer, the agent's token and the policy, its
// masked screen pushed in a signed ticket. The agent hears pending.
func (b *Backend) hubPlan(ctx context.Context, req ipc.Request, env console.Env, h *console.Hub, p Params, pp *prep) ipc.Response {
	inputs := planInputsOf(p, pp)
	hash, err := ticket.HashOf(inputs)
	if err != nil {
		return console.ErrResp(req.ID, ipc.CodeInternal, env.Sanitizer().Error(err))
	}
	digests, err := ticket.InputDigests(inputs)
	if err != nil {
		return console.ErrResp(req.ID, ipc.CodeInternal, env.Sanitizer().Error(err))
	}
	clean := p
	clean.Ticket, clean.Requester = "", ipc.Requester{}
	raw, err := jsonOf(hubBody{Params: clean})
	if err != nil {
		return console.ErrResp(req.ID, ipc.CodeInternal, env.Sanitizer().Error(err))
	}
	caller := plans.Caller{UID: peerUID(ctx), Token: p.Requester.Token}
	stored, err := h.Store.Create(plans.Binding{UID: caller.UID, Agent: p.Requester.Agent, TokenHash: plans.HashToken(caller.Token),
		PolicyFP: policyFP(pp.pol), PlanHash: hash, Inputs: digests}, raw, hubPlanTTL)
	if err != nil {
		return console.ErrResp(req.ID, ipc.CodeInternal, env.Sanitizer().Error(err))
	}
	sc := *pp.screen
	sc.Record = func(base audit.Base) audit.Record { return b.recordOf(env, base, pp) }
	lines := make([]render.Line, 0, len(sc.Body))
	for _, l := range sc.Body {
		lines = append(lines, render.Structure(l))
	}
	sc.Hub = &console.HubTicket{PlanID: stored.ID, Caller: caller, Risk: riskOf(pp),
		Kind: ticket.KindAction, Subject: subjectOf(pp),
		Requester: ticket.Requester{Agent: p.Requester.Agent},
		Masked: render.MaskScreen(render.ScreenSource{Header: sc.Header, Note: sc.Note, Body: lines, Warnings: sc.Warnings, Red: sc.Red},
			render.Masking{Detectors: screenDetectors})}
	a := env.Approve(ctx, req.ID, sc)
	if a.Pending != nil {
		return a.Refusal
	}
	_ = h.Store.End(stored.ID, caller, plans.Withdrawn, "not submitted")
	if a.Approved {
		return console.ErrResp(req.ID, ipc.CodeInternal, "approved outside the hub in hub mode")
	}
	return a.Refusal
}

// hubRun runs the request of a decided ticket once: the decision verified
// and matched, the request prepared again under the policy in force, its
// hash unchanged.
func (b *Backend) hubRun(ctx context.Context, req ipc.Request, env console.Env, h *console.Hub, in Params) ipc.Response {
	caller := plans.Caller{UID: peerUID(ctx), Token: in.Requester.Token}
	// The session's connect ticket is asked before the run begins, never
	// while the recheck holds the plan.
	if _, err := b.acquire(ctx, env, in.Requester); err != nil {
		return b.errResp(ctx, env, req.ID, in, nil, err)
	}
	var body hubBody
	var pp *prep
	var prepErr error
	recheck := func(sp *plans.Plan) (string, string, error) {
		if err := json.Unmarshal(sp.Body, &body); err != nil {
			return "", "", err
		}
		pp, prepErr = b.prepare(env, body.Params)
		if prepErr != nil {
			return "", "", fmt.Errorf("%w: %v", plans.ErrStale, prepErr)
		}
		if pp.screen == nil {
			// Under the policy in force it would run without a decision:
			// the decision still covers it.
			pp.screen = b.screen(pp, body.Params.Intent)
		}
		hash, err := ticket.HashOf(planInputsOf(body.Params, pp))
		return policyFP(pp.pol), hash, err
	}
	run, d, err := h.Client.Begin(h.Store, in.Ticket, caller, recheck)
	if err != nil {
		if errors.Is(err, ticket.ErrExpired) {
			return b.renew(ctx, env, h, req.ID, in, caller)
		}
		if d != nil && (errors.Is(err, hubclient.ErrDenied) || errors.Is(err, ticket.ErrAuto)) {
			p := body.Params
			if len(p.Argv) == 0 {
				p = storedParams(h, in.Ticket, caller)
			}
			event := audit.EventDenied
			if errors.Is(err, ticket.ErrAuto) {
				event = audit.EventRun
			}
			b.auditDecision(ctx, env, in.Ticket, p, d, event, err)
		}
		if prepErr != nil {
			return b.errResp(ctx, env, req.ID, body.Params, pp, prepErr)
		}
		return hubRefusal(req.ID, in.Ticket, h.Instance, err)
	}
	b.auditDecision(ctx, env, in.Ticket, body.Params, d, audit.EventApproved, nil)
	p := body.Params
	p.Requester = in.Requester
	resp := b.execute(ctx, env, req.ID, p, pp)
	reason := ""
	if resp.Error != nil {
		reason = resp.Error.Message
	}
	if err := h.Client.Finish(ctx, h.Store, run.ID, caller, resp.Error == nil, reason); err != nil {
		env.Println("ticket " + in.Ticket + ": the hub was not told it was consumed: " + env.Safe(err.Error()))
	}
	return resp
}

// renew answers the run of expired ticket in.Ticket with its renewal and
// audits it with the stored plan's request. A ticket renewed already
// answers its renewal again, audited once.
func (b *Backend) renew(ctx context.Context, env console.Env, h *console.Hub, id int64, in Params, caller plans.Caller) ipc.Response {
	var stored Params
	prev := ""
	if old, err := h.Store.ExpiredByTicket(in.Ticket, caller); err == nil {
		var body hubBody
		if json.Unmarshal(old.Body, &body) == nil {
			stored = body.Params
		}
		if old.RenewedBy != "" {
			if n, err := h.Store.RenewalOf(old.ID); err == nil {
				prev = n.Ticket
			}
		}
	}
	resp := h.RenewResp(ctx, id, in.Ticket, caller)
	base := audit.Base{Event: audit.EventRenew, Decision: "renewed", Approval: "hub", Ticket: in.Ticket,
		Profile: env.Policy().Profile().Name, Intent: stored.Intent}
	var pd struct {
		Ticket string `json:"ticket"`
	}
	if resp.Error != nil {
		base.Decision, base.Error = "refused", resp.Error.Message
	} else if json.Unmarshal(resp.Result, &pd) == nil {
		if prev != "" && pd.Ticket == prev {
			return resp
		}
		base.Reason = "renewed by ticket " + pd.Ticket
	}
	console.StampPeer(ctx, &base)
	stampManaged(env, &base)
	rec := Record{Base: base, Unmasked: false}
	if command := stored.Argv; len(command) > 0 {
		rec.Command = maskedCommand(command)
	}
	env.Audit(rec)
	return resp
}

// OnHub registers the recompute of the hub's renewals on h, before any
// request is served (console.Options.OnHub).
func (b *Backend) OnHub(h *console.Hub) { h.Client.SetRecompute(b.recompute) }

// recompute gives, for a stored hub plan, its policy fingerprint, plan
// hash and plan-hash inputs as they can be known now, from the approved
// policy on disk (it may run on the hub's watch goroutine: it touches
// neither the console's state nor the SSH session).
func (b *Backend) recompute(sp *plans.Plan) (string, string, map[string]string, error) {
	var body hubBody
	if err := json.Unmarshal(sp.Body, &body); err != nil {
		return "", "", nil, err
	}
	pol, err := b.inForce()
	if err != nil {
		return "", "", nil, err
	}
	pp := classify(pol, body.Params)
	inputs := planInputsOf(body.Params, pp)
	hash, err := ticket.HashOf(inputs)
	if err != nil {
		return "", "", nil, err
	}
	digests, err := ticket.InputDigests(inputs)
	if err != nil {
		return "", "", nil, err
	}
	return policyFP(pol), hash, digests, nil
}

// auditDecision records the hub's decision on a ticket; cause is the
// error that stopped an approval from running (an auto rule's approval of
// a never_auto ticket), nil otherwise.
func (b *Backend) auditDecision(ctx context.Context, env console.Env, id string, p Params, d *ticket.Decision, event string, cause error) {
	base := audit.Base{Event: event, Decision: string(d.Decision), Approval: "hub", Reason: d.Reason, Ticket: id,
		Approver: &d.Approver, Facade: d.Facade, HubSig: d.Sig, Profile: env.Policy().Profile().Name, Intent: p.Intent}
	if cause != nil && event == audit.EventRun {
		base.Decision, base.Error = "failed", env.Sanitizer().Error(cause)
	}
	console.StampPeer(ctx, &base)
	stampManaged(env, &base)
	rec := Record{Base: base, DecidedBy: decidedBy(d)}
	if pol, ok := env.Policy().(Policy); ok && len(p.Argv) > 0 {
		pp := classify(pol, p)
		rec.Command, rec.Action, rec.Rule = maskedCommand(p.Argv), pp.action, pp.rule
		rec.AutoRule = pol.Policy.Profile.Auto.RuleID(pp.action)
	}
	env.Audit(rec)
}

// classify is the action and rule of p under pol, without the checks of
// prepare (for the audit and renewals).
func classify(pol Policy, p Params) *prep {
	pp := &prep{pol: pol, argv: p.Argv, unmask: p.Unmask, action: config.ActExec}
	if rules, err := parseRules(pol); err == nil {
		if r, ok := rules.Find(p.Argv); ok {
			pp.action, pp.rule = config.ActRun, r.String()
		}
	}
	return pp
}

// storedParams is the request of the stored plan behind ticket tk (zero
// when it cannot be read).
func storedParams(h *console.Hub, tk string, caller plans.Caller) Params {
	sp, err := h.Store.ByTicket(tk, caller)
	if err != nil {
		return Params{}
	}
	var body hubBody
	if json.Unmarshal(sp.Body, &body) != nil {
		return Params{}
	}
	return body.Params
}

// hubRefusal answers a run whose ticket cannot run.
func hubRefusal(id int64, tk, instance string, err error) ipc.Response {
	switch {
	case errors.Is(err, hubclient.ErrPending):
		return console.PendingResp(id, product.P.Name, console.Pending{Ticket: tk, Instance: instance})
	case errors.Is(err, hubclient.ErrDenied):
		return console.ErrResp(id, ipc.CodeDenied, "denied by the human on the approval hub; do not retry unless asked")
	case errors.Is(err, ticket.ErrExpired):
		return console.ErrResp(id, ipc.CodeTimeout, "the approval expired; do not retry unless asked")
	case errors.Is(err, plans.ErrStale):
		r := refusal.New(CodeStale, "the profile changed since the command was approved: nothing ran")
		info := r.Info("", 0)
		resp := console.ErrResp(id, ipc.CodeRefused, r.Reason)
		resp.Error.Data = &info
		return resp
	case errors.Is(err, ticket.ErrAuto):
		return console.ErrResp(id, ipc.CodeDenied, "the profile's auto rule asks a human for this command; an auto approval cannot run it")
	case errors.Is(err, plans.ErrWrongRequester):
		return console.ErrResp(id, ipc.CodeWrongRequester, "the ticket was asked by another agent")
	}
	return console.ErrResp(id, ipc.CodeNoSuchPlan, "no such pending ticket, or it already ran")
}

// peerUID is the uid of the client behind ctx, -1 when unknown.
func peerUID(ctx context.Context) int {
	if c, ok := console.PeerFrom(ctx); ok {
		return c.UID
	}
	return -1
}
