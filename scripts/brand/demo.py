#!/usr/bin/env python3
"""Generate docs/assets/demo.svg: lockssh's value in one looping image.

Claude Code (left, the agent's account) asks lockssh to check nginx on a server. The allow-listed
commands (systemctl status, journalctl) run at once and come back with the client's address
masked; `lox run` (right, the human's terminal) only logs them. The fix, `systemctl restart
nginx`, matches no allow rule: it becomes a ticket, the human types y, and the agent runs it once.
The SSH key never leaves the lockssh console. Pure SVG + CSS keyframes, so it plays on GitHub and
in any browser. Every animation shares one clock of LOOP seconds.

The ticket lines follow the real screen of lockssh (internal/sshconsole/handlers.go, screen)
and lox run's ticket frame; keep them in step when those change.

    python3 scripts/brand/demo.py > docs/assets/demo.svg
    python3 scripts/brand/demo.py --at 7.5 > /tmp/frame.svg   # one still frame, to review
"""

import sys

LOOP = 16.0
AT = float(sys.argv[sys.argv.index("--at") + 1]) if "--at" in sys.argv else None
C = dict(bg="#0b1120", pane="#020617", bar="#0f172a", border="#253047", text="#e2e8f0",
         dim="#64748b", sub="#94a3b8", sky="#38bdf8", teal="#5eead4", violet="#a78bfa",
         red="#f87171", green="#4ade80", yellow="#facc15")
FONT = "'JetBrains Mono','SF Mono',Menlo,Consolas,'DejaVu Sans Mono',monospace"
SANS = "Inter,-apple-system,'Segoe UI',system-ui,Helvetica,Arial,'DejaVu Sans',sans-serif"

css, body = [], []
n = 0


def p(t):
    return f"{t / LOOP * 100:.2f}%"


def interp(frames, t):
    """The declarations of keyframes [(time_s, {prop: value}), ...] at time t (linear)."""
    for (t0, d0), (t1, d1) in zip(frames, frames[1:]):
        if t0 <= t <= t1:
            f = 0 if t1 == t0 else (t - t0) / (t1 - t0)
            return {k: d0[k] + (d1[k] - d0[k]) * f for k in d0}
    return frames[-1][1]


def decl(d):
    out = []
    if "x" in d:
        out.append(f"transform:translate({d['x']:.1f}px,{d['y']:.1f}px)")
    out.append(f"opacity:{d['o']:.2f}")
    return ";".join(out)


def anim(frames):
    """Register keyframes [(time_s, {o, x?, y?}), ...] and return a class name."""
    global n
    n += 1
    name = f"k{n}"
    if AT is not None:
        css.append(f".{name}{{{decl(interp(frames, AT))}}}")
        return name
    rules = " ".join(f"{p(t)}{{{decl(d)}}}" for t, d in frames)
    css.append(f"@keyframes {name}{{{rules}}}")
    css.append(f".{name}{{animation:{name} {LOOP}s linear infinite}}")
    return name


END = LOOP - 0.6


def show(t_in, t_out=END, fade=0.2):
    """Opacity window: hidden, visible from t_in to t_out."""
    return anim([(0, dict(o=0)), (t_in, dict(o=0)), (t_in + fade, dict(o=1)),
                 (t_out, dict(o=1)), (t_out + fade, dict(o=0)), (LOOP, dict(o=0))])


def move(t0, t1, x0, y0, x1, y1):
    return anim([(0, dict(o=0, x=x0, y=y0)), (t0, dict(o=0, x=x0, y=y0)),
                 (t0 + 0.05, dict(o=1, x=x0, y=y0)), (t1, dict(o=1, x=x1, y=y1)),
                 (t1 + 0.15, dict(o=0, x=x1, y=y1)), (LOOP, dict(o=0, x=x1, y=y1))])


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x, y, s, cls="", size=12.5, col=C["text"], weight=400, family=FONT, anchor="start"):
    c = f' class="{cls}"' if cls else ""
    return (f'<text x="{x}" y="{y}"{c} font-family="{family}" font-size="{size}" '
            f'fill="{col}" font-weight="{weight}" text-anchor="{anchor}" xml:space="preserve">{esc(s)}</text>')


def spans(x, y, parts, cls="", size=12.5):
    """One line of coloured runs [(text, colour), ...]."""
    c = f' class="{cls}"' if cls else ""
    runs = "".join(f'<tspan fill="{col}">{esc(s)}</tspan>' for s, col in parts)
    return (f'<text x="{x}" y="{y}"{c} font-family="{FONT}" font-size="{size}" '
            f'xml:space="preserve">{runs}</text>')


def pane(x, y, w, h, title, account):
    body.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{C["pane"]}" '
                f'stroke="{C["border"]}" stroke-width="1.5"/>')
    body.append(f'<path d="M{x} {y + 12} a12 12 0 0 1 12 -12 h{w - 24} a12 12 0 0 1 12 12 v18 h-{w} z" '
                f'fill="{C["bar"]}"/>')
    for i, col in enumerate(("#f87171", "#facc15", "#4ade80")):
        body.append(f'<circle cx="{x + 18 + i * 16}" cy="{y + 15}" r="5" fill="{col}" fill-opacity=".7"/>')
    body.append(text(x + 70, y + 20, title, size=12, col=C["sub"], family=SANS, weight=600))
    body.append(text(x + w - 14, y + 20, account, size=12, col=C["dim"], family=SANS, anchor="end"))


W, H = 1200, 660
body.append(f'<rect width="{W}" height="{H}" rx="24" fill="{C["bg"]}"/>')

# --- Agent pane (left) --------------------------------------------------------------------
AX, AY, AW, AH = 24, 32, 540, 536
pane(AX, AY, AW, AH, "✻ Claude Code", "account alice")
LH = 19
ax, ay = AX + 16, AY + 58
M = C["violet"]  # a masked value
G, S, T, D = C["green"], C["sub"], C["text"], C["dim"]
T_TICKET, T_YES, T_RUN = 5.3, 8.2, 8.9
agent = [
    (0.3, [("> ", D), ("is nginx healthy on web1? fix it if it isn't", T)]),
    (1.0, [("● ", G), ("lockssh_run", T), ('(["systemctl","status","nginx"])', S)]),
    (1.7, [("  └ ", D), ("exit 3 · Active: failed (Result: exit-code)", S)]),
    (2.2, [("● ", G), ("lockssh_run", T), ('(["journalctl","-u","nginx",', S)]),
    (2.2, [("               ", S), ('"-n","2","--no-pager"])', S)]),
    (2.9, [("  └ ", D), ("[alert] worker process 812 exited on signal 9", S)]),
    (2.9, [("    ", D), ("[error] upstream timed out, client: ", S), ("⟦ip:9K2QF7XM3RDA⟧", M)]),
    (3.7, [("● ", T), ("Its workers were killed. Restarting nginx needs", T)]),
    (3.7, [("  ", T), ("your approval.", T)]),
    (4.4, [("● ", G), ("lockssh_run", T), ('(["systemctl","restart","nginx"])', S)]),
    (T_TICKET, [("  └ ", D), ("pending · ticket 7c1e9a waits in lox run", C["yellow"])]),
    (T_RUN, [("● ", G), ("lockssh_run", T), ('(["systemctl","restart","nginx"],', S)]),
    (T_RUN, [("               ", S), ('ticket: "7c1e9a")', S)]),
    (T_RUN + 0.7, [("  └ ", D), ("exit 0 · 0.8s", S)]),
    (T_RUN + 1.2, [("● ", G), ("lockssh_run", T), ('(["systemctl","is-active","nginx"])', S)]),
    (T_RUN + 1.8, [("  └ ", D), ("active", G)]),
    (T_RUN + 2.4, [("● ", T), ("nginx is back up on web1.", T)]),
]
for i, (t, parts) in enumerate(agent):
    body.append(spans(ax, ay + i * LH, parts, cls=show(t)))

# --- lox run pane (right) -----------------------------------------------------------------
CX, CY, CW, CH = 600, 32, 576, 536
pane(CX, CY, CW, CH, "lox run · lockhub", "you")
CS = 11.5  # one character is 0.602 em wide
CHW = CS * 0.602
cx, cy = CX + 14, CY + 56
LH2 = 18
body.append(spans(cx, cy, [(" AUTO ", C["pane"]), ("  ", T), ("● hub up", G), (" · 1 lock", S)], size=CS))
body.append(f'<rect x="{cx - 2}" y="{cy - 12}" width="{CHW * 6 + 4:.1f}" height="16" rx="3" fill="{C["teal"]}"/>')
body.append(spans(cx, cy, [(" AUTO ", C["pane"])], size=CS))
log = [
    (1.4, [("14:02:01 ", D), ("dev-1 ", S), ("◆ web ", C["sky"]), ("run  systemctl status nginx", T),
           ("  ✓ auto", G)]),
    (2.6, [("14:02:03 ", D), ("dev-1 ", S), ("◆ web ", C["sky"]), ("run  journalctl -u nginx -n 2 …", T),
           ("  ✓ auto", G)]),
]
for i, (t, parts) in enumerate(log):
    body.append(spans(cx, cy + (i + 2) * LH2, parts, cls=show(t), size=CS))
body.append(text(cx, cy + 4.6 * LH2, "allow-listed commands run at once; only the log shows them",
                 cls=show(1.4, T_TICKET - 0.2), size=CS, col=D))

R, V = C["red"], C["violet"]
BOXW = 76  # the ticket frame, in characters
ticket = [
    [("┌ ", R), ("◆ QUESTION ", R), ("exec", T), (" on web/web1 ", S), ("─" * (BOXW - 31) + "┐", R)],
    [("│ ", R), ("dev-1", T), (" asks · ◆ lockssh · expires in 9m", D)],
    [("│ ", R), ("lockssh-ro@web1.example.com:22 · exec", T)],
    [("│ ", R), ("agent: restart nginx, its workers were killed", D)],
    [("│", R)],
    [("│ ", R), ("RUN systemctl restart nginx", C["yellow"])],
    [("│", R)],
    [("│ ", R), ("no allow rule matches: exec (the profile allows asking", T)],
    [("│ ", R), ("for any command)", T)],
    [("│ ", R), ("output: masked (card, email, iban, ip, phone, secret)", T)],
    [("│ ", R), ("limits: 30s · 65536 bytes per stream", T)],
    [("│ ", R), ("! a command outside the allow list: it may change the host", R)],
    [("└", R), ("─" * (BOXW - 2) + "┘", R)],
]
for row in ticket[1:-1]:  # the right border
    row.append((" " * (BOXW - 1 - sum(len(s) for s, _ in row)) + "│", R))
trow = 6
g = [f'<g class="{show(T_TICKET + 0.2, T_YES + 0.5)}">']
for i, parts in enumerate(ticket):
    g.append(spans(cx, cy + (trow + i) * LH2, parts, size=CS))
g.append("</g>")
body.append("".join(g))
arow = trow + len(ticket) + 1
body.append(spans(cx, cy + arow * LH2, [("approve? ", T), ("y", G), ("/n ", T)], cls=show(T_TICKET + 0.4, T_YES + 0.5), size=CS))
# The human types y.
body.append(text(cx + CHW * 14, cy + arow * LH2, "y", cls=show(T_YES, T_YES + 0.5, fade=0.05), size=CS,
                 col=G, weight=700))
blink = anim([(0, dict(o=0)), (T_TICKET + 0.5, dict(o=0)), (T_TICKET + 0.51, dict(o=1)),
              (6.3, dict(o=1)), (6.31, dict(o=0)), (6.8, dict(o=0)), (6.81, dict(o=1)),
              (7.4, dict(o=1)), (7.41, dict(o=0)), (7.7, dict(o=0)), (7.71, dict(o=1)),
              (T_YES - 0.01, dict(o=1)), (T_YES, dict(o=0)), (LOOP, dict(o=0))])
body.append(f'<rect x="{cx + CHW * 14:.1f}" y="{cy + arow * LH2 - 10}" width="{CHW:.1f}" height="13" '
            f'fill="{T}" class="{blink}"/>')
body.append(f'<g class="{show(T_TICKET + 0.6, T_YES, fade=0.1)}"><rect x="{CX + CW - 196}" '
            f'y="{cy + arow * LH2 - 15}" width="180" height="22" rx="6" fill="{V}"/>'
            + text(CX + CW - 106, cy + arow * LH2, "only you can answer", size=12, col=C["pane"],
                   weight=700, family=SANS, anchor="middle") + "</g>")
# After the answer: the decision in the log.
done = [
    (T_YES + 0.75, [("14:02:19 ", D), ("dev-1 ", S), ("◆ web ", C["sky"]), ("exec systemctl restart nginx", T),
                   ("  ✓ you", G)]),
    (T_YES + 0.95, [("         ", D), ("signed by the hub · runs once, for this agent, this argv", D)]),
    (T_RUN + 1.3, [("14:02:21 ", D), ("dev-1 ", S), ("◆ web ", C["sky"]), ("run  systemctl is-active nginx", T),
                   ("  ✓ auto", G)]),
]
for i, (t, parts) in enumerate(done):
    body.append(spans(cx, cy + (i + 4) * LH2, parts, cls=show(t), size=CS))

# The server, behind the lockssh console only.
BX, BY, BW = CX + 16, CY + CH - 78, CW - 32
body.append(f'<rect x="{BX}" y="{BY}" width="{BW}" height="62" rx="10" fill="{C["bar"]}" '
            f'stroke="{C["sky"]}" stroke-width="1.5" stroke-dasharray="6 5"/>')
body.append(text(BX + 16, BY + 26, "web1.example.com", size=14, col=C["sky"], weight=700, family=SANS))
body.append(text(BX + 16, BY + 46, "SSH: no PTY · no stdin · every argument quoted", size=12,
                 col=C["sub"], family=SANS))
body.append(text(BX + BW - 16, BY + 26, "the key stays in the", size=12, col=C["sub"], family=SANS,
                 anchor="end"))
body.append(text(BX + BW - 16, BY + 46, "lockssh console's container", size=12, col=C["sub"],
                 family=SANS, anchor="end"))

# The socket between the agent and the console.
SY = AY + AH / 2
body.append(f'<rect x="{AX + AW + 4}" y="{SY - 44}" width="{CX - AX - AW - 8}" height="88" rx="4" '
            f'fill="{C["teal"]}" fill-opacity=".85"/>')
body.append(text((AX + AW + CX) / 2, SY - 54, "socket", size=11, col=C["teal"], weight=700, family=SANS,
                 anchor="middle"))
pkt = 'r="6" cx="0" cy="0"'
SRV = BY + 31
for t0, col in ((1.05, C["teal"]), (2.25, C["teal"]), (T_RUN + 0.05, C["teal"]), (T_RUN + 1.25, C["teal"])):
    body.append(f'<circle {pkt} fill="{col}" class="{move(t0, t0 + 0.35, 520, SY, 640, SRV)}"/>')
    body.append(f'<circle {pkt} fill="{C["sky"]}" class="{move(t0 + 0.4, t0 + 0.65, 640, SRV, 520, SY + 20)}"/>')
body.append(f'<circle {pkt} fill="{C["yellow"]}" class="{move(4.45, 4.9, 520, SY, 760, 160)}"/>')

# Captions.
caps = [(0.0, 4.4, "Allowed commands run at once. Your agent never holds the key."),
        (4.4, T_YES + 0.6, "Anything else waits for you, on a ticket it can't sign."),
        (T_YES + 0.6, END, "It runs once. The output comes back masked.")]
for t0, t1, s in caps:
    body.append(text(W / 2, 616, s, cls=show(t0 + 0.05, t1 - 0.2), size=26, weight=650,
                     family=SANS, anchor="middle"))

label = ("lockssh: Claude Code checks nginx on a server through lockssh. The allow-listed status and "
         "log commands run at once, with the client's address masked; the restart matches no allow "
         "rule, so lox run asks the human, who types y, and the agent runs it once. The SSH key "
         "stays in the lockssh console.")
print(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
      f'role="img" aria-label="{label}">')
print("<title>lockssh: your AI runs the command, you hold the key</title>")
reduced = "" if AT is not None else (
    "\n@media (prefers-reduced-motion: reduce){*{animation-delay:-14s!important;"
    "animation-play-state:paused!important}}")
print("<style>" + "\n".join(css) + reduced + "</style>")
print("\n".join(body))
print("</svg>")
