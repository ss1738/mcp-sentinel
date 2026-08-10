"""Terminal-window 'card' asset for mcp-sentinel. Shows the REAL CLI invocation and
the REAL scorecard from examples/sample_config.json, wrapped in macOS-style window
chrome. Honest: real command (mcp-sentinel <path>, no fake subcommand) and the
'not proof of safety' line stays on the card. matplotlib -> PNG."""
import os
import matplotlib as mpl
mpl.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Circle

PAGE, WIN, BAR, EDGE = "#010409", "#0d1117", "#161b22", "#30363d"
FG, SOFT, DIM = "#e6edf3", "#c9d1d9", "#8b949e"
CRIT, WARN, PASS, GREEN, ACC = "#f85149", "#d29922", "#3fb950", "#3fb950", "#58a6ff"
mpl.rcParams["font.family"] = "monospace"

fig = plt.figure(figsize=(11.5, 7.4), dpi=130)
fig.patch.set_facecolor(PAGE)
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 115); ax.set_ylim(0, 74); ax.axis("off")

# window + title bar
ax.add_patch(FancyBboxPatch((5, 5), 105, 64, boxstyle="round,pad=0,rounding_size=1.6",
                            fc=WIN, ec=EDGE, lw=1.3))
ax.add_patch(FancyBboxPatch((5, 62), 105, 7, boxstyle="round,pad=0,rounding_size=1.6",
                            fc=BAR, ec=EDGE, lw=1.3))
for i, c in enumerate(["#ff5f56", "#ffbd2e", "#27c93f"]):
    ax.add_patch(Circle((9.5 + i * 3.2, 65.5), 1.0, fc=c, ec="none"))
ax.text(57.5, 65.4, "mcp-sentinel — audit scorecard", color=DIM, fontsize=11, ha="center", va="center")

def pill(x, y, text, c):
    ax.add_patch(FancyBboxPatch((x, y - 1.0), 6.0, 2.4, boxstyle="round,pad=0.12,rounding_size=0.5",
                                fc=c, ec="none"))
    ax.text(x + 3.0, y + 0.2, text, color="#0d1117", fontsize=8.5, fontweight="bold", ha="center", va="center")

x0, y = 9, 57.5
def line(segs, dy=3.0):
    global y
    cx = x0
    for text, color, size in segs:
        ax.text(cx, y, text, color=color, fontsize=size, va="center", fontweight="normal")
        cx += len(text) * (size * 0.092)   # monospace advance approx
    y -= dy

line([("$ ", GREEN, 11), ("mcp-sentinel examples/sample_config.json", FG, 11)])
y -= 0.6
line([("heuristic MCP config linter  ", SOFT, 9.5), ("(not a safety guarantee)", DIM, 9.5)])
line([("config: examples/sample_config.json   4 servers", DIM, 9.5)])
y -= 0.6

def finding(server_first, sev_label, sev_color, rule, detail, server=None):
    global y
    if server_first:
        ax.text(x0, y, f"▸ {server_first}", color=FG, fontsize=10.5, va="center", fontweight="bold")
        y -= 2.9
    pill(x0 + 1.5, y, sev_label, sev_color)
    ax.text(x0 + 9, y + 0.2, f"[{rule}]", color=DIM, fontsize=9, va="center")
    ax.text(x0 + 32, y + 0.2, detail, color=SOFT, fontsize=9, va="center")
    y -= 3.0

finding("fs-broad", "CRIT", CRIT, "unpinned-remote-pkg", "npx -y, pulls latest remote code")
finding(None, "WARN", WARN, "broad-fs-root", 'filesystem root "/" -> broad access')
finding("leaky-env", "WARN", WARN, "inline-secret", "plaintext token in env")
finding("shell-tool", "CRIT", CRIT, "shell-exec", "/bin/bash -> arbitrary command exec")
finding("well-behaved", "PASS", PASS, "no-known-smells", "pinned, scoped, local path")

y -= 0.4
ax.text(x0, y, "overall:", color=DIM, fontsize=10, va="center")
pill(x0 + 8, y, "CRIT", CRIT)
ax.text(x0 + 16, y, "critical 2   warn 2   pass 1", color=FG, fontsize=10, va="center")
y -= 3.0
ax.text(x0, y, "PASS = no known smell, not proof of safety", color=DIM, fontsize=8.5, va="center")

ax.text(9, 8, "github.com/ss1738/mcp-sentinel", color=ACC, fontsize=10)
ax.text(106, 8, "reads-only  ·  MIT  ·  Rust", color=DIM, fontsize=8.5, ha="right")

out = os.path.join(os.path.dirname(__file__), "terminal_card.png")
fig.savefig(out, facecolor=PAGE); print("saved", out)
