"""Render a dark-mode promo card for mcp-sentinel from its REAL scorecard output.
Honest: shows the actual findings on examples/sample_config.json, keeps the
'heuristic linter / PASS != safe' label on the card. matplotlib -> PNG."""
import matplotlib as mpl
mpl.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

BG, PANEL, EDGE = "#0d1117", "#161b22", "#30363d"
FG, DIM, LN = "#c9d1d9", "#8b949e", "#484f58"
CRIT, WARN, PASS, ACC = "#f85149", "#d29922", "#3fb950", "#58a6ff"
mpl.rcParams["font.family"] = "monospace"

fig = plt.figure(figsize=(12, 6.75), dpi=120)
fig.patch.set_facecolor(BG)
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 120); ax.set_ylim(0, 67.5); ax.axis("off")

# header
ax.text(4, 62.5, "mcp-sentinel", color=FG, fontsize=24, fontweight="bold")
ax.text(4.4, 58.6, "heuristic linter for Model Context Protocol server configs", color=DIM, fontsize=11)

def panel(x, y, w, h):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.0",
                                fc=PANEL, ec=EDGE, lw=1.2))

# ---- left: config ----
lx, ly, lw, lh = 4, 8, 52, 46
panel(lx, ly, lw, lh)
ax.text(lx + 2, ly + lh - 2.6, "claude_desktop_config.json", color=DIM, fontsize=9.5)
cfg = [
    '{', '  "mcpServers": {',
    '    "shell-tool":   { "command": "/bin/bash",',
    '                      "args": ["-c", "..."] },',
    '    "fs-broad":     { "command": "npx", "args":',
    '                      ["-y", "server-filesystem", "/"] },',
    '    "leaky-env":    { "env": { "EXAMPLE_TOKEN":',
    '                      "PLACEHOLDER-..." } },',
    '    "well-behaved": { "command": "npx", "args":',
    '                      ["@scope/notes@2.1.0"] }',
    '  }', '}',
]
for i, line in enumerate(cfg):
    y = ly + lh - 6.2 - i * 3.05
    ax.text(lx + 2, y, f"{i+1:>2}", color=LN, fontsize=8)
    ax.text(lx + 5.2, y, line, color=FG, fontsize=8)

# ---- right: scorecard ----
rx, ry, rw, rh = 60, 8, 56, 46
panel(rx, ry, rw, rh)
ax.text(rx + 2, ry + rh - 2.6, "security scorecard", color=DIM, fontsize=9.5)

def badge(x, y, text, c):
    ax.add_patch(FancyBboxPatch((x, y - 0.9), 6.2, 2.4, boxstyle="round,pad=0.15,rounding_size=0.5",
                                fc=c, ec="none"))
    ax.text(x + 3.1, y + 0.3, text, color="#0d1117", fontsize=8.5, fontweight="bold", ha="center", va="center")

rows = [
    (CRIT, "CRIT", "shell-tool", "shell-exec", "command is a shell"),
    (CRIT, "CRIT", "fs-broad", "unpinned-remote-pkg", "npx -y, latest remote code"),
    (WARN, "WARN", "fs-broad", "broad-fs-root", 'root "/" grants full access'),
    (WARN, "WARN", "leaky-env", "inline-secret", "plaintext token in env"),
    (PASS, "PASS", "well-behaved", "no-known-smells", "pinned, scoped, local path"),
]
for i, (c, lab, srv, rule, det) in enumerate(rows):
    y = ry + rh - 8 - i * 7.2
    badge(rx + 2.5, y, lab, c)
    ax.text(rx + 10, y + 0.9, srv, color=FG, fontsize=10, fontweight="bold", va="center")
    ax.text(rx + 10, y - 1.4, f"[{rule}]  {det}", color=DIM, fontsize=8.2, va="center")

# overall strip
ax.add_patch(FancyBboxPatch((rx + 2.5, ry + 1.8), rw - 5, 3.2,
             boxstyle="round,pad=0.2,rounding_size=0.6", fc="#21262d", ec="none"))
ax.text(rx + 4, ry + 3.4, "OVERALL", color=DIM, fontsize=9, va="center")
badge(rx + 15, ry + 3.4, "CRIT", CRIT)
ax.text(rx + rw - 3, ry + 3.4, "critical 2   warn 2   pass 1", color=FG, fontsize=9, va="center", ha="right")

# footer
ax.text(4, 4.2, "github.com/ss1738/mcp-sentinel", color=ACC, fontsize=11)
ax.text(116, 4.2, "PASS = no known smell, not proof of safety", color=DIM, fontsize=8.5, ha="right")
ax.text(4, 1.5, "reads-only  ·  serde_json  ·  MIT  ·  Rust", color=LN, fontsize=8.5)

out = __import__("os").path.join(__import__("os").path.dirname(__file__), "scorecard.png")
fig.savefig(out, facecolor=BG); print("saved", out)
