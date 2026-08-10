# mcp-sentinel

A small, reads-only linter for Model Context Protocol (MCP) server configurations. It
parses a Claude-Desktop-style config and flags common risk patterns. It does not execute,
fetch, connect to, or modify anything.

## What it checks

| rule | severity | what it flags |
|---|---|---|
| `shell-exec` | CRITICAL | server `command` is a shell (`bash`, `sh`, `zsh`, `powershell`, ...): the server can run arbitrary commands |
| `unpinned-remote-pkg` | WARN / CRITICAL | `npx`/`uvx`/`bunx`/`pipx` running a package with no `@version` pin (CRITICAL when combined with `-y`): pulls the latest remote code on every run |
| `broad-fs-root` | WARN | a filesystem root of `/`, `~`, `$HOME`, etc.: broad file access |
| `inline-secret` | WARN | an `env` value that looks like a plaintext API key or token |

## How it works

It parses the config JSON with `serde_json`, then runs the rules above once per server.
Output is a terminal scorecard with a per-server and an overall severity. Exit code is 1
if any CRITICAL is found, otherwise 0, so it can gate a CI step.

## Usage

```
cargo build --release
./target/release/mcp-sentinel [path/to/config.json]
```

With no argument it reads the default Claude Desktop config path
(`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS,
`%APPDATA%\Claude\claude_desktop_config.json` on Windows).

## Sample output

Run against `examples/sample_config.json`:

```
▸ fs-broad
   CRIT [unpinned-remote-pkg]  `npx` runs unpinned package `@modelcontextprotocol/server-filesystem` with -y (no confirmation): pulls latest remote code on every run
   WARN [broad-fs-root]        filesystem root `/` grants broad file access
▸ leaky-env
   WARN [inline-secret]        env `EXAMPLE_TOKEN` looks like a plaintext secret (prefer $VAR indirection)
▸ shell-tool
   CRIT [shell-exec]           command `/bin/bash` is a shell: this server can run arbitrary commands
▸ well-behaved
   PASS [no-known-smells]      no known configuration smell detected (not a proof of safety)

  overall: CRIT   critical=2 warn=2 pass=1
```

Severity labels are color-coded in a real terminal.

## Limitations

- This is a **heuristic linter, not a vulnerability scanner.** A `PASS` means no known
  smell was found, not that a server is safe.
- The checks are pattern-based and deliberately small. They will miss risks they do not
  encode and can false-positive on legitimate setups.
- It analyzes only the static config: not the server's actual behavior, network calls, or
  downstream code.
- Other MCP security tooling exists (for example, Invariant Labs' `mcp-scan`) with
  different and often deeper analysis. This is a minimal, dependency-light static linter,
  not a replacement for those.

## Build and test

```
cargo test
```

## License

MIT. See `LICENSE`.
