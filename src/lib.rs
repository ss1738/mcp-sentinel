//! mcp-sentinel core: parse an MCP server config and flag common risk *smells*.
//!
//! Honest scope: this is a heuristic linter. It flags configuration patterns that are
//! worth a human review (shell execution, unpinned remote packages, broad filesystem
//! roots, plaintext secrets). A PASS means "no known smell was found", NOT "this server
//! is safe". It does not execute anything, fetch anything, or prove absence of risk.

use serde::Deserialize;
use std::collections::BTreeMap;

/// A Claude-Desktop-style MCP config: { "mcpServers": { name: {command, args, env} } }.
#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default, rename = "mcpServers")]
    pub mcp_servers: BTreeMap<String, Server>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Server {
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Pass,
    Info,
    Warn,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Pass => "PASS",
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Critical => "CRIT",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub server: String,
    pub severity: Severity,
    pub rule: &'static str,
    pub detail: String,
}

const SHELLS: &[&str] = &["bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh", "fish"];
const RUNNERS: &[&str] = &["npx", "uvx", "bunx", "pipx"];

fn basename(cmd: &str) -> &str {
    cmd.rsplit(['/', '\\']).next().unwrap_or(cmd)
}

/// A package spec is "unpinned" if it has no `@version` (scope-only `@` doesn't count).
fn is_unpinned(pkg: &str) -> bool {
    let rest = pkg.strip_prefix('@').unwrap_or(pkg);
    !rest.contains('@')
}

fn looks_like_secret(key: &str, val: &str) -> bool {
    if val.is_empty() || val.starts_with('$') {
        return false; // env-var indirection, not an inline secret
    }
    let k = key.to_ascii_uppercase();
    let keyish = ["KEY", "TOKEN", "SECRET", "PASSWORD", "APIKEY"].iter().any(|s| k.contains(s));
    let prefixed = ["sk-", "ghp_", "gho_", "github_pat_", "AKIA", "xoxb-", "xoxp-"]
        .iter()
        .any(|p| val.starts_with(p));
    let high_entropy = val.len() >= 24
        && val.chars().all(|c| c.is_ascii_alphanumeric() || "-_/+=.".contains(c));
    prefixed || (keyish && high_entropy)
}

/// Audit a config, returning one-or-more findings per server (at least a PASS).
pub fn audit(cfg: &Config) -> Vec<Finding> {
    let mut out = Vec::new();
    for (name, s) in &cfg.mcp_servers {
        let mut hit = false;
        let base = basename(&s.command);

        // 1. shell execution -> arbitrary command execution
        if SHELLS.contains(&base) {
            out.push(Finding {
                server: name.clone(),
                severity: Severity::Critical,
                rule: "shell-exec",
                detail: format!("command `{}` is a shell: this server can run arbitrary commands", s.command),
            });
            hit = true;
        }

        // 2. unpinned remote package via a runner (npx/uvx/...) -> supply-chain risk
        if RUNNERS.contains(&base) {
            let auto_yes = s.args.iter().any(|a| a == "-y" || a == "--yes");
            if let Some(pkg) = s.args.iter().find(|a| !a.starts_with('-')) {
                if is_unpinned(pkg) {
                    let sev = if auto_yes { Severity::Critical } else { Severity::Warn };
                    out.push(Finding {
                        server: name.clone(),
                        severity: sev,
                        rule: "unpinned-remote-pkg",
                        detail: format!(
                            "`{}` runs unpinned package `{}`{}: pulls latest remote code on every run",
                            base, pkg, if auto_yes { " with -y (no confirmation)" } else { "" }
                        ),
                    });
                    hit = true;
                }
            }
        }

        // 3. broad filesystem root -> broad file access
        for a in &s.args {
            let broad = matches!(a.as_str(), "/" | "~" | "$HOME" | "C:\\" | "C:\\Users")
                || a.ends_with("/Users")
                || (a == &std::env::var("HOME").unwrap_or_default() && !a.is_empty());
            if broad {
                out.push(Finding {
                    server: name.clone(),
                    severity: Severity::Warn,
                    rule: "broad-fs-root",
                    detail: format!("filesystem root `{}` grants broad file access", a),
                });
                hit = true;
            }
        }

        // 4. plaintext secret in env
        for (k, v) in &s.env {
            if looks_like_secret(k, v) {
                out.push(Finding {
                    server: name.clone(),
                    severity: Severity::Warn,
                    rule: "inline-secret",
                    detail: format!("env `{}` looks like a plaintext secret (prefer $VAR indirection)", k),
                });
                hit = true;
            }
        }

        if !hit {
            out.push(Finding {
                server: name.clone(),
                severity: Severity::Pass,
                rule: "no-known-smells",
                detail: "no known configuration smell detected (not a proof of safety)".into(),
            });
        }
    }
    out
}

pub fn parse(data: &str) -> Result<Config, serde_json::Error> {
    serde_json::from_str(data)
}

/// Worst severity across all findings (for exit codes / overall grade).
pub fn worst(findings: &[Finding]) -> Severity {
    findings.iter().map(|f| f.severity).max().unwrap_or(Severity::Pass)
}
