//! mcp-sentinel CLI: read an MCP config, print a heuristic risk scorecard.
//! Usage: mcp-sentinel [path/to/config.json]   (defaults to the Claude Desktop path)
//! Exit code: 1 if any CRITICAL finding, else 0. Reads only; executes nothing.
use mcp_sentinel::{audit, parse, worst, Finding, Severity};
use std::process::exit;

fn default_config_path() -> String {
    // Claude Desktop default locations (best-effort; override with an explicit arg).
    if let Ok(home) = std::env::var("HOME") {
        format!("{home}/Library/Application Support/Claude/claude_desktop_config.json")
    } else if let Ok(appdata) = std::env::var("APPDATA") {
        format!("{appdata}\\Claude\\claude_desktop_config.json")
    } else {
        "claude_desktop_config.json".into()
    }
}

fn color(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "\x1b[97;41m", // white on red
        Severity::Warn => "\x1b[30;43m",     // black on yellow
        Severity::Info => "\x1b[30;46m",     // black on cyan
        Severity::Pass => "\x1b[30;42m",     // black on green
    }
}
const RST: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(default_config_path);
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("mcp-sentinel: cannot read {path}: {e}");
            exit(2);
        }
    };
    let cfg = match parse(&data) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("mcp-sentinel: invalid JSON in {path}: {e}");
            exit(2);
        }
    };

    let findings = audit(&cfg);
    print_scorecard(&path, &cfg.mcp_servers.len(), &findings);

    if findings.iter().any(|f| f.severity == Severity::Critical) {
        exit(1);
    }
}

fn print_scorecard(path: &str, n_servers: &usize, findings: &[Finding]) {
    println!("\n{BOLD}mcp-sentinel{RST}  {DIM}heuristic MCP config linter (not a safety guarantee){RST}");
    println!("{DIM}config: {path}  |  {n_servers} server(s){RST}\n");

    let mut last = String::new();
    for f in findings {
        if f.server != last {
            println!("{BOLD}▸ {}{RST}", f.server);
            last = f.server.clone();
        }
        println!(
            "   {}{}{} {}{DIM}[{}]{RST}  {}",
            color(f.severity),
            f.severity.label(),
            RST,
            "",
            f.rule,
            f.detail
        );
    }

    let (mut crit, mut warn, mut pass) = (0, 0, 0);
    for f in findings {
        match f.severity {
            Severity::Critical => crit += 1,
            Severity::Warn => warn += 1,
            Severity::Pass => pass += 1,
            _ => {}
        }
    }
    let grade = worst(findings);
    println!(
        "\n  overall: {}{}{}   {DIM}critical={crit} warn={warn} pass={pass}{RST}",
        color(grade),
        grade.label(),
        RST
    );
    println!("{DIM}  Note: findings are configuration smells to review, not proof of vulnerability.{RST}");
    println!("{DIM}  PASS means no known smell was found, not that the server is safe.{RST}\n");
}
