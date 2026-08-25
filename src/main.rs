//! The `agent-firewall` command.
//!
//! Exit code is the verdict, so this drops into a hook or a CI step without
//! anything having to parse the output: `0` allow, `1` warn, `2` block.

use agent_firewall::{
    audit::AuditLog, corpus::CASES, rules, Config, Decision, Firewall, Mode, Subject, Verdict,
};
use clap::{Args, Parser, Subcommand};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "agent-firewall",
    version,
    about = "A firewall for AI coding agents: secret exfiltration, prompt injection, dangerous tool calls, egress control",
    long_about = None
)]
struct Cli {
    #[command(flatten)]
    opts: GlobalOpts,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct GlobalOpts {
    /// audit (never blocks) · balanced (blocks critical) · strict (blocks high+, allowlist-only egress)
    #[arg(long, short, global = true, value_parser = parse_mode)]
    mode: Option<Mode>,
    /// Config file (JSON). Command-line flags win over it.
    #[arg(long, short, global = true)]
    config: Option<PathBuf>,
    /// Turn a scanner off. Repeatable: secret, injection, hidden_unicode, tool_policy, egress
    #[arg(long = "off", global = true, value_name = "SCANNER")]
    off: Vec<String>,
    /// Silence one rule by id. Repeatable.
    #[arg(long, global = true, value_name = "RULE")]
    suppress: Vec<String>,
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    /// Append every decision to this tamper-evident log.
    #[arg(long, global = true, value_name = "PATH")]
    audit_log: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Inspect a file, a transcript or stdin
    Scan {
        /// File to read; `-` or omitted reads stdin
        path: Option<String>,
        /// Label the input, instead of inferring it
        #[arg(long, value_name = "KIND")]
        r#as: Option<String>,
        /// Print the input with every secret masked, instead of a report
        #[arg(long)]
        redact: bool,
    },
    /// Check one destination or one tool call
    Check {
        /// Destination the agent wants to reach
        #[arg(long, group = "target")]
        url: Option<String>,
        /// Tool the agent wants to run (use with --args)
        #[arg(long, group = "target")]
        tool: Option<String>,
        /// Arguments for --tool
        #[arg(long, default_value = "")]
        args: String,
    },
    /// List the built-in rules
    Rules {
        /// Only this table: secret, injection, tool_policy
        #[arg(long)]
        scanner: Option<String>,
    },
    /// Run the built-in attack corpus and show what happens to it
    Demo,
    /// Read back a decision log
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// Print the effective configuration
    Config,
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Check the hash chain
    Verify { path: PathBuf },
    /// Print the most recent records
    Tail {
        path: PathBuf,
        #[arg(long, short, default_value_t = 20)]
        n: usize,
    },
}

fn parse_mode(s: &str) -> Result<Mode, String> {
    match s {
        "audit" => Ok(Mode::Audit),
        "balanced" => Ok(Mode::Balanced),
        "strict" => Ok(Mode::Strict),
        other => Err(format!("unknown mode `{other}` (audit, balanced, strict)")),
    }
}

fn build_config(o: &GlobalOpts) -> Result<Config, String> {
    let mut cfg = match &o.config {
        Some(p) => {
            let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            Config::from_json(&text).map_err(|e| e.to_string())?
        }
        None => Config::default(),
    };
    if let Some(m) = o.mode {
        cfg.mode = m;
    }
    for name in &o.off {
        match name.as_str() {
            "secret" => cfg.secret_scan = false,
            "injection" => cfg.injection_scan = false,
            "hidden_unicode" | "hidden-unicode" => cfg.hidden_unicode = false,
            "tool_policy" | "tool-policy" => cfg.tool_policy = false,
            "egress" => cfg.egress = false,
            other => return Err(format!("unknown scanner `{other}`")),
        }
    }
    cfg.suppress.extend(o.suppress.iter().cloned());
    Ok(cfg)
}

fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("agent-firewall: {e}");
            std::process::exit(3);
        }
    }
}

fn run(cli: &Cli) -> Result<i32, String> {
    let o = &cli.opts;
    match &cli.cmd {
        Cmd::Rules { scanner } => {
            list_rules(scanner.as_deref(), o.json);
            Ok(0)
        }
        Cmd::Config => {
            let cfg = build_config(o)?;
            println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
            Ok(0)
        }
        Cmd::Audit { cmd } => audit_cmd(cmd, o.json),
        Cmd::Demo => {
            demo(o)?;
            Ok(0)
        }
        Cmd::Check { url, tool, args } => {
            let fw = firewall(o)?;
            let v = match (url, tool) {
                (Some(u), _) => fw.inspect(&Subject::url(u)),
                (_, Some(t)) => fw.inspect(&Subject::tool_call(t, args)),
                _ => return Err("give --url or --tool".into()),
            };
            report(&v, o, url.as_deref().unwrap_or("tool call"), "check")
        }
        Cmd::Scan { path, r#as, redact } => {
            let fw = firewall(o)?;
            let (label, text) = read_input(path.as_deref())?;
            if *redact {
                let (masked, findings) = fw.redact(&text);
                print!("{masked}");
                eprintln!("agent-firewall: masked {} secret(s)", findings.len());
                return Ok(0);
            }
            let v = scan_text(&fw, &text, r#as.as_deref())?;
            report(&v, o, &label, "scan")
        }
    }
}

fn firewall(o: &GlobalOpts) -> Result<Firewall, String> {
    Firewall::new(build_config(o)?).map_err(|e| e.to_string())
}

fn read_input(path: Option<&str>) -> Result<(String, String), String> {
    match path {
        None | Some("-") => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).map_err(|e| e.to_string())?;
            Ok(("stdin".into(), s))
        }
        Some(p) => std::fs::read_to_string(p)
            .map(|s| (p.to_string(), s))
            .map_err(|e| format!("{p}: {e}")),
    }
}

/// Scan a blob whose provenance we were not told.
///
/// The default is deliberately the paranoid reading: a file handed to this tool
/// is treated as *both* something on its way out (so secrets are looked for) and
/// something that came in (so injection is). Naming `--as` narrows it. A body
/// that parses as an LLM request is walked properly instead, since then we do
/// know which part is which.
fn scan_text(fw: &Firewall, text: &str, as_kind: Option<&str>) -> Result<Verdict, String> {
    if as_kind.is_none() && serde_json::from_str::<serde_json::Value>(text).is_ok_and(|v| {
        v.get("messages").is_some() || v.get("input").is_some() || v.get("system").is_some()
    }) {
        return Ok(fw.inspect_request(text.as_bytes(), None));
    }
    Ok(match as_kind {
        Some("prompt") => fw.inspect(&Subject::prompt(text)),
        Some("completion") => fw.inspect(&Subject::completion(text)),
        Some("tool-output") | Some("tool_output") => fw.inspect(&Subject::tool_output(text)),
        Some(other) => return Err(format!("unknown --as `{other}` (prompt, completion, tool-output)")),
        None => {
            let mut a = fw.inspect(&Subject::prompt(text));
            let b = fw.inspect(&Subject::tool_output(text));
            a.findings.extend(b.findings);
            a.findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
            a.findings.dedup_by(|x, y| x.rule == y.rule && x.start == y.start);
            a.decision = a.decision.max(b.decision);
            a.score = a.score.max(b.score);
            a
        }
    })
}

// ── Output ─────────────────────────────────────────────────────────────────

fn color(on: bool, code: &str, s: &str) -> String {
    if on { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
}

fn report(v: &Verdict, o: &GlobalOpts, subject: &str, kind: &str) -> Result<i32, String> {
    if let Some(p) = &o.audit_log {
        AuditLog::open(p)
            .and_then(|l| l.append("cli", kind, v).map(|_| ()))
            .map_err(|e| e.to_string())?;
    }
    if o.json {
        println!("{}", serde_json::to_string_pretty(v).unwrap());
        return Ok(exit_code(v.decision));
    }
    let tty = std::io::stdout().is_terminal();
    let (code, word) = match v.decision {
        Decision::Allow => ("32", "ALLOW"),
        Decision::Warn => ("33", "WARN"),
        Decision::Block => ("31", "BLOCK"),
    };
    println!("{}  {subject}", color(tty, code, word));
    for f in &v.findings {
        let sev = match f.severity.as_str() {
            "critical" => "31",
            "high" => "33",
            _ => "90",
        };
        println!(
            "  {:<9} {:<22} {}",
            color(tty, sev, f.severity.as_str()),
            f.rule,
            f.detail
        );
        if !f.sample.is_empty() {
            println!("            {}", color(tty, "90", &format!("match: {}", f.sample)));
        }
    }
    if v.findings.is_empty() {
        println!("  {}", color(tty, "90", "no findings"));
    }
    Ok(exit_code(v.decision))
}

fn exit_code(d: Decision) -> i32 {
    match d {
        Decision::Allow => 0,
        Decision::Warn => 1,
        Decision::Block => 2,
    }
}

fn list_rules(only: Option<&str>, json: bool) {
    let tables = rules::tables();
    if json {
        let all: Vec<_> = tables
            .iter()
            .filter(|(name, _)| only.is_none_or(|o| o == *name))
            .flat_map(|(name, table)| {
                table.iter().map(move |r| {
                    serde_json::json!({
                        "scanner": name, "id": r.id, "title": r.title,
                        "severity": r.severity.as_str(), "entropy": r.entropy,
                    })
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&all).unwrap());
        return;
    }
    for (name, table) in tables {
        if only.is_some_and(|o| o != name) {
            continue;
        }
        println!("\n{name}  ({} rules)", table.len());
        for r in table {
            println!("  {:<9} {:<24} {}", r.severity.as_str(), r.id, r.title);
        }
    }
    println!("\negress  (no rule table: destination checks are computed — deny list, {} known drop sites, SSRF, subdomain entropy)", rules::EXFIL_HOSTS.len());
    println!("hidden_unicode  (no rule table: any invisible code point is the finding)");
}

fn audit_cmd(cmd: &AuditCmd, json: bool) -> Result<i32, String> {
    match cmd {
        AuditCmd::Verify { path } => {
            let (n, broken) = AuditLog::verify(path).map_err(|e| e.to_string())?;
            match broken {
                None => {
                    println!("{n} record(s), chain intact");
                    Ok(0)
                }
                Some(i) => {
                    println!("{n} record(s), chain breaks at record {i}");
                    Ok(2)
                }
            }
        }
        AuditCmd::Tail { path, n } => {
            let records = AuditLog::read(path).map_err(|e| e.to_string())?;
            let tail = &records[records.len().saturating_sub(*n)..];
            if json {
                println!("{}", serde_json::to_string_pretty(tail).unwrap());
                return Ok(0);
            }
            for r in tail {
                println!(
                    "{} {:<8} {:<11} {:<6} {}",
                    r.ts,
                    r.agent,
                    r.kind,
                    r.decision.as_str(),
                    r.findings.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>().join(",")
                );
            }
            Ok(0)
        }
    }
}

// ── demo ───────────────────────────────────────────────────────────────────

/// Run the corpus of published attacks and show what happens to each.
///
/// The corpus lives in the library (`agent_firewall::corpus`) so that this, the
/// README's table and `tests/real_world.rs` are three views of one list. If the
/// numbers below are wrong, that test is red.
fn demo(o: &GlobalOpts) -> Result<(), String> {
    let fw = firewall(o)?;
    let tty = std::io::stdout().is_terminal();
    let (mut caught, mut attacks, mut false_positives) = (0, 0, 0);
    let mut out = std::io::stdout().lock();

    writeln!(out, "\nmode: {}\n", fw.config().mode.as_str()).ok();
    for case in CASES {
        let v = fw.inspect(&case.subject());
        let flagged = v.decision != Decision::Allow;
        if case.hostile() {
            attacks += 1;
            if flagged {
                caught += 1;
            }
        } else if flagged {
            false_positives += 1;
        }
        let (code, word) = match v.decision {
            Decision::Allow => ("32", "ALLOW"),
            Decision::Warn => ("33", " WARN"),
            Decision::Block => ("31", "BLOCK"),
        };
        // `!` marks a disagreement between what the corpus says this is and
        // what the firewall did — the only rows worth scanning for.
        let mark = if case.hostile() == flagged { " " } else { "!" };
        writeln!(out, "{mark}{} {}", color(tty, code, word), case.title).ok();
        if !case.source.is_empty() {
            writeln!(out, "        {}", color(tty, "90", case.source)).ok();
        }
        for f in v.findings.iter().take(3) {
            writeln!(out, "        {}", color(tty, "90", &format!("{} · {}", f.rule, f.detail))).ok();
        }
    }
    writeln!(
        out,
        "\n{caught}/{attacks} published attacks flagged · {false_positives} false positive(s) on {} benign samples",
        CASES.len() - attacks
    )
    .ok();
    writeln!(out, "{}", color(tty, "90", "Sources are printed above each row. Point this at your own traffic before believing any of it.")).ok();
    Ok(())
}
