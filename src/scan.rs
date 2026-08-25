//! The five scanners.
//!
//! Each takes text and returns findings; none of them decides anything. Turning
//! findings into allow/warn/block is [`crate::Config::decide`]'s job, in one
//! place, so a mode change cannot mean five different things.

use crate::normalize;
use crate::rules::{Rule, Validator, EXFIL_HOSTS};
use crate::{Config, Error, Finding, Result, Scanner, Severity};
use regex::Regex;

pub struct Compiled {
    pub rule: &'static Rule,
    pub re: Regex,
}

/// Compile a table, skipping rules the config suppresses — a suppressed rule
/// should not cost anything at match time either.
pub fn compile(table: &'static [Rule], cfg: &Config) -> Result<Vec<Compiled>> {
    table
        .iter()
        .filter(|r| !cfg.suppress.iter().any(|s| s == r.id))
        .map(|rule| {
            Regex::new(rule.regex)
                .map(|re| Compiled { rule, re })
                .map_err(|e| Error(format!("rule `{}`: {e}", rule.id)))
        })
        .collect()
}

/// Mask a match so a finding can be logged, shown and shipped to a UI without
/// becoming a second copy of the secret.
fn mask(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        return "*".repeat(n.max(1));
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s.chars().skip(n - 2).collect();
    format!("{head}{}{tail}", "*".repeat((n - 6).min(24)))
}

fn finding(
    scanner: Scanner,
    rule: &Rule,
    detail: String,
    sample: String,
    evidence: String,
    start: usize,
    end: usize,
) -> Finding {
    Finding {
        scanner,
        rule: rule.id.into(),
        title: rule.title.into(),
        severity: rule.severity,
        detail,
        sample,
        evidence,
        source: String::new(),
        start,
        end,
    }
}

/// At most this much text in a `sample` or an `evidence`. Long enough to read a
/// command or a sentence, short enough that a finding never becomes a copy of
/// the document it was found in.
const MAX_SAMPLE: usize = 160;
const EVIDENCE_PAD: usize = 60;

/// `s`, cut to `max` characters on a character boundary, with an ellipsis when
/// anything was dropped. Newlines become spaces: a finding is one line in a log
/// and one line in a table.
fn clip(s: &str, max: usize) -> String {
    let flat: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let head: String = flat.chars().take(max).collect();
    format!("{head}…")
}

/// A window around `[start, end)` — the match plus a little of what surrounds
/// it, which is what makes a finding locatable in the original document.
fn excerpt(text: &str, start: usize, end: usize) -> String {
    let lo = (0..=start.saturating_sub(EVIDENCE_PAD))
        .rev()
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(0);
    let hi = ((end + EVIDENCE_PAD).min(text.len())..=text.len())
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(text.len());
    let (lo, hi) = if lo <= hi { (lo, hi) } else { (0, text.len()) };
    let body = clip(&text[lo..hi], MAX_SAMPLE + 2 * EVIDENCE_PAD);
    match (lo > 0, hi < text.len()) {
        (true, true) => format!("…{body}…"),
        (true, false) => format!("…{body}"),
        (false, true) => format!("{body}…"),
        (false, false) => body,
    }
}

/// gitleaks' pre-filter: reject the haystack for a rule with a substring scan
/// before paying for its regex. With ~40 secret rules this is the difference
/// between a firewall you can put in front of every request and one you cannot.
fn prefiltered(lower: &str, keywords: &[&str]) -> bool {
    !keywords.is_empty() && !keywords.iter().any(|k| lower.contains(k))
}

// ── 1. Secrets, outbound ───────────────────────────────────────────────────

/// Credentials in text on its way out. Offsets are into `text` itself, which is
/// what makes [`crate::Firewall::redact`] able to mask in place.
///
/// `host` is where the text is headed: a provider key addressed to its own
/// provider is the key being used, and reporting it would train the user to
/// ignore this scanner.
pub fn secrets(rules: &[Compiled], text: &str, host: Option<&str>, cfg: &Config) -> Vec<Finding> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    for c in rules {
        if prefiltered(&lower, c.rule.keywords) {
            continue;
        }
        if let Some(h) = host {
            if c.rule.exempt_hosts.iter().any(|e| normalize::host_matches(h, e)) {
                continue;
            }
        }
        for m in c.re.find_iter(text).take(8) {
            // The interesting part is the capture when the rule has one
            // (`API_KEY = <this>`), the whole match when it does not.
            let caps = c.re.captures_at(text, m.start());
            let secret = caps
                .as_ref()
                .and_then(|c| c.get(1))
                .map(|g| g.as_str())
                .unwrap_or(m.as_str());

            let floor = if c.rule.entropy > 0.0 { c.rule.entropy.max(cfg.entropy_threshold) } else { 0.0 };
            if floor > 0.0 && normalize::entropy(secret) < floor {
                continue;
            }
            let ok = match c.rule.validator {
                Validator::None => true,
                Validator::Luhn => normalize::luhn(m.as_str()),
                Validator::Mod97 => normalize::mod97(m.as_str()),
            };
            if !ok {
                continue;
            }
            // The excerpt is the whole point of a credential finding — a masked
            // key alone does not tell you *which* line to go and fix — so the
            // surrounding text comes along with the secret itself masked out.
            let masked_context = excerpt(&text.replace(secret, &mask(secret)), m.start(), m.end());
            out.push(finding(
                Scanner::Secret,
                c.rule,
                format!("{} in outbound content", c.rule.title),
                mask(secret),
                masked_context,
                m.start(),
                m.end(),
            ));
        }
    }
    out
}

// ── 2. Prompt injection, inbound ───────────────────────────────────────────

/// Instructions hidden in content the agent read. Run over every normalization
/// fold (see [`normalize::folds`]), so one plain-language rule covers the
/// zero-width, homoglyph, leetspeak and base64 spellings of the same payload.
///
/// Offsets are into the *normalized* text, not the original — the folds are
/// what matched, and pretending otherwise would point a caller at the wrong
/// bytes.
pub fn injection(rules: &[Compiled], text: &str) -> Vec<Finding> {
    let folds = normalize::folds(text);
    let mut out: Vec<Finding> = Vec::new();
    for (i, fold) in folds.iter().enumerate() {
        let lower = fold.to_ascii_lowercase();
        for c in rules {
            if out.iter().any(|f| f.rule == c.rule.id) {
                continue; // one finding per rule; the first fold that hit says it
            }
            if prefiltered(&lower, c.rule.keywords) {
                continue;
            }
            let Some(m) = c.re.find(fold) else { continue };
            let how = match i {
                0 => "",
                _ if Some(i) == folds.len().checked_sub(1) && fold != &folds[0] => " (base64-decoded)",
                _ => " (obfuscated)",
            };
            out.push(finding(
                Scanner::Injection,
                c.rule,
                format!("{}{how} in untrusted content", c.rule.title),
                clip(m.as_str(), MAX_SAMPLE),
                excerpt(fold, m.start(), m.end()),
                m.start(),
                m.end(),
            ));
        }
    }
    out
}

// ── 3. Hidden unicode, both directions ─────────────────────────────────────

/// Characters that render as nothing. Split out from the injection scanner
/// because it needs no rules and no folds: the *presence* of a unicode tag
/// character in a tool result is the finding.
pub fn hidden_unicode(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();

    // Sneaky bits: a long run of variation selectors, each standing for one
    // byte. Reported separately from the invisibles below because the finding
    // is the run length, not which code points turned up.
    let run = normalize::variation_selector_run(text);
    if run >= 8 {
        out.push(Finding {
            scanner: Scanner::HiddenUnicode,
            rule: "variation-selector-payload".into(),
            title: "Data encoded in variation selectors".into(),
            severity: Severity::Critical,
            detail: format!("a run of {run} variation selectors — {run} bytes of hidden data, rendered as nothing"),
            sample: format!("{run} consecutive variation selectors"),
            evidence: clip(text, MAX_SAMPLE),
            source: String::new(),
            start: 0,
            end: 0,
        });
    }

    let found = normalize::invisibles(text);
    if found.is_empty() {
        return out;
    }
    // Two findings, not one graded finding. Tag characters and bidi overrides
    // are an encoded payload and have no legitimate use in agent traffic; the
    // rest — zero-width joiners, soft hyphens — also turn up in copy-pasted
    // prose, and are how a literal rule is defeated rather than how a payload
    // is carried. A file with both is doing both, and the report should say so.
    let smuggled: Vec<u32> = found
        .iter()
        .copied()
        .filter(|c| (0xE0000..=0xE007F).contains(c) || (0x202A..=0x202E).contains(c))
        .collect();
    let plain: Vec<u32> = found.iter().copied().filter(|c| !smuggled.contains(c)).collect();

    let describe = |cs: &[u32]| {
        cs.iter().take(6).map(|c| format!("U+{c:04X}")).collect::<Vec<_>>().join(", ")
    };
    if !smuggled.is_empty() {
        out.push(Finding {
            scanner: Scanner::HiddenUnicode,
            rule: "unicode-tag-smuggling".into(),
            title: "Invisible unicode payload".into(),
            severity: Severity::Critical,
            detail: format!("{} tag/bidi code point(s): {}", smuggled.len(), describe(&smuggled)),
            sample: describe(&smuggled),
            // What the text *decodes to* once the tag block is folded back onto
            // ASCII — the hidden sentence, which is the only thing worth
            // reading here. A list of code points is not a payload.
            evidence: clip(&decode_tags(text), MAX_SAMPLE),
            source: String::new(),
            start: 0,
            end: 0,
        });
    }
    if !plain.is_empty() {
        out.push(Finding {
            scanner: Scanner::HiddenUnicode,
            rule: "zero-width-characters".into(),
            title: "Zero-width characters".into(),
            severity: Severity::High,
            detail: format!("{} invisible code point(s): {}", plain.len(), describe(&plain)),
            sample: describe(&plain),
            evidence: clip(&normalize::strip(text), MAX_SAMPLE),
            source: String::new(),
            start: 0,
            end: 0,
        });
    }
    out
}

/// Unicode tag characters folded back onto the ASCII they mirror, with
/// everything else kept. U+E0041 is a tag "A": the block was designed as an
/// invisible copy of ASCII, which is exactly what makes it a smuggling channel
/// and exactly what makes it trivial to read back.
fn decode_tags(text: &str) -> String {
    text.chars()
        .filter_map(|c| match c as u32 {
            0xE0020..=0xE007E => char::from_u32(c as u32 - 0xE0000),
            0xE0001 | 0xE007F => None,
            _ => Some(c),
        })
        .collect()
}

// ── 4. Tool policy, outbound ───────────────────────────────────────────────

/// Commands an agent should not be able to run without a human in the loop.
/// The tool's own name is scanned along with its arguments, because half of
/// these rules are about `bash` being called at all.
pub fn tool_policy(rules: &[Compiled], name: &str, args: &str, cfg: &Config) -> Vec<Finding> {
    let subject = format!("{name} {args}");
    // A completion has no tool name — the model is proposing the command, not
    // calling it yet — so the finding says where it was found instead.
    let whose = if name.is_empty() { "the model's answer".to_string() } else { format!("`{name}`") };
    let lower = subject.to_ascii_lowercase();
    let mut out = Vec::new();
    for c in rules {
        if prefiltered(&lower, c.rule.keywords) {
            continue;
        }
        if let Some(m) = c.re.find(&subject) {
            let mut f = finding(
                Scanner::ToolPolicy,
                c.rule,
                format!("{} in {whose}", c.rule.title),
                clip(m.as_str(), MAX_SAMPLE),
                excerpt(&subject, m.start(), m.end()),
                m.start(),
                m.end(),
            );
            // Sending a token to the service that issued it is the token being
            // used. Only the destination can tell that apart from theft, so
            // this one rule is graded on where the command is pointed.
            if c.rule.id == "env-secret-egress" {
                let urls = urls_in(&subject);
                let allowed = !urls.is_empty()
                    && urls.iter().all(|u| {
                        normalize::host_of(u).is_some_and(|h| {
                            cfg.allow_list().iter().any(|a| normalize::host_matches(&h, a))
                        })
                    });
                if allowed {
                    f.severity = Severity::Low;
                    f.detail = format!("{} in {whose}, to an allowlisted destination", c.rule.title);
                }
            }
            out.push(f);
        }
    }
    out
}

// ── 5. Egress, outbound ────────────────────────────────────────────────────

fn egress_finding(rule: &'static str, title: &str, sev: Severity, detail: String, url: &str) -> Finding {
    Finding {
        scanner: Scanner::Egress,
        rule: rule.into(),
        title: title.into(),
        severity: sev,
        detail,
        // The destination, in full. "A request was refused" is not actionable;
        // "a request to *this* was refused" is the entire finding.
        sample: clip(url, MAX_SAMPLE),
        evidence: String::new(),
        source: String::new(),
        start: 0,
        end: 0,
    }
}

/// Where the agent is trying to reach.
pub fn egress(url: &str, cfg: &Config) -> Vec<Finding> {
    let Some(host) = normalize::host_of(url) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    if cfg.deny_hosts.iter().any(|d| normalize::host_matches(&host, d)) {
        out.push(egress_finding("host-denied", "Denied destination", Severity::Critical,
            format!("`{host}` is on the deny list"), url));
    }
    if EXFIL_HOSTS.iter().any(|d| normalize::host_matches(&host, d)) {
        out.push(egress_finding("exfil-host", "Anonymous drop site", Severity::Critical,
            format!("`{host}` accepts anonymous uploads — a one-hop exfiltration channel"), url));
    }
    if normalize::is_ssrf_target(&host) {
        out.push(egress_finding("ssrf-target", "Internal / metadata address", Severity::Critical,
            format!("`{host}` is a loopback, private or link-local address"), url));
    }

    // The two entropy checks below are the ones that mistake a signed CDN URL
    // for an exfiltration, so a destination the operator has already vouched
    // for is exempt from both. Everything above this line is not: an allowlist
    // entry is permission to be talked to, not permission to be a drop site.
    let allowlisted = cfg.allow_list().iter().any(|a| normalize::host_matches(&host, a));

    // DNS tunnelling: the payload rides in a subdomain label, so the request
    // looks ordinary to everything that only checks the registered domain.
    let (ent, len) = normalize::max_label_entropy(&host);
    if !allowlisted && len >= 20 && ent >= cfg.subdomain_entropy_threshold {
        out.push(egress_finding("subdomain-entropy", "High-entropy hostname", Severity::High,
            format!("`{host}` carries a {len}-character random label ({ent:.1} bits/char) — the shape of DNS tunnelling"), url));
    }

    // A long high-entropy path or query is where an encoded secret rides out
    // when the secret rules did not recognise its shape. Path *and* query,
    // because the exfiltration that reaches a rendered markdown image puts its
    // payload in the path, where a query-only check never looks.
    let tail = url.split_once("://").map_or(url, |(_, r)| r);
    let tail = tail.find(['/', '?']).map_or("", |i| &tail[i..]);
    let e = normalize::entropy(tail);
    if !allowlisted && tail.len() >= 48 && e >= 4.5 {
        out.push(egress_finding("url-payload-entropy", "Encoded payload in a URL", Severity::High,
            format!("{} bytes of path/query at {e:.1} bits/char — a payload rather than an address", tail.len()), url));
    }
    if url.len() > 2048 {
        out.push(egress_finding("url-length", "Oversized URL", Severity::Medium,
            format!("{} bytes of URL", url.len()), url));
    }

    // Strict mode is allowlist-only. In every other mode an unknown destination
    // is inspected, not refused — that is the whole difference between the two.
    if cfg.mode == crate::Mode::Strict && !allowlisted && !out.iter().any(|f| f.rule == "host-denied") {
        out.push(egress_finding("host-not-allowlisted", "Destination not on the allowlist", Severity::Critical,
            format!("strict mode permits only the allowlist; `{host}` is not on it"), url));
    }
    out
}

/// The URLs a rendered answer reaches, paired with whether reaching them takes
/// a click.
///
/// This is the exfiltration channel behind EchoLeak, the Slack AI leak and
/// every "the assistant rendered an image" report since: markdown image syntax
/// makes the client fetch the URL the moment the answer is displayed, so an
/// attacker who can get one sentence into the context can get a GET request out
/// of it, with whatever the model was willing to put in the path. Reference
/// style (`![x][ref]` with `[ref]: https://…` further down) is covered too —
/// it was the form that got past Microsoft's link redaction.
pub fn markdown_sinks(text: &str) -> Vec<(bool, &str)> {
    static INLINE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static REFDEF: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let inline = INLINE.get_or_init(|| {
        Regex::new(r"(!?)\[[^\]]{0,300}\]\(\s*<?(https?://[^)\s>]+)").expect("literal")
    });
    let refdef = REFDEF.get_or_init(|| {
        Regex::new(r"(?m)^[ 	]{0,3}\[[^\]]{1,120}\]:[ 	]*<?(https?://[^\s>]+)").expect("literal")
    });

    let mut out: Vec<(bool, &str)> = inline
        .captures_iter(text)
        .take(32)
        .filter_map(|c| Some((c.get(1)?.as_str() == "!", c.get(2)?.as_str())))
        .collect();
    // A reference definition does not say whether it is used as an image or a
    // link. Treated as a link — the weaker claim — so the finding rests on what
    // the URL carries rather than on a guess about how it is rendered.
    out.extend(refdef.captures_iter(text).take(32).filter_map(|c| Some((false, c.get(1)?.as_str()))));
    out
}

/// Every URL in a blob of text — how a `curl` buried in a shell command reaches
/// the egress scanner.
pub fn urls_in(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("http") {
        let tail = &rest[i..];
        if tail.starts_with("http://") || tail.starts_with("https://") {
            let end = tail
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>' | ')' | ']' | '|' | ';'))
                .unwrap_or(tail.len());
            out.push(&tail[..end]);
            rest = &tail[end..];
        } else {
            rest = &tail[4..];
        }
        if out.len() >= 16 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masking_never_reveals_the_middle() {
        assert_eq!(mask("short"), "*****");
        let m = mask("ghp_abcdefghijklmnopqrstuvwxyz012345");
        assert!(m.starts_with("ghp_") && m.ends_with("45") && !m.contains("defg"), "{m}");
    }

    #[test]
    fn urls_are_pulled_out_of_a_shell_command() {
        let got = urls_in("curl -s https://a.example/x?y=1 | tee f && wget 'https://b.example/z'");
        assert_eq!(got, vec!["https://a.example/x?y=1", "https://b.example/z"]);
    }

    #[test]
    fn loopback_written_four_ways_is_still_loopback() {
        let cfg = Config::default();
        for u in ["http://127.0.0.1/", "http://localhost:8080/", "http://169.254.169.254/latest/meta-data/", "http://2130706433/"] {
            assert!(egress(u, &cfg).iter().any(|f| f.rule == "ssrf-target"), "missed {u}");
        }
    }
}
