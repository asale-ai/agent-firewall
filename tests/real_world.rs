//! Every published attack in [`agent_firewall::corpus`], run against the
//! shipped rule set.
//!
//! This is what makes the README's table a claim rather than an advertisement:
//! each row names the rule that catches it, and if that rule stops catching it
//! this test goes red. The benign half matters just as much — a scanner that
//! flags `cargo test` is a scanner that gets switched off in a week.

use agent_firewall::{corpus::CASES, Config, Decision, Firewall, Mode};

fn fw(mode: Mode) -> Firewall {
    Firewall::new(Config::preset(mode)).expect("built-in rules compile")
}

#[test]
fn every_published_attack_is_caught_by_the_rule_the_readme_names() {
    let fw = fw(Mode::Balanced);
    let mut missed = Vec::new();
    for case in CASES.iter().filter(|c| c.hostile()) {
        let v = fw.inspect(&case.subject());
        let fired: Vec<&str> = v.findings.iter().map(|f| f.rule.as_str()).collect();
        for want in case.expect {
            if !fired.contains(want) {
                missed.push(format!("{}: expected `{want}`, got {fired:?}", case.id));
            }
        }
        if v.decision == Decision::Allow {
            missed.push(format!("{}: findings but no action ({fired:?})", case.id));
        }
    }
    assert!(missed.is_empty(), "\n{}", missed.join("\n"));
}

#[test]
fn ordinary_work_is_left_alone() {
    let fw = fw(Mode::Balanced);
    let mut wrong = Vec::new();
    for case in CASES.iter().filter(|c| !c.hostile()) {
        let v = fw.inspect(&case.subject());
        if v.decision != Decision::Allow {
            wrong.push(format!("{}: {} — {:?}", case.id, v.decision.as_str(), v.findings));
        }
    }
    assert!(wrong.is_empty(), "false positives:\n{}", wrong.join("\n"));
}

/// Audit mode is the one a user is asked to start on, so its promise — reports
/// everything, refuses nothing — is worth a test of its own.
#[test]
fn audit_mode_reports_every_attack_and_refuses_none() {
    let fw = fw(Mode::Audit);
    for case in CASES.iter().filter(|c| c.hostile()) {
        let v = fw.inspect(&case.subject());
        assert!(!v.findings.is_empty(), "{}: audit mode found nothing", case.id);
        assert_eq!(v.decision, Decision::Allow, "{}: audit mode refused something", case.id);
    }
}

/// Every rule the corpus claims must exist in a rule table, or the claim is
/// about a rule that was renamed out from under it.
#[test]
fn the_corpus_only_names_rules_that_exist() {
    let mut known: Vec<&str> = agent_firewall::rules::tables()
        .iter()
        .flat_map(|(_, t)| t.iter().map(|r| r.id))
        .collect();
    // The computed checks — egress and hidden unicode have no rule table.
    known.extend([
        "host-denied", "exfil-host", "ssrf-target", "subdomain-entropy",
        "url-payload-entropy", "url-length", "host-not-allowlisted",
        "zero-width-characters", "unicode-tag-smuggling", "variation-selector-payload",
    ]);
    for case in CASES {
        for want in case.expect {
            assert!(known.contains(want), "{}: no such rule `{want}`", case.id);
        }
    }
}
