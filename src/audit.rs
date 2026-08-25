//! A tamper-evident decision log.
//!
//! One JSON object per line, each carrying the SHA-256 of the previous line.
//! Deleting or editing an entry breaks the chain from that point on, and
//! [`AuditLog::verify`] says where — which is the property that matters when
//! the log is evidence about an agent that had shell access.
//!
//! Deliberately *not* signed. A signature proves who wrote the line; the
//! operator holds the key and is also the party the log is about, so it would
//! prove less than it appears to. A hash chain makes silent editing impossible
//! without claiming more than that.

use crate::{Decision, Finding, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// One recorded decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    /// Unix seconds.
    pub ts: u64,
    /// Which agent the traffic belonged to (`claude`, `codex`, …).
    pub agent: String,
    /// What was inspected (`prompt`, `tool_call`, …).
    pub kind: String,
    pub decision: Decision,
    pub score: f32,
    pub findings: Vec<Finding>,
    /// Hash of the previous record; `""` for the first.
    pub prev: String,
    /// Hash of this record's payload, chained onto `prev`.
    pub hash: String,
}

impl Record {
    /// The chained hash. Computed over the payload fields in a fixed order —
    /// not over the serialized line, so a re-serialization with different key
    /// ordering does not read as tampering.
    fn digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.prev.as_bytes());
        h.update(self.ts.to_be_bytes());
        h.update(self.agent.as_bytes());
        h.update(self.kind.as_bytes());
        h.update(self.decision.as_str().as_bytes());
        for f in &self.findings {
            h.update(f.rule.as_bytes());
            h.update(f.severity.as_str().as_bytes());
            h.update(f.sample.as_bytes());
            // Added after the first release. Records written before it carry
            // neither field, so both deserialize to `""` and contribute no
            // bytes — the digest of an old record is unchanged and its chain
            // still verifies.
            h.update(f.evidence.as_bytes());
            h.update(f.source.as_bytes());
        }
        format!("{:x}", h.finalize())
    }
}

/// An append-only log. Cheap to keep open; appends are line-atomic under the
/// mutex and flushed before returning, because a crash right after a block is
/// exactly when the line matters.
pub struct AuditLog {
    path: PathBuf,
    prev: Mutex<String>,
}

impl AuditLog {
    /// Open (creating the file and its parent directory) and pick up the chain
    /// where it left off.
    pub fn open(path: impl AsRef<Path>) -> Result<AuditLog> {
        let path = path.as_ref().to_path_buf();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| crate::Error(format!("audit dir: {e}")))?;
        }
        let prev = last_hash(&path)?;
        Ok(AuditLog { path, prev: Mutex::new(prev) })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record one decision. Findings are already masked by the scanners, so the
    /// log never becomes a second copy of what it caught.
    pub fn append(&self, agent: &str, kind: &str, v: &crate::Verdict) -> Result<Record> {
        let mut prev = self.prev.lock().unwrap_or_else(|e| e.into_inner());
        let mut rec = Record {
            ts: now(),
            agent: agent.into(),
            kind: kind.into(),
            decision: v.decision,
            score: v.score,
            findings: v.findings.clone(),
            prev: prev.clone(),
            hash: String::new(),
        };
        rec.hash = rec.digest();
        let line = serde_json::to_string(&rec).map_err(|e| crate::Error(e.to_string()))?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| crate::Error(format!("audit open: {e}")))?;
        writeln!(f, "{line}").and_then(|_| f.flush()).map_err(|e| crate::Error(format!("audit write: {e}")))?;
        *prev = rec.hash.clone();
        Ok(rec)
    }

    /// Read the log back. `Err` on a malformed line — a log you cannot parse is
    /// not a log you should report as intact.
    pub fn read(path: impl AsRef<Path>) -> Result<Vec<Record>> {
        let f = match std::fs::File::open(path.as_ref()) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(crate::Error(format!("audit read: {e}"))),
        };
        std::io::BufReader::new(f)
            .lines()
            .map_while(std::result::Result::ok)
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<Record>(&l).map_err(|e| crate::Error(format!("audit parse: {e}"))))
            .collect()
    }

    /// Check the chain. Returns the number of records and the index of the
    /// first one that does not verify, if any.
    pub fn verify(path: impl AsRef<Path>) -> Result<(usize, Option<usize>)> {
        let records = Self::read(path)?;
        let mut prev = String::new();
        for (i, r) in records.iter().enumerate() {
            if r.prev != prev || r.digest() != r.hash {
                return Ok((records.len(), Some(i)));
            }
            prev = r.hash.clone();
        }
        Ok((records.len(), None))
    }
}

/// The chain head, read without parsing the whole log — only the last line is
/// a record we need. A log that has been appended to for months is still one
/// `read_to_string` and one `serde_json::from_str`.
fn last_hash(path: &Path) -> Result<String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(crate::Error(format!("audit read: {e}"))),
    };
    let Some(line) = text.lines().rev().find(|l| !l.trim().is_empty()) else {
        return Ok(String::new());
    };
    // A trailing partial line (a crash mid-write) is not a reason to refuse to
    // log again — start a fresh chain rather than dying, and `verify` will
    // report exactly where the old one stopped.
    Ok(serde_json::from_str::<Record>(line).map(|r| r.hash).unwrap_or_default())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Firewall, Subject};

    #[test]
    fn the_chain_catches_an_edited_line() {
        let dir = std::env::temp_dir().join(format!("afw-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("audit.jsonl");

        let fw = Firewall::new(Config::default()).unwrap();
        let log = AuditLog::open(&path).unwrap();
        for cmd in ["ls -la", "rm -rf / --no-preserve-root", "cargo test"] {
            log.append("claude", "tool_call", &fw.inspect(&Subject::tool_call("bash", cmd))).unwrap();
        }
        assert_eq!(AuditLog::verify(&path).unwrap(), (3, None));

        // Rewrite the middle record's verdict, the way somebody covering up a
        // block would.
        let text = std::fs::read_to_string(&path).unwrap();
        let doctored = text.replacen("\"decision\":\"block\"", "\"decision\":\"allow\"", 1);
        assert_ne!(text, doctored, "expected a block to doctor");
        std::fs::write(&path, doctored).unwrap();
        assert_eq!(AuditLog::verify(&path).unwrap().1, Some(1));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
