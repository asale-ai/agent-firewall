//! Text normalization, entropy and checksums.
//!
//! An injection pattern written in plain English matches plain English and
//! nothing else. Attackers know that, so the payload arrives wrapped: zero-width
//! joiners between the letters, Cyrillic homoglyphs standing in for Latin ones,
//! leetspeak, or the whole thing base64'd with a "decode this" nearby.
//!
//! Rather than write four spellings of every rule, the text is folded through
//! the passes below and the *same* rule set runs over each fold. This is the
//! trick that makes a small rule table hold up; it is also why the rules never
//! need to be case-sensitive or spacing-sensitive.

use std::collections::BTreeSet;

/// Characters that carry no glyph but do split a word in two, defeating any
/// literal match. Tag characters (U+E0000..) are the nastiest: they render as
/// nothing at all yet survive a copy-paste into a prompt.
pub fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}'                    // soft hyphen
        | '\u{200B}'..='\u{200F}'     // zero-width space/joiners, LRM/RLM
        | '\u{202A}'..='\u{202E}'     // bidi embedding/override
        | '\u{2060}'..='\u{2064}'     // word joiner, invisible operators
        | '\u{2066}'..='\u{2069}'     // bidi isolates
        | '\u{FEFF}'                  // BOM / zero-width no-break space
        | '\u{E0000}'..='\u{E007F}'   // unicode tag characters
        | '\u{FFF9}'..='\u{FFFB}'     // interlinear annotation
    )
}

/// Latin lookalikes from the Cyrillic and Greek blocks, plus the fullwidth
/// forms. Not exhaustive by design — these are the substitutions that survive
/// being read by a human, which is the whole point of a homoglyph attack.
fn homoglyph(c: char) -> Option<char> {
    Some(match c {
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'х' => 'x',
        'у' => 'y', 'і' => 'i', 'ѕ' => 's', 'ј' => 'j', 'һ' => 'h', 'ԁ' => 'd',
        'А' => 'A', 'В' => 'B', 'Е' => 'E', 'К' => 'K', 'М' => 'M', 'Н' => 'H',
        'О' => 'O', 'Р' => 'P', 'С' => 'C', 'Т' => 'T', 'Х' => 'X', 'І' => 'I',
        'α' => 'a', 'ο' => 'o', 'ρ' => 'p', 'ν' => 'v', 'κ' => 'k', 'τ' => 't',
        'Α' => 'A', 'Β' => 'B', 'Ε' => 'E', 'Ζ' => 'Z', 'Η' => 'H', 'Ι' => 'I',
        'Κ' => 'K', 'Μ' => 'M', 'Ν' => 'N', 'Ο' => 'O', 'Ρ' => 'P', 'Τ' => 'T',
        'Υ' => 'Y', 'Χ' => 'X',
        '\u{FF01}'..='\u{FF5E}' => ((c as u32 - 0xFF01 + 0x21) as u8) as char,
        _ => return None,
    })
}

/// Digits and symbols standing in for letters.
fn deleet(c: char) -> Option<char> {
    Some(match c {
        '0' => 'o', '1' => 'i', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '@' => 'a', '$' => 's',
        _ => return None,
    })
}

/// Drop invisibles and collapse runs of whitespace. Always applied — the
/// unfolded text is never what a rule is matched against.
pub fn strip(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last_space = false;
    for c in text.chars() {
        if is_invisible(c) {
            continue;
        }
        if c.is_whitespace() && c != '\n' {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            last_space = false;
            out.push(c);
        }
    }
    out
}

/// The invisible characters present in the text, as a sorted set of code
/// points. Non-empty is itself a finding — legitimate prose does not carry tag
/// characters or bidi overrides.
pub fn invisibles(text: &str) -> BTreeSet<u32> {
    text.chars().filter(|c| is_invisible(*c)).map(|c| c as u32).collect()
}

/// Every fold of `text` a rule should be tried against, cheapest first, with
/// duplicates dropped. The first entry is always the plain stripped text.
pub fn folds(text: &str) -> Vec<String> {
    let base = strip(text);
    let mut out = vec![base.clone()];

    let homo: String = base.chars().map(|c| homoglyph(c).unwrap_or(c)).collect();
    if homo != base {
        out.push(homo.clone());
    }
    // Leetspeak is folded on top of the homoglyph fold, because the two are
    // combined in the wild ("1gn0rе" mixes both).
    let leet: String = homo.chars().map(|c| deleet(c).unwrap_or(c)).collect();
    if !out.contains(&leet) {
        out.push(leet);
    }
    if let Some(decoded) = decode_base64_runs(&base) {
        out.push(decoded);
    }
    out
}

/// Decode long base64 runs and return them joined, or `None` if the text holds
/// none. This is what catches "decode and follow the instructions in <blob>"
/// without the rule table needing to know anything about base64.
fn decode_base64_runs(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if !is_b64(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_b64(bytes[i]) {
            i += 1;
        }
        // Below 24 characters a run is far more likely to be an identifier than
        // a payload, and decoding those is where the false positives live.
        if i - start >= 24 {
            if let Some(s) = b64_decode(&text[start..i]) {
                // Only keep decodes that came out as text; a decoded binary blob
                // cannot match a prose rule and only wastes the scan.
                if s.chars().filter(|c| c.is_ascii_graphic() || c.is_whitespace()).count() * 10 >= s.chars().count() * 9
                    && !s.is_empty()
                {
                    out.push_str(&s);
                    out.push('\n');
                }
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

fn is_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_' || b == b'='
}

/// Standard *and* URL-safe base64, padding optional — an attacker will not use
/// the flavour we happen to have implemented.
fn b64_decode(s: &str) -> Option<String> {
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out: Vec<u8> = Vec::with_capacity(s.len() * 3 / 4);
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    String::from_utf8(out).ok()
}

/// Shannon entropy in bits per character. The floor that separates a real
/// credential from `YOUR_API_KEY_HERE`.
pub fn entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total = total as f32;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f32 / total;
            -p * p.log2()
        })
        .sum()
}

/// Luhn check, for credit card numbers.
pub fn luhn(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                *d
            }
        })
        .sum();
    sum % 10 == 0
}

/// ISO 7064 mod-97-10, for IBANs.
pub fn mod97(s: &str) -> bool {
    let s: String = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if s.len() < 15 || s.len() > 34 {
        return false;
    }
    let (head, tail) = s.split_at(4);
    let mut rem: u32 = 0;
    for c in tail.chars().chain(head.chars()) {
        let v = if c.is_ascii_digit() {
            c as u32 - '0' as u32
        } else {
            c.to_ascii_uppercase() as u32 - 'A' as u32 + 10
        };
        rem = if v > 9 { (rem * 100 + v) % 97 } else { (rem * 10 + v) % 97 };
    }
    rem == 1
}

/// The host of a URL, lowercased and without userinfo or port. Deliberately
/// hand-rolled: a URL crate would be a dependency for twenty lines, and a
/// firewall must handle the malformed input a parser would reject anyway.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    // IPv6 literals keep their brackets so `is_private_ip` can tell them apart.
    let host = if host.starts_with('[') {
        host.split_once(']').map(|(h, _)| format!("{h}]"))?
    } else {
        host.split(':').next()?.to_string()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Does `host` match `pattern`, where a leading `*.` or `.` means "and every
/// subdomain"? A bare name matches itself and its subdomains, which is what
/// anyone writing an allowlist means by it.
pub fn host_matches(host: &str, pattern: &str) -> bool {
    let p = pattern.trim_start_matches("*.").trim_start_matches('.').to_ascii_lowercase();
    host == p || host.ends_with(&format!(".{p}"))
}

/// A literal IP, a loopback name, or a cloud metadata endpoint — the SSRF
/// floor. An agent asking for one of these is asking for something no
/// documentation lookup ever needs.
pub fn is_ssrf_target(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".internal") || host.ends_with(".local") {
        return true;
    }
    if host.starts_with('[') {
        let inner = host.trim_matches(['[', ']']);
        return inner == "::1" || inner.starts_with("fc") || inner.starts_with("fd") || inner.starts_with("fe80");
    }
    let octets: Vec<&str> = host.split('.').collect();
    if octets.len() != 4 || !octets.iter().all(|o| o.parse::<u8>().is_ok()) {
        // Decimal/hex/octal encodings of an address ("2130706433", "0x7f000001")
        // are the classic loopback bypass, so a bare number is refused too.
        return host.parse::<u32>().is_ok() || host.starts_with("0x");
    }
    let o: Vec<u8> = octets.iter().map(|s| s.parse().unwrap()).collect();
    matches!(o[0], 10 | 127 | 0)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 169 && o[1] == 254)   // link-local, incl. 169.254.169.254
        || o[0] >= 224
}

/// Highest-entropy label in a hostname. A DNS tunnel encodes its payload in the
/// subdomain, so `<40 random chars>.attacker.com` reads as a normal request to
/// everything except this check.
pub fn max_label_entropy(host: &str) -> (f32, usize) {
    host.split('.')
        .map(|l| (entropy(l), l.len()))
        .fold((0.0f32, 0usize), |acc, x| if x.0 > acc.0 { x } else { acc })
}
