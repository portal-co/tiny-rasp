// AIKEY-l4qkxonqry2b4gj7bsrkqpryiy
//! Pure-Rust statistical heuristic scanner — exact port of the Go
//! `HeuristicScanner`.
//!
//! Scoring weights and all phrase lists are kept identical to the Go
//! implementation so that CI behaviour is unchanged.

use std::path::Path;

use anyhow::Result;
use env_traits::AiEnv;

#[derive(Default, Clone, Copy)]
pub struct HeuristicAiEnv;

impl AiEnv for HeuristicAiEnv {
    fn scan(&self, _path: &Path, content: &[u8]) -> Result<(bool, f64)> {
        let text = String::from_utf8_lossy(content);
        let score = score(&text);
        Ok((score >= 0.5, score))
    }
}

/// Returns a value in [0, 1]; >= 0.5 means likely AI.
pub(crate) fn score(text: &str) -> f64 {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return 0.0;
    }

    let weights: &[(f64, f64)] = &[
        (phrase_density(text), 0.45),
        (hedge_density(text), 0.35),
        (bullet_header_density(text), 0.20),
    ];

    let (total, wsum) = weights
        .iter()
        .fold((0.0_f64, 0.0_f64), |(t, w), (v, wt)| (t + v * wt, w + wt));

    sigmoid_norm(total / wsum)
}

fn phrase_density(text: &str) -> f64 {
    const PHRASES: &[&str] = &[
        "it's worth noting",
        "it is worth noting",
        "as an ai",
        "as an ai language model",
        "i cannot provide",
        "i'm unable to",
        "i am unable to",
        "delve into",
        "dive into",
        "in conclusion",
        "in summary",
        "to summarize",
        "let's explore",
        "let us explore",
        "it is important to note",
        "it's important to note",
        "please note that",
        "feel free to",
        "i hope this helps",
        "certainly!",
        "of course!",
        "absolutely!",
        "great question",
        "this is a great",
        "comprehensive guide",
        "step-by-step",
        "step by step",
        "furthermore,",
        "additionally,",
        "in the realm of",
        "leveraging",
        "utilize",
        "robust solution",
        "seamlessly",
        "cutting-edge",
    ];

    let lower = text.to_lowercase();
    let sentences = split_sentences(&lower);
    if sentences.is_empty() {
        return 0.0;
    }
    let hits = sentences
        .iter()
        .filter(|s| PHRASES.iter().any(|p| s.contains(p)))
        .count();
    f64::min(hits as f64 / sentences.len() as f64 * 3.0, 1.0)
}

fn hedge_density(text: &str) -> f64 {
    const HEDGES: &[&str] = &[
        "as mentioned",
        "as noted above",
        "as discussed",
        "as outlined",
        "this ensures that",
        "this allows you to",
        "this will allow",
        "this helps to",
        "this approach ensures",
        "by doing so",
        "in other words",
        "to put it simply",
        "put simply",
        "to clarify",
        "that being said",
        "with that said",
        "having said that",
        "needless to say",
    ];

    let lower = text.to_lowercase();
    let sentences = split_sentences(&lower);
    if sentences.is_empty() {
        return 0.0;
    }
    let hits = sentences
        .iter()
        .filter(|s| HEDGES.iter().any(|p| s.contains(p)))
        .count();
    f64::min(hits as f64 / sentences.len() as f64 * 4.0, 1.0)
}

fn bullet_header_density(text: &str) -> f64 {
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.is_empty() {
        return 0.0;
    }
    let structural = lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .filter(|l| {
            l.starts_with('#')
                || l.starts_with("- ")
                || l.starts_with("* ")
                || l.starts_with("+ ")
                || (l.len() > 2
                    && l.as_bytes()[0].is_ascii_digit()
                    && l.as_bytes()[0] != b'0'
                    && l.as_bytes()[1] == b'.')
        })
        .count();
    let ratio = structural as f64 / lines.len() as f64;
    f64::min(ratio / 0.4, 1.0)
}

fn split_sentences(text: &str) -> Vec<String> {
    let mut sentences = Vec::new();
    let mut buf = String::new();
    for ch in text.chars() {
        buf.push(ch);
        if ch == '.' || ch == '!' || ch == '?' || ch == '\n' {
            let s: String = buf.trim().to_string();
            if s.len() > 8 {
                sentences.push(s);
            }
            buf.clear();
        }
    }
    let remaining = buf.trim().to_string();
    if remaining.len() > 8 {
        sentences.push(remaining);
    }
    sentences
}

/// Logistic sigmoid: 1/(1+exp(-8*(x-0.35))).
/// Maps [0,1] → [0,1] with a soft S-curve centred at 0.35.
fn sigmoid_norm(x: f64) -> f64 {
    1.0 / (1.0 + (-8.0 * (x - 0.35)).exp())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(text: &str) -> (bool, f64) {
        HeuristicAiEnv
            .scan(std::path::Path::new("test.txt"), text.as_bytes())
            .unwrap()
    }

    #[test]
    fn empty_text_is_not_ai() {
        let (likely, conf) = scan("   ");
        assert!(!likely);
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn plain_code_is_not_ai() {
        let (likely, _) = scan("fn main() { println!(\"hello\"); }");
        assert!(!likely);
    }

    #[test]
    fn heavy_phrase_density_is_flagged() {
        let text = "\
            It is worth noting that this is important. \
            In conclusion, let's explore the realm of cutting-edge solutions. \
            Furthermore, this comprehensive guide will delve into robust solutions. \
            Additionally, seamlessly leveraging these tools is certainly useful. \
            Absolutely! I hope this helps.";
        let (likely, conf) = scan(text);
        assert!(likely, "expected AI flag, got conf={conf:.3}");
    }

    #[test]
    fn sigmoid_norm_midpoint() {
        // At x=0.35 the sigmoid should return ~0.5
        let v = sigmoid_norm(0.35);
        assert!((v - 0.5).abs() < 1e-9);
    }
}
