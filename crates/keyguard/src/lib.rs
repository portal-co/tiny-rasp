// AIKEY-l4qkxonqry2b4gj7bsrkqpryiy
//! AI submission key management.
//!
//! Provides functions for reading the key from `key.agents_.md` or
//! `AGENTS.md`, resolving the CI anchor commit, listing changed files, and
//! scanning file contents for the presence of the key.

use std::path::{Path, PathBuf};

use anyhow::Result;
use env_traits::{ErrorType, FileEnv, GitEnv};
use regex::Regex;

/// Ordered list of candidate files that may contain the key.
const CANDIDATE_FILES: &[&str] = &["key.agents_.md", "AGENTS.md"];

// ── Public API ────────────────────────────────────────────────────────────────

/// Read the AI submission key from the working-tree copy of `key.agents_.md`
/// (or `AGENTS.md`) inside `repo_root`.
///
/// Returns `Ok(None)` when neither file exists or neither contains a key.
pub fn read_key<F: FileEnv>(file: &F, repo_root: &Path) -> Result<Option<String>>
where
    F::Error: Send + Sync + 'static,
{
    for name in CANDIDATE_FILES {
        let path = repo_root.join(name);
        let path_str = path.to_string_lossy();
        if !file.file_exists(&path_str) {
            continue;
        }
        let data = file.read_file(&path_str)?;
        if let Some(k) = extract_key(&data) {
            return Ok(Some(k));
        }
    }
    Ok(None)
}

/// Read the AI submission key from a specific git commit object.
///
/// Returns `Ok(None)` when the commit contains neither file or neither has
/// a key.
pub fn read_key_at_commit<G: GitEnv>(
    git: &G,
    repo_root: &Path,
    commit: &str,
) -> Result<Option<String>>
where
    G::Error: Send + Sync + 'static,
{
    let root_str = repo_root.to_string_lossy();
    for name in CANDIDATE_FILES {
        match git.show_file(&root_str, commit, name) {
            Err(_) => continue, // file absent in this commit
            Ok(data) => {
                if let Some(k) = extract_key(&data) {
                    return Ok(Some(k));
                }
            }
        }
    }
    Ok(None)
}

/// Resolve the anchor commit for the current CI event.
///
/// Resolution rules:
/// - `pull_request` event: `git merge-base HEAD origin/$GITHUB_BASE_REF`
/// - `push` event with a parent commit: `HEAD^`
/// - orphan / initial commit: returns `Ok(None)` — caller should skip
///   enforcement
pub fn base_commit<F: FileEnv, G: GitEnv>(
    file: &F,
    git: &G,
    repo_root: &Path,
) -> Result<Option<String>>
where
    F::Error: Send + Sync + 'static,
    G::Error: Send + Sync + 'static,
{
    let root_str = repo_root.to_string_lossy();
    let event = file.env_var("GITHUB_EVENT_NAME").unwrap_or_default();
    let base_ref = file.env_var("GITHUB_BASE_REF").unwrap_or_default();

    if event.trim() == "pull_request" && !base_ref.trim().is_empty() {
        let _ = git.fetch(&root_str, "origin", base_ref.trim());
        let sha = git.merge_base(&root_str, base_ref.trim())?;
        return Ok(Some(sha));
    }

    match git.rev_parse(&root_str, "HEAD^") {
        Ok(sha) => Ok(Some(sha)),
        Err(_) => Ok(None), // orphan / initial commit
    }
}

/// Return the list of files changed between `base_sha` and HEAD.
pub fn changed_files<G: GitEnv>(
    git: &G,
    repo_root: &Path,
    base_sha: &str,
) -> Result<Vec<String>>
where
    G::Error: Send + Sync + 'static,
{
    git.changed_files(&repo_root.to_string_lossy(), base_sha).map_err(anyhow::Error::from)
}

/// Return the paths (relative to `repo_root`) from `paths` that do **not**
/// contain `key` as a literal byte sequence.
pub fn scan_for_key<F: FileEnv>(
    file: &F,
    repo_root: &Path,
    paths: &[String],
    key: &str,
) -> Result<Vec<String>>
where
    F::Error: Send + Sync + 'static,
{
    let mut missing = Vec::new();
    for rel in paths {
        let abs: PathBuf = repo_root.join(rel);
        let abs_str = abs.to_string_lossy();
        if !file.file_exists(&abs_str) {
            continue; // deleted file — not a submission
        }
        let data = file.read_file(&abs_str)?;
        if !data.windows(key.len()).any(|w| w == key.as_bytes()) {
            missing.push(rel.clone());
        }
    }
    Ok(missing)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn extract_key(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let re = Regex::new(r"(?m)^Key:\s+(AIKEY-[A-Za-z2-7]+)\s*$").unwrap();
    re.captures(&text)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use env_fake::{FakeFileEnv, FakeGitEnv};

    const KEY: &str = "AIKEY-testkey234abc";
    const KEY_FILE_CONTENT: &str = "# AI Submission Key\n\nKey: AIKEY-testkey234abc\n";

    fn repo() -> PathBuf {
        PathBuf::from("/repo")
    }

    #[test]
    fn read_key_from_key_agents_md() {
        let file = FakeFileEnv::default()
            .with_file("/repo/key.agents_.md", KEY_FILE_CONTENT.as_bytes());
        let k = read_key(&file, &repo()).unwrap();
        assert_eq!(k.as_deref(), Some(KEY));
    }

    #[test]
    fn read_key_falls_back_to_agents_md() {
        let file = FakeFileEnv::default()
            .with_file("/repo/AGENTS.md", KEY_FILE_CONTENT.as_bytes());
        let k = read_key(&file, &repo()).unwrap();
        assert_eq!(k.as_deref(), Some(KEY));
    }

    #[test]
    fn read_key_returns_none_when_absent() {
        let file = FakeFileEnv::default();
        let k = read_key(&file, &repo()).unwrap();
        assert!(k.is_none());
    }

    #[test]
    fn read_key_at_commit_found() {
        let git = FakeGitEnv::default()
            .with_show_file("abc", "key.agents_.md", KEY_FILE_CONTENT.as_bytes());
        let k = read_key_at_commit(&git, &repo(), "abc").unwrap();
        assert_eq!(k.as_deref(), Some(KEY));
    }

    #[test]
    fn read_key_at_commit_missing_returns_none() {
        let git = FakeGitEnv::default();
        let k = read_key_at_commit(&git, &repo(), "abc").unwrap();
        assert!(k.is_none());
    }

    #[test]
    fn base_commit_pull_request() {
        let file = FakeFileEnv::default()
            .with_env("GITHUB_EVENT_NAME", "pull_request")
            .with_env("GITHUB_BASE_REF", "main");
        let git = FakeGitEnv::default().with_merge_base("main", "deadbeef");
        let sha = base_commit(&file, &git, &repo()).unwrap();
        assert_eq!(sha.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn base_commit_push() {
        let file = FakeFileEnv::default();
        let git = FakeGitEnv::default().with_rev("HEAD^", "parentsha");
        let sha = base_commit(&file, &git, &repo()).unwrap();
        assert_eq!(sha.as_deref(), Some("parentsha"));
    }

    #[test]
    fn base_commit_orphan_returns_none() {
        let file = FakeFileEnv::default();
        let git = FakeGitEnv::default(); // rev_parse("HEAD^") will fail
        let sha = base_commit(&file, &git, &repo()).unwrap();
        assert!(sha.is_none());
    }

    #[test]
    fn scan_for_key_detects_missing() {
        let file = FakeFileEnv::default()
            .with_file("/repo/a.rs", b"no key here")
            .with_file("/repo/b.rs", format!("has key: {KEY}").as_bytes());
        let paths = vec!["a.rs".to_string(), "b.rs".to_string()];
        let missing = scan_for_key(&file, &repo(), &paths, KEY).unwrap();
        assert_eq!(missing, vec!["a.rs".to_string()]);
    }
}
