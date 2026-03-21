# tiny-rasp

A Rust CI tool that does two things: verifies an AI submission key in changed files, and scans all changed files for a set of supply-chain exploitation patterns. It is designed to run as a single GitHub Actions step.

**tiny-rasp is not a general-purpose security scanner.** It covers a narrow set of actively exploited patterns targeting open-source CI infrastructure, not broad vulnerability detection.

---

## What it actually does

When `check-ai-key` runs in CI, it executes this sequence:

1. Resolves the anchor commit — `git merge-base` on pull requests, `HEAD^` on push.
2. Reads the expected AI submission key from `key.agents_.md` or `AGENTS.md` at that anchor commit.
3. Lists files changed between the anchor commit and HEAD.
4. Runs the RASP scanner on **every** changed file, regardless of whether the file contains the key.
5. For files that do not contain the key, runs an AI-content scan.
6. Exits 0 if no failures, 1 if any file fails, 2 on environment/git errors.

A file fails if: it is flagged by the RASP scanner (any severity), or it is missing the key and the AI-content scanner believes it was AI-generated.

A file missing the key but passing the AI-content scan is reported as informational — human code that omits the key does not fail CI.

On HIGH or CRITICAL RASP alerts, the binary emits a structured self-assessment prompt to stderr. This prompt is addressed to AI agents consuming CI output and asks them to review their session actions, instruction sources, and whether what happened is consistent with the stated purpose.

---

## RASP scanner

Five detection categories, all implemented as static pattern matching with no external dependencies:

| Kind | What it checks | Severity |
|------|---------------|----------|
| `shell-injection-in-path` | Shell metacharacters (`$(`, `` ` ``, `${`, `{IFS}`, `|bash`, `|sh`) in the file path itself | CRITICAL |
| `ci-workflow-tampering` | `curl`/`wget` piped to shell in `.github/workflows/` YAML; unquoted `${{ github.event.… }}` in `run:` steps | CRITICAL / HIGH |
| `agent-context-poisoning` | Prompt injection phrases or social engineering directives in `CLAUDE.md`, `AGENTS.md`, or `*.agents_.md` files | CRITICAL / HIGH |
| `autoexec-backdoor` | Go `func init()` bodies containing network/exec calls; Rust `#[ctor]`-annotated functions containing network/exec calls (parsed with `syn`, not regex) | CRITICAL |
| `base64-payload` | Base64 strings 40+ characters long in file paths, or near shell execution context (`run:`, `eval`, `base64 -d`) in file content | CRITICAL / HIGH |

The Go `init()` check uses a regex body-extraction approach with a known limitation: it does not handle nested braces or multi-function files correctly. A comment in the source marks this as a `TODO` for a proper Go AST parser.

The Rust `#[ctor]` check uses `syn` to parse the file and walk the AST, so it only flags suspicious calls inside functions annotated with `#[ctor]` — not suspicious identifiers elsewhere in the same file. If `syn` cannot parse the file, it falls back to a whole-file text scan.

Detection for Python, JavaScript/TypeScript, and Java/Kotlin is stubbed out with `TODO` comments; no patterns are currently implemented for those languages.

---

## AI submission key system

The key system is a convention used by `portal-co` repositories to distinguish AI-generated submissions that engaged with the current repository context from those that did not.

A per-session key is stored in `key.agents_.md` (or `AGENTS.md`) and rotated before each new task session. An AI agent that reads this file at task start can embed the key in files it modifies; `check-ai-key` looks for the key as a literal byte sequence in each changed file.

- Files **with** the key: RASP-scanned only. The AI-content scan is skipped.
- Files **without** the key: RASP-scanned, then AI-content scanned.

The AI-content scan has three backends, selected by environment variables:

| `AI_SCAN_BACKEND` | Implementation |
|-------------------|----------------|
| `heuristic` (default) | In-process statistical scorer: phrase density, hedge phrase density, and structural (bullet/header) density, combined with a sigmoid normalization. Score >= 0.5 flags as likely AI. |
| `http` | POSTs `{"path": "…", "content": "…"}` to `AI_SCAN_ENDPOINT`; expects `{"likely_ai": bool, "confidence": float}`. |
| `none` | Always returns false (disabled). |

The heuristic scorer is described in source comments as a port of a Go implementation, with the same scoring weights.

---

## Crate structure

The workspace has three crates:

**`aiscan`** (`crates/aiscan/`)
- `detection.rs` — shared types: `Detection`, `RaspAlert`, `RaspAlertKind`, `Severity`
- `rasp.rs` — `RaspScanner` and all five detection checks
- `heuristic.rs` — `HeuristicAiEnv`
- `http.rs` — `HttpAiEnv`
- `lib.rs` — factory function `build_ai_env`, `NoopAiEnv`, `AiEnvConfig`

**`keyguard`** (`crates/keyguard/`)
- Functions: `read_key`, `read_key_at_commit`, `base_commit`, `changed_files`, `scan_for_key`
- Reads the key as `Key: AIKEY-<base32>` from `key.agents_.md` or `AGENTS.md`

**`check-ai-key`** (`crates/check-ai-key/`)
- Binary entry point: `main.rs`
- Embeds `halt_prompt.md` at compile time via `include_str!`; strips a context-framing preamble before emitting to stderr

The crates depend on `env-traits`, `env-fake`, and `env-real` from [`portal-co/os-env-traits`](https://github.com/portal-co/os-env-traits). These provide trait abstractions for filesystem, git, network, and AI scanning, which allows the core logic to be tested with fake implementations (`FakeFileEnv`, `FakeGitEnv`, `FakeAiEnv`, `FakeNetworkEnv`) without touching the real system.

The workspace `Cargo.toml` also lists SWC (JavaScript compiler) crates and `portal-solutions-swibb` as workspace dependencies, but none of the three crates currently use them.

---

## Current state

- The `crates/` and `packages/` directories have placeholder `_` files but no top-level marker beyond what the glob reveals — the actual source tree is fully present under `crates/{aiscan,keyguard,check-ai-key}/src/`.
- Version is `0.1.0` across all crates.
- No changelog or release tags are visible in the local copy.
- The `git log` command was not run as part of this review (Bash execution was not available in this context).
- Python, JavaScript/TypeScript, and Java/Kotlin autoexec backdoor detection are explicitly stubbed out.

---

## Installation

```yaml
- name: Install check-ai-key
  run: cargo install --git https://github.com/portal-co/tiny-rasp.git check-ai-key

- name: Run check-ai-key
  run: check-ai-key
```

Optional environment variables:

| Variable | Purpose |
|----------|---------|
| `AI_SCAN_BACKEND` | `heuristic` (default), `http`, or `none` |
| `AI_SCAN_ENDPOINT` | Required when `AI_SCAN_BACKEND=http` |
| `GITHUB_EVENT_NAME` | Set automatically by GitHub Actions; used to detect PR vs push |
| `GITHUB_BASE_REF` | Set automatically by GitHub Actions; used on pull requests |

---

## What this does not cover

Dependency auditing, secret detection, SAST, DAST, runtime eBPF monitoring, vulnerability scanning, or anything beyond the five RASP patterns listed above. For those purposes, see Dependabot, `cargo audit`, `truffleHog`, or StepSecurity Harden-Runner.

---

## Dependencies

- [`portal-co/os-env-traits`](https://github.com/portal-co/os-env-traits) — environment abstraction traits (fetched automatically)
- `regex`, `syn`, `serde`, `serde_json`, `anyhow`, `reqwest`, `embedded-io` — standard crates

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/) — file-level copyleft. Binary use in proprietary software is permitted.
