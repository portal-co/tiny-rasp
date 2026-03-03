# tiny-rasp

A lightweight, integrated RASP (Runtime Application Self-Protection) and AI key
verification tool for CI pipelines.

**tiny-rasp is intentionally not a comprehensive security solution.** It focuses
on a specific, high-urgency subset of supply-chain attack patterns that are
actively being used in the wild against open source CI infrastructure. The
design priority is fast detection and fast response, tightly integrated into a
single CI step — not broad coverage.

## What it detects

Five categories of exploitation technique, each drawn from documented real-world
campaigns:

| Kind | Signal | Reference |
|------|--------|-----------|
| `shell-injection-in-path` | Shell metacharacters in a file path or name | `hackerbot-claw` (2026) |
| `ci-workflow-tampering` | `curl`/`wget`-to-shell droppers; unquoted `${{ github.event.… }}` expressions | CVE-2025-30066 class |
| `agent-context-poisoning` | Prompt injection phrases in `CLAUDE.md` / `AGENTS.md` / `*.agents_.md` | CLAUDE.md poisoning campaign |
| `autoexec-backdoor` | Go `func init()` or Rust `#[ctor]` with network/exec calls | `hackerbot-claw` Go init() backdoor |
| `base64-payload` | Long base64 string near a shell execution context | Encoded dropper pattern |

## What it does not cover

Broad vulnerability scanning, dependency auditing, secret detection, SAST, or
runtime eBPF-level monitoring are explicitly out of scope. For those, see
dedicated tools (Dependabot, `cargo audit`, `truffleHog`, StepSecurity
Harden-Runner). tiny-rasp complements rather than replaces them.

## AI key system

tiny-rasp also includes the AI submission key system used by `portal-co/scripts`:

- **`keyguard`** — reads and verifies the per-session AI submission key from
  `key.agents_.md` or `AGENTS.md`, resolves the CI anchor commit, and lists
  changed files.
- **`check-ai-key`** (binary) — CI entrypoint. Runs the RASP scanner on all
  changed files, then AI-scans files that lack the submission key. On a
  HIGH/CRITICAL RASP alert, emits a structured self-assessment request to stderr
  that is visible to any AI agent consuming the CI output.

## Crates

- **`aiscan`** — detection types (`Detection`, `RaspAlert`, `RaspAlertKind`,
  `Severity`), RASP scanner (`RaspScanner`), heuristic AI scanner
  (`HeuristicAiEnv`), and HTTP AI scanner (`HttpAiEnv`).
- **`keyguard`** — AI key reading and CI anchor-commit resolution.
- **`check-ai-key`** — the `check-ai-key` binary.

## Installation (in a target repo's CI workflow)

```yaml
- name: Install check-ai-key
  run: cargo install --git https://github.com/portal-co/tiny-rasp.git check-ai-key

- name: Run check-ai-key
  run: check-ai-key
```

## Dependencies

Requires [`portal-co/os-env-traits`](https://github.com/portal-co/os-env-traits)
(fetched automatically via Cargo).

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/) — file-level copyleft.
Binary use in proprietary software is permitted.
