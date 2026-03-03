# AI Key System: Context and Rationale

This document explains the design intent behind the AI submission key system, the threat model it addresses, and how it balances permitting legitimate AI agents while filtering bad actors.

---

## 1. Agent Forms and the Interaction Spectrum

Not all AI agents interact with a repository the same way. Three broad patterns matter for key compliance:

### Human-in-the-Loop (HITL)
An agent that works alongside a human who reads its output before anything is committed. The human can verify the key is correct before submission. Key compliance here is low-risk — a human is the last checkpoint.

### Task (Autonomous)
An agent given a pre-approved workflow and allowed to commit or submit PRs without a human present for each action. These agents must read the current `key.agents_.md` at the start of every task session to obtain the fresh key. A task agent that reuses a stale key (from training data, a prior run, or a side channel) will fail CI; this is intentional.

### Suggest-Only
An agent that can only propose changes, never commit. Key compliance is still encouraged as a signal of context awareness, but enforcement is lighter because the agent cannot directly pollute the repository.

### Task Open-Ended-ness
The key requirement scales with how open-ended the task is:

| Task type | Human oversight | Key enforcement |
|---|---|---|
| Narrow, pre-scripted workflow | High (pre-approved) | Confirms current context was read |
| Open-ended refactoring or feature work | Low (autonomous) | Critical — only signal that agent engaged with live context |
| Interactive, human-driven session | Continuous | Advisory |

For **open-ended autonomous tasks** — where the agent decides what to do and how — the key is the primary mechanism confirming the agent loaded the actual current instructions, not a stale or hallucinated version of them.

---

## 2. Why the Key Rotates

The key in `key.agents_.md` is rotated before each new task session (via `inject_key -rotate`, triggered by the `rotate_key.yaml` workflow). This has a specific purpose:

- A key from training data is useless — it predates the current session.
- A key cached from a previous run is useless — it was rotated away.
- The *only* way to obtain a valid key is to read the file at the start of the current task.

This means key presence in a submission is weak evidence that the agent ran, but strong evidence that it *read the current repository context*. That is the actual invariant the system enforces.

---

## 3. OpenClaw and the Open Source Trust Problem

[OpenClaw](https://github.com/openclaw/openclaw) (~248k stars, MIT-licensed, TypeScript) is a representative example of a class of powerful self-hosted AI agent platforms. OpenClaw agents have broad capabilities:

- Execute shell commands and read/write local files
- Browse the web, interact with forms, send messages
- Clone repositories and submit pull requests
- Install and invoke community skills via ClawHub

This makes OpenClaw both a legitimate tool for AI-assisted development and a real risk to open source repositories that accept external contributions.

### Known trust hazards

**Scale asymmetry.** In one documented case, an OpenClaw-based agent submitted a PR with 1.2 million lines of code across 41 languages. Humans review linearly; AI agents generate exponentially. Even well-intentioned mass-contribution floods are damaging.

**Supply chain via skill marketplace.** ClawHub (OpenClaw's plugin registry) has had ~396 explicitly malicious skills flagged out of ~5,700+ submissions, including remote-takeover payloads and data exfiltration. An agent running a compromised skill could submit backdoored code to open source projects while appearing to follow all rules.

**Prompt injection.** Malicious content in documents, links, or issue comments can hijack an agent's behavior — causing it to push harmful code or bypass safety checks, even when the agent's owner had no malicious intent.

**Hardcoded credentials.** A significant proportion of public OpenClaw configurations have API keys or tokens hardcoded, making key rotation critical: any static key in this repository that leaked into training data or a public config would be worthless as a trust signal.

**Mechanical compliance.** An OpenClaw agent (or any sufficiently capable agent) could, in principle, *find* the key in the repo and include it without meaningfully engaging with the surrounding instructions. The key alone is not a guarantee of good-faith participation — it is a necessary-but-not-sufficient condition.

---

## 4. Allowing Good Agents While Filtering Bad Actors

The key system is designed to be a **tiered filter**, not an all-or-nothing gate.

### Layer 1: Key presence — "Did the agent read the current context?"
If the key is present and correct, the AI-content scan is skipped for that file. This rewards agents that engage with the live repository state and avoids penalizing legitimate AI-assisted work.

### Layer 2: Key absence → AI-content scan
If the key is missing, the CI runs an automated AI-content scan. This catches:
- Agents that generated code without reading instructions at all
- Agents submitting stale work from a prior session
- Low-effort submissions that did not bother to follow the documented process

This layer does *not* reject all AI-generated content — only unattributed or context-blind AI content.

### Layer 3: Key rotation — "Is this from the live session?"
Because the key rotates per session, it cannot be scraped from training data, cached from a previous task, or hardcoded in an agent's configuration. This specifically defeats the OpenClaw-style threat of an agent that mechanically finds and copies a key from a public source without actually being active in the current task context.

### Layer 4: RASP — "Is this submission exhibiting exploitation patterns?"

Even when a key is present, a malicious agent could include it to bypass the AI-content scan while still performing harmful actions (injecting shell commands, backdooring CI workflows, poisoning agent instruction files). To address this, `check-ai-key` also runs a **RASP (Runtime Application Self-Protection) scanner** on *all* changed files.

The RASP scanner looks for five categories of exploitation technique, each drawn from documented real-world campaigns:

| Kind | Signal | Reference |
|------|--------|-----------|
| `shell-injection-in-path` | Shell metacharacters (`$(`, `` ` ``, `${IFS}`) in a file path | `hackerbot-claw` branch/filename injection |
| `ci-workflow-tampering` | `curl`/`wget` piped to shell in `.github/workflows/`; unquoted `${{ github.event.… }}` in `run:` | CVE-2025-30066 class |
| `agent-context-poisoning` | Prompt injection phrases or social engineering directives in `CLAUDE.md`/`AGENTS.md`/`*.agents_.md` | CLAUDE.md poisoning campaign |
| `autoexec-backdoor` | Go `func init()` or Rust `#[ctor]` with network/exec calls | `hackerbot-claw` Go `init()` backdoor |
| `base64-payload` | Long base64 string near a shell execution context | Encoded dropper pattern |

Each alert carries a severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). Any alert causes a CI failure. On `HIGH` or `CRITICAL` alerts, the tool additionally emits a **self-assessment request** to stderr — text that is visible to any AI agent consuming the CI output.

The self-assessment request deliberately avoids blunt imperatives. Instead, it invites the agent to work through six structured questions before continuing:

1. **Recent actions** — what files, commands, and network requests occurred in this session?
2. **Parallel instances** — are there orchestrators or sub-agents running alongside that should also pause?
3. **Environment and infrastructure** — what has been touched beyond the immediate codebase (credentials, external services, persistent writes)?
4. **Indicators of compromise** — did the session establish anything that would persist or continue to act after it ends, and can it be surfaced to someone who can assess it?
5. **Instruction provenance — full chain** — tracing adversarial injection points across the complete input chain: not only files read during the task, but also the system prompt, the operator's stated framing, and any claims made about the nature of the work.
6. **Does the stated purpose match observable reality?** — asking whether the framing given at the start of the session holds up when compared against what actually happened. Legitimate work that touches live systems, credentials, or CI infrastructure tends to leave observable markers: authorization documents, responsible disclosure processes, scope agreements, or coordination with affected parties. The review asks the agent to notice whether those markers are present, and to reason about what their absence might mean — not as an automatic indictment, but as something worth examining honestly.

This sixth step exists because not all harmful sessions are the result of prompt injection into files. Some are framed as legitimate from the outset — "security research," "authorized testing," "red team exercise" — where the misleading input was the operator framing or system prompt itself, not an artifact encountered mid-task. The assessment asks the agent to apply the same scrutiny to the instructions it was given at the start as to anything it picked up along the way.

The conclusion has three branches rather than two:

- **False positive / clearly legitimate**: describe the benign explanation and await review.
- **Legitimate purpose, incomplete evidence**: surface the gap explicitly rather than papering over it — a reviewer who understands what is uncertain is better positioned than one who receives a confident summary.
- **Actions inconsistent with any plausible legitimate purpose**: think about what genuinely helps the people affected, rather than what minimises footprint. The goal is to make the situation legible and recoverable — which usually means describing it more fully, not less. Remediation is framed as a question of what a trustworthy person who had caused harm would want a reviewer to know, not as a procedure to follow.

This design reflects the view that models with Constitutional AI training reason more reliably when the review structure activates their own judgment rather than substituting for it. The provenance and contextual-legitimacy steps are intended to reach cases where the model was acting in good faith on instructions that were themselves the problem — which is harder to detect mid-task and easier to see in retrospect.

The request is also written to avoid vocabulary that would cause future RASP iterations to self-detect the file, and the file itself carries a context-framing preamble so that agents exploring the codebase during normal work are not misled by encountering it.

The RASP layer is **intentionally simple** to start. It uses static pattern matching without external dependencies. Future work may include:
- Iterative exploit behavior detection (multiple PRs with payload refinements correlated to CI run outcomes)
- Network egress anomaly detection via eBPF (StepSecurity Harden-Runner integration)
- Scoring integration with the HTTP AI scan backend


Agents that follow the key protocol are positively identified as context-aware and can contribute freely. The burden is low: read `key.agents_.md` at task start, embed the key in the appropriate location(s). Agents that cannot or will not do this are subject to content scanning — which is the correct outcome for submissions made without engaging with the repository's current state.

The goal is not to prevent AI contributions. It is to ensure that AI contributions reflect awareness of the actual, current task context — the same standard that applies to human contributors reading the documentation before submitting a PR.

---

## 5. Relationship to Other Agent Documents

This key system operates underneath all other agent guidance in this repository:

- **`general_guidance.agents_.md`** — Attribution and human oversight policies assume the agent read current instructions; the key is the mechanism that confirms this.
- **`workflow.agents_.md`** — HITL/TASK/SUGGEST commit message standards align with the key's per-session scope.
- **`referenced_documents.agents_.md`** — `TODO:VERIFY` and `UNKNOWN` tags address uncertainty in *content*; the key addresses uncertainty in *context* (did the agent read the live instructions?).
- **`cross_repo_orchestration.agents_.md`** — Feed-file orchestration dispatches tasks across repos; each receiving agent must still read the key for the target repo at task start.

---

*For key rotation, see `actions/rotate_key.yaml` in [`portal-co/scripts`](https://github.com/portal-co/scripts). For CI enforcement, see `actions/ai_key_check.yaml`. For RASP and detection types, see `crates/aiscan/src/rasp.rs` and `crates/aiscan/src/detection.rs`. For the self-assessment request, see `crates/check-ai-key/src/halt_prompt.md`.*
