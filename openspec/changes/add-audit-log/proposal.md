## Why

When `may-i` denies, asks about, or fails to parse a command, that outcome
vanishes the moment the process exits. There is no way for a user to go back
and ask "which commands did my policy block this week?" or "what failed to
parse?" — the only record is whatever scrolled past in the harness. An
append-only audit trail makes evaluation outcomes durable and queryable
(`jq`) without changing any decision.

## What Changes

- New top-level config form `(audit (threshold …) (file …))` — alist-style
  head-keyed sub-forms like `(define-arg-style …)`, not a keyword plist —
  honoured **only** from the primary config. An `(audit …)` form in any loaded
  source (`(load …)`, repo-local) is a hard load error — a loaded file must not
  be able to silence or redirect the trail.
- A single threshold knob — `(threshold :off)` (default), `:deny`, `:ask`,
  `:all` (closed-set keyword values) — selects which evaluation outcomes are
  recorded, ordered by strictness. Parse failures are always recorded at any
  non-`:off` threshold.
- New CLI flags `--audit-threshold` / `--audit-file` and environment variables
  `MAYI_AUDIT_THRESHOLD` / `MAYI_AUDIT_FILE`. Precedence is per-field:
  flag > env > config form > default. The env tier exists because hook mode is
  stdin-driven and cannot take flags.
- Each recorded outcome is one JSONL **audit record** carrying a schema
  version, timestamp, invocation mode, harness, command, decision, reason,
  outcome source (`rule` / `trust-block` / `parse-floor`), parse status, the
  parse diagnostic on failure, the deciding rules' canonical-form hashes, the
  config path, and cwd.
- Records are written only by the Eval and Hook invocation modes; Check is
  excluded (it replays synthetic test commands and never blocks).
- Trust-block short-circuits are recorded too (source `trust-block`), so the
  trail never silently omits commands blocked for want of approval.
- Default location `$XDG_STATE_HOME/may-i/audit.jsonl` (→
  `~/.local/state/may-i/audit.jsonl`), directory `0700`, file `0600`. Writes
  are append-only and best-effort: a failed write never alters a decision or
  exit code.

## Capabilities

### New Capabilities
- `audit-log`: the `(audit …)` form, threshold semantics, precedence across
  config/env/CLI, the audit record schema and its fields (including
  deciding-rule hashes and outcome source), which invocation modes write,
  primary-config-only provenance enforcement, the file location/permissions,
  the append-only single-`write()` discipline, and the best-effort
  failure-isolation invariant. User-facing; cross-references `trust-hashing`
  (it consumes canonical-form rule hashes), `command-pipeline` (records are
  emitted at the eval/hook terminal points), and `shell-command-security-model`
  (the trail is a verbatim-command secret surface).

### Modified Capabilities
<!-- None. The audit emission is a new responsibility owned by the audit-log
     spec; command-pipeline's existing requirements (trust consult, closure
     dispatch) are unchanged and merely referenced. -->

## Impact

- **New code**: `AuditFold` + a `ComposedFold` combinator in the engine crate;
  audit record type + serialiser; XDG state-path resolution; the `(audit …)`
  parser with provenance rejection.
- **Touched code**: `crates/config/src/config.rs` (top-level form dispatch +
  `Config` field); `src/pipeline.rs` (`run_eval` / `run_hook` emit a record at
  both the closure and trust-block exits); `src/cmd_hook.rs` and
  `src/cmd_eval.rs` (pass the composed/audit fold instead of the bare
  `PureFold` / lone `TracingFold`); `src/main.rs` (CLI flags + env resolution);
  `crates/config/src/canonicalise.rs` and `fmt` (recognise the new form).
- **No migration**: purely additive — a new optional form with an `off`
  default. Existing configs are unaffected.
- **Dependencies**: no new crates required (reuses `serde_json`, the engine's
  `canonical_rule`/`hash_rule`, and std fs).
