## Context

Redirect targets and env-assignment prefixes are parsed (`Redirection`,
`Assignment` in `crates/shell-parser/src/ast/mod.rs`) but invisible to
evaluation: redirects are only scanned for process-substitution targets, and
assignment prefixes only for embedded commands in their values
(`crates/engine/src/eval/decompose.rs`). The config side of `safe-env-vars`
already exists — `(safe-env-vars …)` parses into `SecurityConfig`
(`crates/config/src/config.rs`) and the loaded-file set is hashed under the
`:safe-env-vars` trust scope (`crates/engine/src/trust.rs:367`) — but nothing
consumes it at decision time.

## Goals / Non-Goals

**Goals.** No command structure that changes what runs escapes the decision.
Safe defaults: floor to `:ask`, never deny outright, never silently ignore.

**Non-Goals.** Constraining *where* a redirect points. `may-i` classifies by
command; path-level restriction is the job of syscall-interception /
sandboxing layers beneath it. No redirect-target Pattern.

## Decisions

### D1 — Floor-only for redirects; capability opt-in deferred

A redirect to a non-standard file target floors to at least `:ask`,
unconditionally. No DSL surface in this change. The earlier idea of a
redirect-target Pattern (match the path against `^/tmp/` etc.) is rejected:
it puts `may-i` in the path-authorisation business, which duplicates the
sandbox's job badly and invites exactly the expansion-bearing bypasses the
asymmetric-soundness invariant exists to stop. The right opt-out is a
*capability* — a rule declaring its command may carry redirects at all —
drafted separately as `rules-grant-redirect-capability` (new user-facing DSL
surface; needs its own design).

Exempt as standard plumbing: targets that are exactly `/dev/null`, and fd
duplication to a numeric fd (`2>&1`, `>&2`). Heredocs and herestrings do not
floor — their "target" is data fed to stdin, not a file the command names
(heredoc bodies are covered by `evaluate-unquoted-heredoc-substitutions`).

### D2 — Env prefixes gate on NAME against the effective safe-env-vars set

A `NAME=VALUE` prefix floors the segment to at least `:ask` unless `NAME` is
in the effective set. The VALUE does not gate: embedded commands in values are
already extracted as evaluation units by `decompose.rs`, and an
expansion-bearing value cannot widen anything because the name-allowlist is
the only gate. Effective set = primary-config entries, plus loaded-file
entries only when the `:safe-env-vars` trust scope is approved (the hashing
side already exists; this wires the consuming side).

**Rejected:** a built-in default allowlist of "known harmless" names. Any
hardcoded list is a curated guess that widens silently as bash evolves; the
spec's "empty set floors everything" default keeps widening an explicit,
trust-scoped user action.

### D3 — Floors reuse the raise-to-ask combinator, not parse diagnostics

Both floors reuse the existing "raise decision to at least `:ask`" path that
the Error-severity parse floor uses (`crates/engine/src/eval/command.rs`),
carrying their own reason strings ("redirect target …", "env prefix …"). No
synthesized `ParseDiagnostic` — the command parsed fine; polluting
`parse_diagnostics` would corrupt the audit record's parse-status field.

## Risks

- **Noise.** `cmd > out.txt` and `sort < f` now ask under allow rules. This is
  the intended safe default; relief arrives with the capability opt-in
  follow-up. Mitigated by reasons that name the operator and target.

## Migration

None. `safe-env-vars` is additive and already parsed; redirect flooring is a
behavioural tightening covered by the pre-1.0 policy.
