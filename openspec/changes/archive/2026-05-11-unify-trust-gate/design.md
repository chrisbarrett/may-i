## Context

Three CLI commands consult Trust before evaluating a command. Each duplicates
some subset of: store loading, advisory rendering, JSON block construction,
program-name extraction, and untrusted-rule filtering. The current seam
splits these between `src/trust_advisory.rs` (compute + render side effects)
and `src/trust_store.rs` (storage), leaving orchestration on the caller. Two
copies of program-name extraction and three copies of "load store + filter"
are visible.

Trust behaviour itself is fully specified by existing specs
(`trust-block-context`, `trust-advisory-boxes`, `trust-provenance`,
`per-rule-trust`). The shape of those outputs must not change.

## Goals / Non-Goals

**Goals:**
- One module owns Trust orchestration; CLI commands consult it once per
  invocation.
- Program-name extraction lives in exactly one place.
- Advisory and block construction are pure (return values), not side-effecting
  prints.
- No change to user-visible output for any existing input.

**Non-Goals:**
- Changing the trust hash algorithm, store format, or per-rule trust semantics.
- Changing the JSON / hook response shapes.
- Reworking `cmd_trust` (the trust-administration command), which legitimately
  uses `TrustStore` and related helpers directly.
- Removing the Loaded vs PrimaryConfig provenance distinction.

## Decisions

### Decision: One entry point, three modes
`trust_gate::evaluate(config, command, mode) -> GateOutcome` where
`GateMode` is `Text | Json | Hook`. A single function rather than three
mode-named functions keeps the seam tight and makes the differences visible
inside the gate (as `match mode` arms) rather than spread across CLI
modules.

Alternative considered: separate `text_gate`, `json_gate`, `hook_gate`. Rejected
because the differences between modes are small (advisory shape, block
serialisation) and visibility-into-one-place is the goal.

### Decision: `GateOutcome::Proceed` carries the filtered config
Rather than returning a "filter callback" or making the caller re-call
`filter_trusted_rules`, the gate returns the filtered config directly. This
removes the last reason for callers to know about the trust store.

Alternative: return a `TrustVerdict` and have callers apply it. Rejected — keeps
filtering as a caller responsibility, which is exactly the friction this
change removes.

### Decision: Advisory returned as `Layout`, not printed
`trust_advisory::render` currently writes to stdout/stderr. The gate returns
`Option<Layout>`; the caller writes it where appropriate (stderr for
`cmd_eval`, stderr for `cmd_check`). This:
- separates "what the advisory says" from "where it lands";
- lets `cmd_eval` continue routing the advisory to stderr ahead of trace
  output without coupling the gate to a `Write` impl;
- aligns with the existing `migration_note` pattern (`Option<Layout>`).

### Decision: Trust-store load failures degrade silently
Today's behaviour: `if let Some(store_path) = ... && let Ok(load_result) = ...`
— failures fall through to "no filter, no advisory, proceed". The gate
preserves this. Reason: trust filtering is opportunistic from the eval
pipeline's perspective; a missing store is normal on first run.

`cmd_trust` keeps its own explicit error handling for store IO since it is the
administrative path.

### Decision: `trust_advisory` and `trust_store` stay as internal modules
They become implementation details of the gate, exposed at most as
`pub(crate)`. `cmd_trust` and the hook crate boundary force some symbols to
remain `pub` for now; the gate is the only consumer that benefits from
reduction.

### Decision: Program-name extraction unified verbatim
The gate uses today's algorithm exactly: `split_whitespace().next()` then
`rsplit('/').next()`. No correctness fix bundled in. Any divergence from this
(e.g., honouring quoting, env-prefix handling) is a separate change.

## Risks / Trade-offs

- **Risk: hidden behavioural drift between modes during refactor.**
  Mitigation: snapshot existing CLI outputs for representative inputs before
  the refactor; replay after to verify byte-equality. Use
  `tests/snapshots/` if present, or new fixtures.

- **Risk: the gate becomes a god module if scope creeps.**
  Mitigation: bind scope via the spec — the gate exposes one function and
  one outcome enum. Trust hashing, store IO, canonical-form serialisation
  remain in their current modules.

- **Trade-off: `GateMode::Text` returning a `Layout` requires the gate to
  depend on the `output`/`layout` types.** Acceptable: those types are already
  the project's lingua franca for advisory boxes.

- **Trade-off: removing direct calls to `trust_advisory::render` from
  `cmd_eval` and `cmd_check` is a churn-y rename.** Acceptable: once.

## Migration Plan

1. Build the gate alongside existing code; tests cover each `GateMode` with
   fabricated configs and trust stores.
2. Migrate one caller at a time (`cmd_claude_code_hook` first — smallest;
   `cmd_eval` last — most complex). Snapshot tests at each step.
3. Demote `trust_advisory::render` and `filter_trusted_rules` to
   `pub(crate)` once no CLI module calls them directly.
4. Delete the duplicated program-name extraction in the call sites.

Rollback: the gate is purely additive until the third call site is migrated;
any caller can be reverted to direct trust orchestration if a bug surfaces.

## Open Questions

- Should `GateOutcome::Block` carry the engine `EvalResult` shape or stay
  minimal? Today the hook constructs an `EvalResult` to render the response;
  proposal keeps the gate minimal and lets the caller assemble the response.
  Confirm during implementation.
- Where does the unit test for the gate live — `tests/trust_gate.rs` or
  inline `#[cfg(test)]`? Default to inline unless integration coverage is
  preferable.
