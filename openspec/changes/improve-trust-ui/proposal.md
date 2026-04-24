## Why

When may-i blocks a command due to untrusted loaded rules, the user gets an opaque message with no context about what they're being asked to trust. The `may-i trust` listing is equally unhelpful — a flat list of program names with NEW/CHANGED labels. Users must manually trace which config files contribute rules and read those files to understand what changed before blindly approving. This friction undermines the trust system's purpose: informed consent over third-party rule changes.

## What Changes

- **Provenance carries file paths**: `Provenance::Loaded` gains the source file path so rules can be traced back to their origin.
- **Trust store preserves canonical forms**: The on-disk trust store expands from `{program: hash}` to include the canonical rule s-expressions, enabling old-vs-new diffs on change.
- **TrustHashes carries metadata**: `compute_trust_hashes` retains per-program canonical forms and source file paths instead of discarding them.
- **Redesigned `may-i trust` listing**: Grouped-by-file two-column layout when all trusted; detailed view with rule content and diffs for NEW/CHANGED entries.
- **Richer block messages**: Eval and hook block messages include source file paths so users know where untrusted rules originate.
- **Extended JSON output**: Trust listing and block responses include source files, canonical forms, and (for changed) previous forms.
- **Per-rule trust granularity**: Trust decisions (approve/ignore) are made per individual rule, not per program. Ignored rules are filtered out of the evaluation pipeline as if they don't exist. Pending (unreviewed) rules are also inactive until explicitly approved.
- **Interactive `git add -p` style review**: `may-i trust` presents each rule one at a time with `[y] approve  [n] ignore  [s] skip  [q] quit` keybindings. Changed rules show a diff of old vs new canonical form.

## Capabilities

### New Capabilities

- `trust-provenance`: Track and surface the source file path for loaded rules and defines through the trust pipeline.
- `trust-ui-listing`: Redesigned `may-i trust` listing with grouped-by-file layout, rule content display, and change diffs.
- `trust-block-context`: Improved block messages in eval and hook modes that include source file provenance.
- `per-rule-trust`: Per-rule trust granularity with approve/ignore/skip interactive review flow.

### Modified Capabilities

## Impact

- `crates/core/src/ast.rs` — `Provenance` enum gains data field; all pattern matches on `Provenance::Loaded` must update.
- `crates/config/src/io.rs` — `expand_loads` propagates file paths into provenance.
- `crates/engine/src/trust.rs` — `TrustHashes` expanded to per-rule metadata; `compute_trust_hashes` produces per-rule entries. Eval pipeline gains trust-aware rule filtering.
- `src/trust_store.rs` — Store format v3: per-rule entries keyed by canonical form hash, each with `approved` or `ignored` status. Migration from v2 (per-program) treats all existing approvals as approved at rule level.
- `src/cmd_trust.rs` — Interactive review rewritten for per-rule `y/n/s/q` flow.
- `src/interactive.rs` — `interactive_approve` replaced with `interactive_review` supporting three-way decisions per rule.
- `src/cmd_eval.rs` — Eval filters out ignored and pending rules before evaluation.
- `src/cmd_claude_code_hook.rs` — Hook filters out ignored and pending rules; blocks only if no approved rules exist for a matched program.
- `tests/trust_integration.rs` — Tests updated for per-rule trust model.
