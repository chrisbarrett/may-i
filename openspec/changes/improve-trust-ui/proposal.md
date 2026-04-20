## Why

When may-i blocks a command due to untrusted loaded rules, the user gets an opaque message with no context about what they're being asked to trust. The `may-i trust` listing is equally unhelpful — a flat list of program names with NEW/CHANGED labels. Users must manually trace which config files contribute rules and read those files to understand what changed before blindly approving. This friction undermines the trust system's purpose: informed consent over third-party rule changes.

## What Changes

- **Provenance carries file paths**: `Provenance::Loaded` gains the source file path so rules can be traced back to their origin.
- **Trust store preserves canonical forms**: The on-disk trust store expands from `{program: hash}` to include the canonical rule s-expressions, enabling old-vs-new diffs on change.
- **TrustHashes carries metadata**: `compute_trust_hashes` retains per-program canonical forms and source file paths instead of discarding them.
- **Redesigned `may-i trust` listing**: Grouped-by-file two-column layout when all trusted; detailed view with rule content and diffs for NEW/CHANGED entries.
- **Richer block messages**: Eval and hook block messages include source file paths so users know where untrusted rules originate.
- **Extended JSON output**: Trust listing and block responses include source files, canonical forms, and (for changed) previous forms.

## Capabilities

### New Capabilities

- `trust-provenance`: Track and surface the source file path for loaded rules and defines through the trust pipeline.
- `trust-ui-listing`: Redesigned `may-i trust` listing with grouped-by-file layout, rule content display, and change diffs.
- `trust-block-context`: Improved block messages in eval and hook modes that include source file provenance.

### Modified Capabilities

## Impact

- `crates/core/src/ast.rs` — `Provenance` enum gains data field; all pattern matches on `Provenance::Loaded` must update.
- `crates/config/src/io.rs` — `expand_loads` propagates file paths into provenance.
- `crates/engine/src/trust.rs` — `TrustHashes` struct expanded; `compute_trust_hashes` retains metadata.
- `src/trust_store.rs` — Store format expanded with backward-compatible loading.
- `src/cmd_trust.rs` — Complete rewrite of listing/display logic.
- `src/cmd_eval.rs` — `check_trust_for_command` enriched with file paths.
- `src/cmd_claude_code_hook.rs` — `check_trust` enriched with file paths.
- `tests/trust_integration.rs` — Tests updated for new output format and metadata.
