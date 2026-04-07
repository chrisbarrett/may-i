## Why

The migration module rewrites v1 config syntax to canonical syntax via 15 CST rewrite rules applied until convergence. Currently, correctness is verified only by hand-written unit tests for each rule and oracle snapshot tests against the user's config. There are no property tests verifying the fundamental algebraic invariant: `eval(e) = eval(migrate(e))`. A single rewrite rule that subtly changes semantics (e.g., dropping a predicate, reordering branches) would silently corrupt user configs.

## What Changes

- Add proptest-based property tests for the migration pipeline covering:
  - **Canonical fixed-point**: migration is a no-op on already-canonical configs
  - **Idempotency**: `migrate(migrate(e)) = migrate(e)`
  - **Parseability**: migration output always parses with the canonical parser
  - **Eval preservation**: v1 configs evaluate identically before and after migration
  - **Convergence**: migration terminates for arbitrary inputs
- Add string-based proptest generators for canonical and v1 config syntax
- Add dev-dependencies (`proptest`, `may-i-engine`) to the config crate

## Capabilities

### New Capabilities
- `migration-property-tests`: Property-based test suite verifying migration preserves evaluation semantics, is idempotent, always produces parseable output, and converges

### Modified Capabilities

## Impact

- `crates/config/Cargo.toml` — new dev-dependencies
- `crates/config/src/migrate/` — new test module with generators and property tests
- No runtime code changes; test-only
