## Why

Currently, `(check)` forms can only appear inside `(rule ...)` definitions. This limits test expressiveness because:
1. Tests are coupled to specific rules, making it hard to test cross-cutting concerns
2. Users cannot write integration tests that verify the entire rule engine's behavior
3. Tests must be co-located with rules even when they test broader system properties

Adding top-level `(check)` support enables standalone tests that evaluate against the complete rule set, improving test organization and expressiveness.

## What Changes

- **New top-level form**: Allow `(check ...)` as a top-level form in config files, alongside `rule`, `wrapper`, `defcontext`, and `safe-env-vars`
- **Config structure**: Extend `Config` type to include a `checks: Vec<Check>` field for top-level checks
- **Parser update**: Add `"check"` case to top-level form parser in `crates/config/src/parse/mod.rs`
- **Check execution**: Update `run_checks()` in `crates/engine/src/check.rs` to include top-level checks alongside embedded rule checks
- **No breaking changes**: Existing configs with embedded checks continue to work unchanged

## Capabilities

### New Capabilities
- `top-level-checks`: Support for `(check ...)` forms at the top level of config files, enabling standalone tests that evaluate commands against the complete rule set

### Modified Capabilities
- None. This is a pure addition with no changes to existing spec requirements.

## Impact

- **Parser** (`crates/config/src/parse/mod.rs`): Add top-level check parsing
- **Core types** (`crates/core/src/types.rs`): Add `checks` field to `Config`
- **Engine** (`crates/engine/src/check.rs`): Include top-level checks in check execution
- **CLI** (`src/cmd_check.rs`): May need to update output to distinguish top-level from embedded checks
- **Documentation**: Update config format documentation to describe top-level check syntax
