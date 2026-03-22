## Why

The may-i codebase currently maintains two separate s-expression parsers: a CST (Concrete Syntax Tree) parser that preserves trivia (whitespace, comments) and a simpler Sexpr AST parser that discards trivia. This redundancy creates maintenance burden and has caused real bugs where the parsers diverge in behavior - specifically, the CST serializer produces output that the Sexpr parser cannot parse.

Consolidating on a single parser eliminates this class of bugs, reduces code duplication (~700 lines), and simplifies the mental model: CST is the canonical representation, and Sexpr becomes a view type derived from it.

## What Changes

- **Remove Sexpr parser** (crates/sexpr/src/sexpr.rs): Delete the redundant parser implementation (~700 lines)
- **Add CST → Sexpr conversion**: Implement `CstNode::to_sexpr()` method to derive Sexpr from CST
- **Update `parse()` function**: Make `may_i_sexpr::parse()` use CST parser internally, then convert to Sexpr for backward compatibility
- **Keep Sexpr type**: Retain `Sexpr` enum as a view type for v2/config module (no API changes in consuming code)
- **Add generative tests**: Property-based tests for CST roundtrip correctness

## Capabilities

### New Capabilities
- `cst-roundtrip`: CST serialization and parsing must be consistent and reversible

### Modified Capabilities
- None (no spec-level requirement changes; this is purely an implementation consolidation)

## Impact

- **crates/sexpr**: Parser consolidation, ~700 lines deleted, ~50 lines added
- **crates/config**: No changes required (continues using `Sexpr` via `parse()`)
- **All existing tests**: Continue to pass (no behavior changes)
- **Test coverage**: Improved with generative testing of CST roundtrips
