## Why

The v1 configuration format supported fact binding in wrapper patterns like `(positional [:ssh/host *] :command+args)`, which captured positional arguments and made them available as facts in the context. During migration to v2, this capability was lost—the migration code strips `[:ssh/host *]` down to just `*`, losing the binding information. This breaks use cases like SSH host filtering where the host needs to be captured and checked in subsequent rules.

## What Changes

- **Add `Keyword` type** to core types: A validated string wrapper that ensures keywords start with `:` for correctness by construction
- **Add `Expr::Bind` variant**: New expression variant that combines a keyword with an inner expression pattern, representing "match this pattern and bind the matched value to this fact key"
- **Update v2 pattern parser**: Support bracket notation `[:keyword]` and `[:keyword EXPR]` in positional argument expressions (currently rejected as "do not support bracket syntax")
- **Update expression evaluator**: `match_expr` needs to return both match result AND bound facts when encountering `Expr::Bind`
- **Update migration code**: Preserve `[:keyword EXPR]` bindings instead of converting to just `EXPR`

## Capabilities

### New Capabilities

- `v2-expr-fact-binding`: Fact binding within v2 expression patterns using bracket notation `[:keyword EXPR]`

### Modified Capabilities

- `v1-to-v2-migration`: Migration now preserves fact bindings in positional patterns instead of stripping them

## Impact

- **Core types** (`crates/core/src/types.rs`): Add `Keyword` type and `Expr::Bind` variant
- **Config parser** (`crates/config/src/v2/pattern.rs`): Parse bracket syntax as `Expr::Bind`
- **Engine evaluator** (`crates/engine/src/v2/eval.rs`): Handle `Expr::Bind` in pattern matching
- **Migration** (`crates/config/src/v2/migrate.rs`): Stop stripping bindings, preserve `[:keyword EXPR]`
- **12 failing tests** already written that define expected behavior

