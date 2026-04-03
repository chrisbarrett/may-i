## Why

A comprehensive pre-release code review identified critical bugs, spec
deviations, and unspecified functionality that should be addressed before
cutting a release. The most impactful findings are: the Claude Code hook entry
point bypasses predicate resolution and uses naive command parsing; the
evaluator panics on unresolved predicates instead of returning an error; `Or`
expression matching leaks bindings from non-first alternatives; and several
implementation details diverge from their specs.

## What Changes

- **Fix Claude Code hook**: add predicate resolution and use the shell parser
  instead of `split_whitespace`. Also spec this entry point which is currently
  undocumented.
- **Eliminate evaluator panic**: return a `Result` when encountering unresolved
  `Named` predicates instead of calling `panic!`.
- **Fix `Or` binding semantics**: short-circuit `match_expr_with_binding` on
  first matching alternative to prevent fact leakage from later branches.
- **Fix `fact?` serialization**: `Predicate::to_doc()` emits `has` but should
  emit `fact?` to match the canonical DSL syntax.
- **Fix `Cond` short-circuit**: stop evaluating predicates for branches after a
  match has been found.
- **Type-tighten `ContextFacts`**: use `Keyword` keys instead of bare `String`
  to match the runtime-context spec.

## Capabilities

### New Capabilities
- `claude-code-hook`: Specifies the Claude Code MCP hook entry point — JSON
  stdin protocol, auto-created facts, required preprocessing (resolution, shell
  parsing), and output format.
- `evaluator-error-handling`: Specifies error propagation requirements for the
  evaluation engine — unresolved references must produce errors, not panics.

### Modified Capabilities
- `runtime-context`: Require `Keyword`-typed keys in `ContextFacts` and
  `FactQuery` to match the existing spec's stated representation.
- `expr-combinator-matching`: Require `Or` in expression matching to
  short-circuit on first match when bindings are involved.
- `configuration-language`: Require `fact?` keyword in `to_doc` serialization;
  require `Cond` to stop evaluating predicates after a branch matches.

## Impact

- **`crates/core`**: `ContextFacts` signature changes from `String` to
  `Keyword` keys; `FactQuery` key fields change type. `Predicate::to_doc()`
  output changes. **BREAKING** for any downstream code constructing
  `ContextFacts` or `FactQuery` with bare strings.
- **`crates/engine`**: `evaluate_predicate` returns `Result` instead of
  panicking; `match_expr_with_binding` short-circuits `Or`; `Cond` evaluation
  loop stops after match.
- **`src/cmd_claude_code_hook.rs`**: Adds `validate_and_resolve` call and
  switches to shell parser.
- **`crates/config`**: Callers of `ContextFacts` in test helpers must use
  `Keyword`.
