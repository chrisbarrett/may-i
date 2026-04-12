## 1. AST Decomposition

- [x] 1.1 Add `extract_simple_commands` as public API on `Command` (currently test-only in shell-parser lib.rs) — returns `Vec<&SimpleCommand>` by recursing through `children()`
- [x] 1.2 Add `Word::is_dynamic()` method — returns true if any part is Parameter, CommandSubstitution, Backtick, Arithmetic, Glob, or Opaque
- [x] 1.3 Add `Word::extract_embedded_commands()` method — returns `Vec<&str>` of command strings from CommandSubstitution, Backtick, and ProcessSubstitution parts, recursing into DoubleQuoted inner parts
- [x] 1.4 Write unit tests for `extract_simple_commands` covering Pipeline, And, Or, Sequence, Background, Subshell, BraceGroup, If, For, Loop, Case, FunctionDef, Redirected, Assignment
- [x] 1.5 Write unit tests for `Word::is_dynamic()` covering all WordPart variants
- [x] 1.6 Write unit tests for `Word::extract_embedded_commands()` including nested substitutions

## 2. Unified Evaluation Function

- [x] 2.1 Define `EvalUnit` enum in `crates/engine/src/eval/` — variants: `SimpleCommand { command, args }`, `EmbeddedCommand { source }`, `DynamicCommand { reason }`
- [x] 2.2 Implement `decompose(cmd: &Command) → Vec<EvalUnit>` — walks AST via `extract_simple_commands`, checks `is_dynamic()` on first word, extracts embedded commands from all word parts
- [x] 2.3 Implement `evaluate_command(input: &str, config, facts) → Result<EvalResult>` — parses input, calls `decompose`, evaluates each unit, aggregates with `max(decisions)`. Embedded commands recursively call `evaluate_command` with depth limit.
- [x] 2.4 Add fold variant: `evaluate_command_with_fold` that threads an `EvalFold` through per-unit evaluation and emits segment headers
- [x] 2.5 Write unit tests for `decompose` covering compound commands, embedded substitutions, dynamic command names, and empty input
- [x] 2.6 Write unit tests for `evaluate_command` covering the test vectors from the spec (compound, embedded, dynamic, empty)

## 3. Entry Point Migration

- [x] 3.1 Update `cmd_claude_code_hook.rs` to use `evaluate_command` instead of `parse_command_args` + `evaluate`
- [x] 3.2 Update `cmd_eval.rs` JSON path to use `evaluate_command_with_fold` instead of `parse_command_args` + `evaluate_with_fold`
- [x] 3.3 Update `cmd_eval.rs` pretty path to use `evaluate_command_with_fold` for decisions, retain `segment()` only for display colorization
- [x] 3.4 Remove `parse_command_args` from `cmd_eval.rs` (no longer needed as public API)
- [x] 3.5 Update or remove `evaluate_segments` — either delete or reduce to a thin wrapper that calls `evaluate_command_with_fold` + `segment()` for colorization

## 4. Trace Output

- [x] 4.1 Add `fn embedded_command(&mut self, source: &str, decision: Decision)` to the `EvalFold` trait with a default no-op implementation
- [x] 4.2 Implement `embedded_command` in `TracingFold` to emit trace entries for embedded substitution evaluations
- [x] 4.3 Add trace entries for dynamic command name detections (`:ask` with reason)
- [x] 4.4 Update JSON trace serialisation to include embedded command and dynamic command entries

## 5. Integration Tests

- [x] 5.1 Integration test: `echo hello && rm -rf /` with echo allowed → `:ask` (verifies hook path fix)
- [x] 5.2 Integration test: `echo $(rm -rf /)` with echo allowed + rm denied → `:deny`
- [x] 5.3 Integration test: `$EDITOR file.txt` → `:ask` with dynamic reason
- [x] 5.4 Integration test: `if true; then rm -rf /; fi` with rm denied → `:deny`
- [x] 5.5 Integration test: empty string → `:ask`
- [x] 5.6 Integration test: verify JSON and non-JSON paths return same decision for compound commands
- [x] 5.7 Integration test: deeply nested substitution `$(echo $(echo $(rm /)))` respects recursion depth limit
