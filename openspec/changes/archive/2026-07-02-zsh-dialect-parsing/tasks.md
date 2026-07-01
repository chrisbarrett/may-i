## 1. Dialect type and parser plumbing

- [x] 1.1 Write a failing test: `parse_with_dialect("if true; then echo hi; fi", Dialect::Zsh)` yields the same AST and empty diagnostics as `parse(…)` (shared constructs identical across dialects).
- [x] 1.2 Add `pub enum Dialect { Bash, Zsh }` with `impl Default for Dialect = Bash` to `may-i-shell-parser`; add a `dialect` field to `Parser`; add `pub fn parse_with_dialect(input, Dialect)`; make `parse(input)` delegate with `Dialect::Bash`. Green.
- [x] 1.3 Confirm every existing Bash call site and test is unchanged (no signature break); `cargo test -p may-i-shell-parser` stays green.

## 2. No-semicolon brace terminator (Zsh)

- [x] 2.1 Write failing tests: under `Dialect::Zsh`, `{ echo a }` parses as a `BraceGroup` running `echo a` with empty diagnostics; `foo() { echo hi }` parses as a `FunctionDef` named `foo`; the same inputs under `Dialect::Bash` keep today's `Warning` behaviour.
- [x] 2.2 In the simple-command argument loop, when `dialect == Zsh` and inside brace-group/function-body context, stop at a whitespace-delimited `}` token instead of absorbing it as a literal word, so `parse_list`/`parse_brace_group` see the terminator. Keep top-level `echo }` a literal argument in both dialects. Green.
- [x] 2.3 Write failing test: `cleanup() { rm -rf "$wt" }; cleanup` under `Dialect::Zsh` still surfaces the body's `rm` for evaluation (strictness preserved). Confirm green.
- [x] 2.4 Add a regression test asserting the glued-`}` case (`echo hi}`) remains a fail-safe `Warning` under `Zsh` (documented limitation, not a silent drop).

## 3. Glob qualifiers (Zsh)

- [x] 3.1 Write failing tests: under `Dialect::Zsh`, `ls **/*(.)` and `print -l *(.om[1])` parse with empty diagnostics and carry the qualifier in the glob argument word; the same inputs under `Dialect::Bash` keep today's `Error`.
- [x] 3.2 Lex/parse a `(` immediately adjacent to a preceding word containing an unquoted glob metacharacter (`*`, `?`, `[`) as a glob qualifier under `Zsh`; fold its balanced `(…)` into that word as unresolved glob text. Green.
- [x] 3.3 Write failing test: a qualified glob word is expansion-bearing — an `:allow` resting on matching it floors to `:ask` exactly as a plain glob does (strictness preserved). Confirm green.
- [x] 3.4 Add tests guarding disambiguation: `cmd (subshell)` still parses as a subshell, and `name() { … }` still parses as a function definition (neither is mistaken for a qualifier).

## 4. Dialect resolution and threading

- [x] 4.1 Resolve the dialect at the invocation boundary in `src/main.rs`: `hook` and `eval` derive it from the executing shell path basename (`zsh` → `Zsh`, else `Bash`); `check` passes `Bash`. Add unit tests for the basename mapping (`zsh`, `/usr/bin/zsh`, `bash`, empty, absent → expected dialect).
- [x] 4.2 Add the `eval --dialect <bash|zsh>` override that takes precedence over the `$SHELL`-derived value; test the override wins.
- [x] 4.3 Thread the resolved dialect through the engine so recursive re-parses of embedded command sources inherit it. Add a property test: a zsh-only construct (no-semi brace) inside `$(…)` is not diagnosed under `Dialect::Zsh`.
- [x] 4.4 Confirm the dialect is not exposed as a Fact — no `:dialect`/`:zsh` fact key, not reachable via `(fact? …)`.

## 5. Documentation

- [x] 5.1 REFERENCE.md (`may-i reference`): document the shell-dialect behaviour and the `eval --dialect` flag, or record "verified, no surface change". Required — `shell-dialect` is user-facing (`scripts/validate-change-doc-sync.sh`).
- [x] 5.2 Confirm CONTEXT.md vocabulary is unaffected (dialect is a parsing-layer implementation term; the entry-environment analogy is already documented). Record the check. — Verified: CONTEXT.md already documents the "observed ground truth, not a Fact, never reachable via `(fact? …)`" analogy for the entry environment (line 28); dialect mirrors it and is a contributor-register parsing term, so no user-vocabulary entry is required. No change.

## 6. Verification

- [x] 6.1 Add a proptest that uses `zsh -n` as an oracle: for generated inputs, `Dialect::Zsh` SHALL NOT emit an `Error`-severity diagnostic on any input `zsh -n` accepts (guarded/skipped when `zsh` is absent from `PATH`).
- [x] 6.2 `cargo fmt`; `cargo test` across the workspace green; `cargo tarpaulin` and inspect `lcov.info` for uncovered branches in the new dialect paths. — Workspace tests green (0 failures); tarpaulin 91.18%. New dialect lines covered: glob-qualifier folding (`word_parts.rs`), `at_zsh_brace_terminator`, `brace_depth` in/dec, and the `expect_brace_close` zsh branch all show non-zero hits.
- [x] 6.3 `openspec validate zsh-dialect-parsing` passes.
