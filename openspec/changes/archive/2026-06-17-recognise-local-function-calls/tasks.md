## 1. Collect defined function names

- [x] 1.1 Write a failing shell-parser test: a collector returns `{materialise, run_seeds}` for a command defining both (and `{}` for one defining none), covering `name()` and `function name` forms and nested defs.
- [x] 1.2 Add the collector in `crates/shell-parser` (sibling to `extract_simple_commands`), walking `children()` for `FunctionDef` names.

## 2. Classify internal calls in decompose

- [x] 2.1 Write failing decompose tests: `materialise() { echo hi; }; materialise foo` yields the body `echo` unit plus a `LocalFunctionCall { name: "materialise" }` for the call (not a `SimpleCommand`).
- [x] 2.2 Write a failing test that embedded substitutions in a local call's args are still extracted: `f() { :; }; f "$(rm -rf /)"` still yields the `rm` embedded unit.
- [x] 2.3 Add `EvalUnit::LocalFunctionCall { name, span }`; thread the defined-name set into `decompose` and classify matching non-dynamic command names as that unit (D1). Keep argument substitution extraction.

## 3. Evaluate internal calls as allow

- [x] 3.1 Write failing engine tests: the four spec scenarios — call does not ask (`:allow`); body still authorised (`rm` asks); forward reference internal; non-defined name (`kubectl`) still asks.
- [x] 3.2 In `command.rs`, evaluate `LocalFunctionCall` as `:allow` with a traceable reason; ensure it does not raise the aggregate or emit `No rule for command …`.

## 4. End-to-end & docs

- [x] 4.1 Run the motivating script in hook mode; confirm the three function calls no longer ask (residual asks limited to the dynamic `$TGBIN` command, which is out of scope).
- [x] 4.2 Confirm the trace renders an intelligible line for an internal call.
- [x] 4.3 `cargo fmt`; run `cargo tarpaulin`, inspect `lcov.info` for uncovered branches in the new paths.
- [x] 4.4 Check in any new `proptest-regressions/` files.

## 5. Liveness-aware classification (tighten D2)

- [x] 5.1 Write failing classifier tests: a top-level call before its definition is NOT a live internal call; a call after `unset -f` is NOT; mutual recursion / helper-defined-below (defined before the activation point) ARE; a body forward-reference invoked before its definition is NOT.
- [x] 5.2 Add a span-keyed liveness classifier in `decompose` — Tier 1 (top-level order + `unset -f` tracking) and Tier 2 (body establishment via activation point). Factor a shared `resolved_command_name` helper so the classifier and `decompose_simple_command` agree on the resolved name (incl. `$BIN` constant resolution).
- [x] 5.3 Thread the classifier's internal-call span set into `decompose`; classify a simple command as `LocalFunctionCall` iff its span is in that set (replacing flat name-set membership).
- [x] 5.4 Write failing engine scenario tests for the three new spec scenarios (pre-def external, post-`unset` external, body-forward-ref external); confirm mutual recursion and all existing scenarios still pass.
- [x] 5.5 Conservative fallbacks: definitions inside `if`/`while`/`case`/subshell/brace-group do not establish internal status; a dynamic `unset -f "$x"` clears the live set. Cover with tests.
- [x] 5.6 `cargo fmt`; full suite + `cargo tarpaulin` on the new branches; check in any new `proptest-regressions/`.
