## 1. Collect defined function names

- [ ] 1.1 Write a failing shell-parser test: a collector returns `{materialise, run_seeds}` for a command defining both (and `{}` for one defining none), covering `name()` and `function name` forms and nested defs.
- [ ] 1.2 Add the collector in `crates/shell-parser` (sibling to `extract_simple_commands`), walking `children()` for `FunctionDef` names.

## 2. Classify internal calls in decompose

- [ ] 2.1 Write failing decompose tests: `materialise() { echo hi; }; materialise foo` yields the body `echo` unit plus a `LocalFunctionCall { name: "materialise" }` for the call (not a `SimpleCommand`).
- [ ] 2.2 Write a failing test that embedded substitutions in a local call's args are still extracted: `f() { :; }; f "$(rm -rf /)"` still yields the `rm` embedded unit.
- [ ] 2.3 Add `EvalUnit::LocalFunctionCall { name, span }`; thread the defined-name set into `decompose` and classify matching non-dynamic command names as that unit (D1). Keep argument substitution extraction.

## 3. Evaluate internal calls as allow

- [ ] 3.1 Write failing engine tests: the four spec scenarios — call does not ask (`:allow`); body still authorised (`rm` asks); forward reference internal; non-defined name (`kubectl`) still asks.
- [ ] 3.2 In `command.rs`, evaluate `LocalFunctionCall` as `:allow` with a traceable reason; ensure it does not raise the aggregate or emit `No rule for command …`.

## 4. End-to-end & docs

- [ ] 4.1 Run the motivating script in hook mode; confirm the three function calls no longer ask (residual asks limited to the dynamic `$TGBIN` command, which is out of scope).
- [ ] 4.2 Confirm the trace renders an intelligible line for an internal call.
- [ ] 4.3 `cargo fmt`; run `cargo tarpaulin`, inspect `lcov.info` for uncovered branches in the new paths.
- [ ] 4.4 Check in any new `proptest-regressions/` files.
