## 1. Provably-constant env analysis

- [x] 1.1 Write failing shell-parser tests: `BIN=./x; $BIN run` → env `{BIN: "./x"}`; `BIN=$(which x)` → `{}`; `B=a; B=b` → `{}`; assignment inside `if`/loop/function → `{}`; loop variable → `{}`.
- [x] 1.2 Add the analysis: structural walk returning `HashMap<String,String>` of variables with exactly one static-literal assignment, never reassigned/`unset`, not inside a conditional/loop/function body. Reuse `resolve_param_op` for RHS resolution.
- [x] 1.3 Cover `export VAR=lit` as an assignment; confirm prefix assignment (`VAR=lit cmd`) does not feed command-name resolution.

## 2. Resolve command names in decompose

- [x] 2.1 Write failing decompose tests: a first word that is a single `$VAR`/`${VAR}` with a constant in the env yields `SimpleCommand { command: <resolved> }`; an unresolved one still yields `DynamicCommand`.
- [x] 2.2 In `decompose`, when the first word is dynamic and is a lone variable expansion, resolve against the D1 env; emit `SimpleCommand` on success, else `DynamicCommand` (unchanged). Leave argument words untouched.

## 3. Engine scenarios

- [x] 3.1 Write failing engine tests for the five spec scenarios: constant resolves (`./target/debug/may-i`, reason names the resolved command, not `$BIN`); `R=rm; $R -rf /danger` asks via the `rm` rule; substitution-assigned stays dynamic; loop variable stays dynamic; reassignment stays dynamic.
- [x] 3.2 Add a guard test: a command with no variable command name is byte-for-byte unchanged in decision and reason.

## 4. End-to-end & docs

- [x] 4.1 Run the motivating loop (`BIN=…; for c in …; do $BIN eval … "$c"; done`) in hook mode; confirm `$BIN` resolves while `$c` arguments remain dynamic/opaque as expected.
- [x] 4.2 `cargo fmt`; run `cargo tarpaulin`, inspect `lcov.info` for uncovered branches in the analysis/resolution paths.
- [x] 4.3 Check in any new `proptest-regressions/` files.
