## 1. Failing tests first

- [x] 1.1 Integration test: bypass reproducer.
      `(rule "sudo" (authorise #cmd))` + `(rule "bash" (authorise #cmd))` +
      `(rule "rm" (deny))`. Input
      `sudo bash -c "echo a && rm -rf /tmp/x"` → `:deny`. Must FAIL on
      current main; PASS after the fix.
- [x] 1.2 Integration test: `:via`-gated deny survives wrapper chain.
      `(rule "sudo" (authorise #cmd))` + `(rule "bash" (authorise #cmd))` +
      `(rule "rm" (when (fact? [:via "bash"]) (deny "rm via bash")))`.
      Input `sudo bash -c "echo a && rm /tmp/x"` → `:deny "rm via bash"`.
      The `:via "bash"` fact MUST be set on the inner rm — proving the
      recursion routed through bash's frame rather than emerging at sudo's
      frame.
- [x] 1.3 Integration test: `sudo sh -c "if true; then rm /; fi"` →
      `:deny` (the scenario in the existing parser-bindings spec that
      currently isn't satisfied).
- [x] 1.4 Integration test: `ssh host "ls && rm /tmp/x"` → `:deny` via
      `ssh`'s `(rest …)` chained into `sh -c` (use a stub `(rule "ssh" (authorise #cmd))`).
- [x] 1.5 Regression: existing `sudo rm -rf /tmp/x` test passes
      unchanged. (All tokens metacharacter-free → token-list path agrees
      with old join-and-parse.)
- [x] 1.6 Token-list with dynamic `tokens[0]`: returns `:ask` with a
      reason naming the dynamic command name.
- [x] 1.7 Empty token-list (`(rest #cmd)` with no tail tokens) remains
      a no-match.

## 2. Confirm BindingValue plumbing

- [x] 2.1 Confirm `Effect::Authorise`'s call site can observe
      `BindingValue::{Token, Tokens, Unbound}` distinctly. If the site
      currently only ever sees `as_joined()`, expose the underlying
      value (or pattern-match directly) — `BindingValue` is already
      `pub` and `Clone`.
- [x] 2.2 Audit other `as_joined()` consumers (`(matches? #var …)`,
      `(with-facts …)`, predicates) to ensure their string semantics
      stays untouched. Only the recursion dispatch changes shape.

## 3. Helper: `evaluate_authorised_tokens`

- [x] 3.1 Add `evaluate_authorised_tokens(tokens: &[String], config,
      facts, fold, depth, via) -> Result<EvalResult>` to
      `crates/engine/src/eval/command.rs`. Same depth/via/limit
      contract as `evaluate_authorised_string`.
- [x] 3.2 Body:
      - depth guard (same constant);
      - empty `tokens` → `:ask` with empty-command reason
        (callers short-circuit before this for no-match semantics);
      - `tokens[0]` empty or contains shell metacharacters → `:ask`
        with a dynamic-command-name reason;
      - else: push `:via` into facts; call
        `evaluate_at_depth(tokens[0], &tokens[1..], config, facts,
        fold, depth)`. Return its result directly. No decomposition,
        no parse.
- [x] 3.3 Decide which characters count as "shell metacharacter" for
      the `tokens[0]` guard. Recommendation: any of
      `[ \t\n;|&()<>"'$\\``]`, plus `=` (assignment-prefix). Keep the
      check in one helper so the property test can reuse it.

## 4. Dispatch at recursion sites

- [x] 4.1 Move the empty-binding short-circuit out of the
      `Effect::Authorise` arm and into `recurse_into_bound_command`.
      The arm passes the `BindingValue` (or the binding name) through;
      the helper inspects the kind.
- [x] 4.2 In `recurse_into_bound_command`, match on the
      `BindingValue`:
      - `BindingValue::Unbound` or empty → `effect_nil`.
      - `BindingValue::Token(s)` → call
        `evaluate_authorised_string(&s, …)`.
      - `BindingValue::Tokens(v)` → call
        `evaluate_authorised_tokens(&v, …)`.
      Surrounding `fold.begin_recursive_eval()` and
      `effect_terminal(…)` wrappers are shared across both branches.
- [x] 4.3 `evaluate_tail_authorise_fold` (`ArgPattern::Tail`): the
      tail slice is already `&[String]`. Route it through
      `evaluate_authorised_tokens` instead of joining + calling
      `evaluate_authorised_string`. Preserve the existing
      `effect_arg_continuation` wrapper.
- [x] 4.4 `recurse_into_inner_command` (`ParameterForm::Authorise`)
      and `entry.rs`'s `ParameterTreatment::Authorise` pre-rule
      recursion: NO change. Captured value is always a single string.
- [x] 4.5 Delete any newly-orphaned helpers or imports.

## 5. Property tests

- [x] 5.1 Equivalence proptest in `command.rs`: for any token list
      where every element matches the metacharacter-free regex,
      `evaluate_authorised_tokens(tokens)` and
      `evaluate_authorised_string(tokens.join(" "))` agree on the
      decision. Encodes the regression-safety guarantee.
- [x] 5.2 Bypass proptest: for any well-formed inner command `c` such
      that evaluating `bash -c c` directly produces a decision `d`,
      evaluating `sudo bash -c c` under the wrapper rule set must
      produce the same decision `d` (and the inner facts must include
      `:via "sudo"` and `:via "bash"`).

## 6. Live spec edits

- [x] 6.1 Apply the `parser-bindings` delta (string-vs-token-list split
      and new scenarios) to the live spec.
- [x] 6.2 Apply the `parameter-many-till` delta (clarifying sentence
      about the asymmetry) to the live spec.
- [x] 6.3 Re-read the scenario at the existing
      `parser-bindings` requirement (`sudo sh -c "if true; then rm /;
      fi"` → `:deny`). Confirm it now passes — the spec asserted this
      contract previously, but the implementation did not satisfy it
      until this change.

## 7. Coverage and oracle

- [x] 7.1 `cargo fmt`, `cargo clippy`, `cargo test --workspace`.
- [x] 7.2 User oracle: `may-i eval 'sudo bash -c "echo a && rm /tmp/x"'`
      with the bypass-reproducer config — verify `:deny`. Save the
      trace output to confirm the inner `rm` evaluates with
      `:via "sudo"` and `:via "bash"` both present.
- [x] 7.3 `cargo tarpaulin` sweep on
      `crates/engine/src/eval/command.rs` and `effects.rs` — confirm
      the new helper and dispatch branches are covered.

## 8. Release notes

- [x] 8.1 Add a security-fix note to whatever changelog / release
      surface the project uses. Frame: "`(authorise #var)` over
      `(rest)`-style bindings could be bypassed by inner argv tokens
      containing shell metacharacters. Users with wrapper rules
      (sudo, ssh, xargs, mise, nix-shell, …) should re-review their
      policies — previously-`:allow` outcomes for compound inner
      commands may now correctly resolve to `:ask` or `:deny`."
- [x] 8.2 Bump version in `Cargo.toml` per the project's release
      convention (patch-level: this is a fix, not a feature).
