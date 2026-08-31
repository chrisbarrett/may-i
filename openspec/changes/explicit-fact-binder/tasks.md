## 1. Fact storage: rebinding

- [ ] 1.1 Add a failing proptest asserting that rebinding a key in `ContextFacts` replaces its value set rather than unioning, and that rebinding to no values leaves `has()` false (distinct from `insert_present`)
- [ ] 1.2 Add the rebinding operation to `crates/core/src/context.rs` alongside `merge`, keeping `merge` for the Check-block `(with-facts …)` path
- [ ] 1.3 Rewrite the `:via` push sites (`crates/engine/src/eval/command.rs:295`, `:774`, `crates/engine/src/eval/entry.rs:142`) to bind `:via` to its previous value plus the Carrier name, so accumulation is expressed in the rebinding primitive rather than in `insert_scalar`
- [ ] 1.4 Proptest: `:via` accumulation across nested Carriers is unchanged by 1.3

## 2. `(let-facts …)` form

- [ ] 2.1 Failing test in `tests/binding_recursion.rs`: `(rule "ssh" (let-facts [[:ssh/host #host]] (authorise #cmd)))` makes `:ssh/host` visible to the `sudo` rule
- [ ] 2.2 Add the AST node and loader support for `(let-facts BINDINGS BODY)`, accepting `#var`, literal string, and omitted value; add it to the rule-body form list in `crates/config/src/effect.rs:135`
- [ ] 2.3 Evaluate `let-facts` by rebinding each key for the body's evaluation context, including across `(authorise …)`
- [ ] 2.4 Implement total rebind: an unbound `#var` removes the key for the body; the body still evaluates
- [ ] 2.5 Proptest: no enclosing value for a key is observable inside a `let-facts` body that binds it, for any nesting depth
- [ ] 2.6 Test the nested-Carrier case end to end — `ssh jump-host ssh media-server sudo …` sees only the innermost host

## 3. `(filter #var PAT)` value form

- [ ] 3.1 Failing test: `(filter #opts (regex "^ProxyCommand="))` binds only matching values
- [ ] 3.2 Add `filter` as a value-position form, rejected anywhere else
- [ ] 3.3 Proptest: `(filter #v PAT)` yields exactly the subset of `#v` satisfying `PAT`, order-independent as a set

## 4. Shape checking

- [ ] 4.1 Add shape signatures for `(let-facts …)` (`Token | Command | Collection Token`) and `(filter …)` (`Collection Token`) to `crates/engine/src/shape.rs`
- [ ] 4.2 Failing tests for both rejection cases: `Count` under `let-facts`, `Token` under `filter`, each with the diagnostic naming the binding, its shape, and what the form requires

## 5. Migration and corpus

- [ ] 5.1 Add the `bind_pattern_to_let_facts` rewrite under `crates/config/src/migrate/`, following the `rename_has_to_fact` shape
- [ ] 5.2 Snapshot tests for the three rewrite cases (`every?`, `some?`, bare wildcard) plus the left-alone argv-Pattern case
- [ ] 5.3 Proptest: the rewrite preserves comments and formatting per the CST roundtrip requirement
- [ ] 5.4 Migrate `crates/config/src/prelude.lisp`, `starter_config.lisp` and `examples/*.lisp`; run `may-i fmt` over the examples
- [ ] 5.5 Fix the dead rule in `examples/ssh-sudo-prod-demo.lisp:29-32` (`(fact? :via/sudo)` never matches; the engine writes `[:via "sudo"]`) and add a `check` block covering it

## 6. Remove the bind Pattern

- [ ] 6.1 Delete `Expr::Bind` (`crates/core/src/pattern.rs:56`) and its arms in `is_match`, `matches_any_value`, `find_effect`, `to_doc` and the Debug impl
- [ ] 6.2 Delete `captured_facts` and `collect_captures` including the `Or` re-evaluation (`crates/engine/src/eval/predicates.rs:233-289`) and `eval_body_with_captures` (`crates/engine/src/eval/effects.rs:17-28`)
- [ ] 6.3 Delete the bind arm of `match_expr_with_binding` (`crates/engine/src/eval/positional.rs:496-508`) and the `contains_bind` guard (`crates/config/src/pattern.rs:262`)
- [ ] 6.4 Replace the loader's acceptance of `[:k PAT]` in argv Patterns with a diagnostic naming `(let-facts …)` and the parser declaration needed to supply the binding
- [ ] 6.5 Remove the now-dead proptest generators and arbitrary impls for `Expr::Bind`

## 7. Outer-slice scoping fix

- [ ] 7.1 Failing test: with the Prelude `ssh` parser, `(anywhere "media-server")` matches on `ssh media-server sudo -n true`, and `(anywhere "sudo")` does not
- [ ] 7.2 Wire `bindings::parse_argv`'s residual through to `matcher_scope` (`crates/engine/src/eval/effects.rs:581`), consuming it at both discard sites (`crates/engine/src/eval/context.rs:126`, `effects.rs:1075`)
- [ ] 7.3 Proptest: for every `(flags MODE)`, the matcher-visible slice contains every declared-positional token and no `(rest …)` token
- [ ] 7.4 Audit every Prelude parser declaring positionals (`ssh`, `direnv`, others) and the example corpus for decisions changed by the wider slice; record findings in the change

## 8. Unwritten-key Advisory

- [ ] 8.1 Failing test: a config querying `(fact? :via/sudo)` loads with an Advisory suggesting `[:via "sudo"]`
- [ ] 8.2 Compute the writable key set at load time from `:via`, `let-facts` sites and Check-block `with-facts` sites
- [ ] 8.3 Emit the Advisory with the queried key, its source span, and a suggestion when a writable key differs only in namespace-versus-value spelling
- [ ] 8.4 Confirm the Advisory never blocks loading, since `--fact :k=v` admits arbitrary keys at runtime

## 9. Documentation

- [ ] 9.1 REFERENCE.md: document `(let-facts …)`, `(filter …)` and the rebinding write model; remove the bind-Pattern entries from the Patterns table and the Facts section; update the `(parser "ssh")` / `(rule "ssh")` worked example
- [ ] 9.2 REFERENCE.md:547 — state that declared-positional tokens stay visible to rule-body Patterns, now that it is true
- [ ] 9.3 CONTEXT.md: correct the Binding row, which names `(with-facts [[:k #var]] …)` as a rule-body form; record the `with-` merges / `let-` rebinds convention
- [ ] 9.4 Verify `may-i reference` output matches REFERENCE.md

## 10. Verification

- [ ] 10.1 `cargo fmt` and `cargo clippy`
- [ ] 10.2 Full test suite, including the migration snapshot corpus
- [ ] 10.3 `may-i check` over `examples/*.lisp` and the fixture corpus
- [ ] 10.4 `cargo tarpaulin`; inspect `lcov.info` for uncovered branches in the new forms
- [ ] 10.5 `scripts/validate-change-doc-sync.sh`
- [ ] 10.6 `openspec validate explicit-fact-binder --strict`
- [ ] 10.7 Confirm the motivating policy evaluates correctly end to end: `sudo` authorised under `ssh media-server` and `ssh media-server.local`, refused under `ssh media-serverX`, `ssh notmedia-server`, a foreign host, and local `sudo`
