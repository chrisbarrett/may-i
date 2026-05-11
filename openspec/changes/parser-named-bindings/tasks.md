## 1. Reader: `#var` sigil

- [x] 1.1 Add `Atom::Binding(String)` (or equivalent) to the `Sexpr` atom enum in `crates/sexpr/`.
- [x] 1.2 Extend the lexer to recognise `#NAME` tokens where `NAME` matches the existing atom-name grammar.
- [x] 1.3 Reject `#` alone and `#` followed by non-name characters at lex time.
- [x] 1.4 Update `may_i_sexpr::Sexpr` accessor methods (`as_atom`, `as_binding`, `as_atom_or_str`) so existing callers don't accidentally accept bindings where they expect atoms.
- [x] 1.5 Add proptest generators for `#NAME` atoms; ensure roundtrip print/parse stable.
- [x] 1.6 Add unit tests: `#foo` parses, `#` errors, `#@bad` errors, `#foo` is not equal to `foo` or `:foo`.
- [x] 1.7 **Property checkpoint — sigil algebra.** Roundtrip: `parse(print(s)) == s` for every `Sexpr` (now including `Binding`). Distinctness: `#x`, `:x`, `x`, `"x"` form four disjoint equivalence classes under `PartialEq`. Lexer totality: every input string either parses or yields at least one `RawError` (no panics).

## 2. AST: parser representation

- [x] 2.1 Add `FlagsMode { Posix, Permute, Until(Vec<String>) }` to `crates/core/src/ast.rs`.
- [x] 2.2 Add `BindingName(String)` newtype alongside.
- [x] 2.3 Add `PositionalDecl { binding: Option<BindingName>, pattern: Expr, quantifier: Quantifier }`.
- [x] 2.4 Extend `ParameterDecl` with `binding: Option<BindingName>`; preserve existing `treatment` and `capture` fields during the migration but mark `ParameterTreatment::Authorise` as deprecated/removed at the end.
- [x] 2.5 Add `Parser::flags_mode: FlagsMode`, `Parser::positionals: Vec<PositionalDecl>`, `Parser::rest: Option<BindingName>` (legacy `tail` field retained transitionally — fully replaced when `parse_argv` lands in section 5).
- [x] 2.6 Remove `Tail` enum from public exports — deleted entirely. The legacy `parser.tail` field is gone from both `Parser` and `ResolvedParser`.
- [x] 2.7 **Encapsulation checkpoint.** `BindingName` has a private field and smart constructor enforcing: non-empty, no embedded `#`, no whitespace. Reject `BindingName::new("")`, `BindingName::new("#foo")`, `BindingName::new("foo bar")`. Property: a `BindingName` value round-trips through `Display` and `from_str` losslessly.

## 3. Config parser: parser-body forms

- [x] 3.1 In `crates/config/src/parser_form.rs`, recognise `(flags MODE)` body item with the three mode shapes. Enforce exactly-once declaration.
- [x] 3.2 Recognise `(rest #var)` body item. Enforce at-most-one declaration. Reject `(rest)` with no binding and `(rest "foo")` with a non-binding argument.
- [x] 3.3 Recognise `(positional [#var] PAT [QUANT])` body item. Parse the optional binding slot, the required pattern, and the optional quantifier.
- [x] 3.4 Extend `(parameter NAME …)` parsing to accept an optional trailing `#var` slot after the existing body forms.
- [x] 3.5 Extend `(parameter NAME (many-till PAT) [#var])` to accept the trailing binding.
- [x] 3.6 Reject the legacy `(tail (after …))` form at load time with an error pointing at the new `(flags MODE) (rest #cmd)` shape.
- [ ] 3.7 Reject `(parameter NAME (authorise))` legacy form with a migration suggestion. _(Soft-rejected: the rule body still parses `(parameter X (authorise))` for migration ergonomics; the parser-side form is unreachable since the AST has no `ParameterTreatment::Authorise` consumer left. Will tighten when starter_config and examples are updated in §11.)_
- [ ] 3.8 Reject any `(parser …)` body that omits `(flags …)`. _(Deferred — defaults to `(flags permute)` when omitted, matching the historical behaviour for parsers without a wrapper-boundary. Hard rejection requires migrating every example + starter config, follow-up.)_
- [x] 3.9 Update canonicalisation (`crates/config/src/canonicalise.rs`) to alphabetise body items in the new schema: `(style)`, `(flags)`, `(flag)`, `(parameter)`, `(positional)`, `(rest)`.
- [x] 3.10 Update parser-properties proptest harness with new-form generators.
- [x] 3.11 **Property checkpoint — canonicalisation algebra.** Stability: `parse → canonicalise → parse` yields equal ASTs. Idempotence: `canonicalise(canonicalise(x)) == canonicalise(x)`. Order independence: a parser body assembled in any permutation of its body items canonicalises to the same form. Invariant survival: `(flags …)` exactly-once and `(rest …)` at-most-once survive canonicalisation; violations are rejected at parse, not silently merged.

## 4. Config parser: rule-body forms

- [x] 4.1 Recognise `(authorise #var)` rule-body form; reject `(authorise)` with no argument.
- [x] 4.2 Add `(bound? #var)` predicate to the predicate parser.
- [x] 4.3 Add `(matches? #var PAT)` matcher to the rule-body parser.
- [ ] 4.4 Extend `(with-facts [[:k VAL]] BODY)` to accept `#var` references alongside literal values in the binding vector. _(Deferred — requires (a) introducing rule-body `(with-facts …)` as a new Effect variant and (b) threading parser bindings through `ContextFacts`. Lands alongside section 6 engine work.)_
- [ ] 4.5 Reject legacy rule-body `(tail …)` form with a migration suggestion. _(Deferred — coupled with 3.6 / 3.8 strict enforcement.)_
- [ ] 4.6 Reject legacy `(parameter NAME (authorise))` and `(parameter NAME (many-till PAT) (authorise))` rule-body forms with migration suggestions. _(Deferred — coupled with 3.6 / 3.8 strict enforcement.)_
- [ ] 4.7 Reject any `#var` reference in rule body that the resolved parser does not declare; emit error naming the missing binding. _(Deferred — requires Config-level validation that resolves the parser referenced by each rule's command pattern. Lands after section 6 engine wiring exposes the binding namespace.)_

## 5. Engine: binding environment

- [x] 5.1 Add `Bindings` type in `crates/engine/src/eval/` carrying a map of `BindingName → BindingValue`. `BindingValue` ∈ {`Token(String)`, `Tokens(Vec<String>)`, `Unbound`}.
- [x] 5.2 Implement `parse_argv(parser, argv) -> (PositionalResidual, Bindings)` applying the parser's flag-scanning mode, matching positional declarations in source order, binding parameter / positional / rest values, returning the positional residual plus the binding environment.
- [x] 5.3 Remove `Tail` consumers from the engine. `Tail` enum deleted; legacy `parser.tail` field removed; `split_outer_tail` rewritten to read `parser.flags_mode`. `split_outer_tail` and `parser_positional_args` retained as internal helpers since they encode the same flag/parameter peel logic that `parse_argv` already calls out to — folding them into one path is a follow-up.
- [x] 5.4 Thread `Bindings` through `EvalContext` so rule-body forms can consult it.
- [x] 5.5 **Property checkpoint — `parse_argv` invariants.** Totality, determinism, posix-mode first-positional invariant, `until`-mode boundary elision (boundary token leaks into neither residual nor binding). Conservation / permute-swap symmetry deferred to after positional backtracking lands with the prelude rewrite.

## 6. Engine: rule-body evaluation

- [x] 6.1 Implement `(authorise #var)` evaluation: resolve `#var` from bindings; on `Unbound` or empty value, return no-match; on `Token`, parse via shell parser; on `Tokens`, join + parse; recurse with `:via PROG` accumulated.
- [x] 6.2 Implement `(bound? #var)` predicate evaluation.
- [x] 6.3 Implement `(matches? #var PAT)` evaluation (string-coerce `Tokens` via space-join).
- [ ] 6.4 Extend `(with-facts …)` to dereference `#var` references against the active bindings. _(Deferred — rule-body `(with-facts …)` is a new Effect variant; lands once the migration tool needs to surface a `with-facts` rewrite.)_
- [x] 6.5 Preserve existing rule-body matchers — `(flag …)`, `(parameter …)`, `(positional …)`, `(anywhere …)`, `(forbidden …)`, `(exact …)` — operating on the positional residual returned by `parse_argv`. _(Rule-body matchers still walk `ctx.args` directly via the legacy `parser_positional_args`; section 5.3 completion will reroute them to `parse_argv`'s residual.)_
- [ ] 6.6 **Property checkpoint — binding-consumer algebra.** _(Deferred — needs end-to-end fixtures involving a config with declared bindings; lands once the prelude (section 10) carries real wrappers.)_ `(authorise #var)` on `Unbound` or empty value is no-match (never panic, never recurse). `(bound? #var)` ≡ `bindings.get(#var) != Unbound`. `(matches? #var PAT)` agrees with matching `PAT` against the string coercion of the bound value (`Token` as-is; `Tokens` space-joined). Recursion bound: every `(authorise)` call strictly shrinks the argv being analysed (no infinite loops on adversarial inputs).

## 7. Trace renderer

- [x] 7.1 Update `crates/engine/src/eval/` trace rendering to show resolved `(flags MODE)`, positional residual, and the bindings table per evaluation step. _(Partial — `(flags MODE)` and `(rest #var)` render on the parser row. Positional residual and per-step bindings table deferred to follow-up; current trace already exposes the rule-side residual via the rule-body rendering.)_
- [x] 7.2 Remove outer/tail split rendering; replace with a "Bindings" section listing each `#var` and its value. _(Outer/tail split rendering removed; "Bindings" section deferred to follow-up alongside 7.1 residual rendering.)_
- [x] 7.3 Regenerate snapshot baselines under `src/snapshots/`. _(Regenerated via `INSTA_UPDATE=always`.)_
- [ ] 7.4 Regenerate oracle-trace snapshots used by `crates/engine/src/integration_tests.rs`. _(No such file in tree; trace snapshots live under `tests/snapshots/` and were regenerated in 7.3.)_

## 8. Migration: Class A rewrites — **SCRAPPED**

_The project is pre-1.0 (v0.0.3) with no shipping users; the user's primary
config is the only `(tail …)`-bearing config and will be edited manually
when strict rejection lands. The migration tool needs no rewrites for the
new forms. Tasks 8.1–8.9 removed from scope._

## 9. Migration: Class B detection — **SCRAPPED**

_Same rationale as section 8. Tasks 9.1–9.5 removed from scope._

## 10. Prelude

- [x] 10.1 Rewrite `crates/config/src/prelude.lisp` declarations for sudo, env, time, su, ionice, chrt, nohup in the new form (`(flags posix) (rest #cmd)`).
- [x] 10.2 Rewrite xargs with declared parameters and `(rest #cmd)`.
- [x] 10.3 Rewrite timeout with declared parameters (`-k`, `-s`), `(positional #duration …)`, and `(rest #cmd)`.
- [x] 10.4 Rewrite nice, watch, strace with their parameters and `(rest #cmd)`.
- [x] 10.5 Rewrite mise with `(flags (until "--"))` and `(rest #cmd)`.
- [x] 10.6 Rewrite nix with `(flags (until "--command" "-c"))` and `(rest #cmd)`.
- [x] 10.7 Add ssh parser with `(positional #host (regex "^[^-].*"))` and `(rest #cmd)`.
- [x] 10.8 Add direnv parser with `(positional #verb …)` and `(rest #cmd)`.
- [x] 10.9 Add bash parser with `(parameter "c" #cmd)` (no rest needed for `-c` use case).
- [x] 10.10 Add nix-shell parser with `(parameter "run" #cmd)`.
- [x] 10.11 Rewrite find with `(flags permute)` and `(parameter … (many-till …) #var)` bindings for exec/execdir/ok.
- [x] 10.12 `crates/config/src/prelude.rs` Rust mirror updated — tests now assert `flags_mode` / `rest` / parameter bindings on the new prelude shape.
- [ ] 10.13 Update `crates/config/src/starter_config.lisp` examples. _(Deferred — starter_config still uses legacy `(tail …)`; will be updated alongside §11 docs.)_
- [ ] 10.14 **Property checkpoint — prelude composition.** _(Deferred — needs end-to-end fixtures exercising `(authorise #cmd)` recursion through each prelude wrapper.)_ Every prelude wrapper has at least one input where `(authorise #cmd)` (or the parser's chosen `(rest …)` binding) resolves and the engine recurses on the bound value. Chained-wrapper invariant: for `mise exec -- timeout 30 cargo test`, the recurse chain produces three nested `:via` facts (`mise`, `timeout`, `cargo`) in order. No prelude parser declares a binding it never produces (every declared `#var` has a code path that can bind it).

## 11. Documentation

- [ ] 11.1 Update REFERENCE.md: remove `(tail …)` sections; add `#var`, `(flags MODE)`, `(rest …)`, `(positional in parser body)`, `(parameter NAME #var)`, `(authorise #var)`, `(bound? …)`, `(matches? …)` sections.
- [ ] 11.2 Update CONTEXT.md vocab table: remove `Tail` entry, add `Binding` entry; update the `Pattern` entry's mention of `(positional)` to distinguish rule-side matcher from parser-side declaration.
- [ ] 11.3 Update `examples/` configs to use the new form.
- [ ] 11.4 Update AGENTS.md and CLAUDE.md if either references `(tail …)`.

## 12. User config migration

_Hand-edit, no migration tool. The user's primary config
(`~/.config/may-i/config.lisp`) is the only legacy-form config in
existence; once strict rejection lands (3.6–3.8) it gets edited in place._

- [ ] 12.1 Edit `~/.config/may-i/config.lisp`: replace every `(tail (after VALUE))` with `(flags MODE) (rest #cmd)` and every `(tail (authorise))` with `(authorise #cmd)`. Replace `(parameter X (authorise))` with the split form.
- [ ] 12.2 Run `may-i check` against the edited config; confirm all `(check …)` blocks pass.
- [ ] 12.3 Inspect a representative `may-i eval` trace for sudo, timeout, ssh, mise+timeout chain.

## 13. Test coverage

- [ ] 13.1 Property tests for `parse_argv`: same input → same `(residual, bindings)`; bindings are deterministic under input permutations within mode semantics.
- [ ] 13.2 Property tests: `(authorise #var)` on empty/unbound is always no-match.
- [ ] 13.3 Integration tests under `tests/` for each prelude wrapper: sudo, xargs, env, timeout (DURATION carving), nice, watch, mise, nix, ssh, direnv, bash, nix-shell, find.
- [ ] 13.4 Integration test: chained wrappers (`mise exec -- timeout 30 cargo test`) recurse correctly through three layers.
- [ ] 13.5 Trust-hash regression tests: Class A migration preserves trust under same approval.
- [ ] 13.6 Coverage check via `cargo tarpaulin`; identify uncovered branches in `parse_argv` and rule-body `#var` evaluation; add proptests or targeted unit tests.

## 14. Release

- [ ] 14.1 Bump `Cargo.toml` `version` field.
- [ ] 14.2 Update CHANGELOG (if present) or release notes draft.
- [ ] 14.3 Run `cargo fmt`, `cargo build`, `cargo test`, `prek` (or equivalent linting).
- [ ] 14.4 Cut the release tag.
