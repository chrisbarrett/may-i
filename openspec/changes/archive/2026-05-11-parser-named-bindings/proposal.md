## Why

The parser DSL has an invisible side-channel between parser declarations and rule bodies. `(tail (after …))` in a parser body and `(tail (authorise))` in a rule body coordinate by convention, not by name — the engine threads a context-sensitive "current tail" through evaluation, and `(authorise)` means one of four different things depending on its surrounding form. In practice this shows up as wrappers that can only be expressed via `(when (positional …))` guards that don't actually consume (e.g. `timeout`'s `DURATION COMMAND` shape), and as fragile composition when wrappers stack (`mise exec -- timeout 30 cargo test` recurses on `30 cargo test` and re-recurses on `cargo test` only by happy accident). The user's own primary config exhibits five distinct meanings for `(tail (authorise))` across the wrapper rules.

Replacing the side-channel with **explicit parser-bound names** (`#var`) gives every recurse target a referent the user can see, makes flag-scanning mode an explicit declaration rather than a hidden default, and fits the existing one-Pattern mental model from CONTEXT.md. Pre-1.0 is the window to land this without back-compat shims.

## What Changes

- **BREAKING** Add `#var` sigil for parser-bound names. Bindings flow from parser body to rule body by name.
- **BREAKING** Replace `(tail (after VALUE))` in parser body with `(rest #var)`, which binds the unconsumed tail of argv to `#var`. The boundary semantics that `(after :flags)` / `(after STR)` encoded fold into the new explicit `(flags …)` mode declaration.
- **BREAKING** Add `(flags MODE)` declaration in parser body, where `MODE` is one of `posix` (outer flags only before the first positional), `permute` (outer flags scanned anywhere; GNU getopt default), or `(until STR…)` (outer flags scanned until a literal token, then stop). Replaces the implicit defaults the current engine uses.
- **BREAKING** Add `(positional [#var] PAT [QUANT])` declaration in parser body. Optional binding name promotes the matched arg to `#var` for rule-body reference. Quantifier defaults to `one`; `?` / `*` / `+` available.
- **BREAKING** `(parameter NAME)` in parser body gains an optional binding form: `(parameter NAME #var)` binds the captured value; `(parameter NAME (many-till PAT) #var)` binds the captured token list.
- **BREAKING** Replace `(tail (authorise))` in rule body with `(authorise #var)`. The verb always takes a single binding reference. Rule-body `(tail …)` is removed.
- **BREAKING** Rule body gains `(bound? #var)` predicate and `(matches? #var PAT)` matcher for constraining/conditioning on parser-bound names. Existing `(when …)` / `(cond …)` / `(if …)` combine with these naturally.
- Rule body gains `(with-facts [[:k #var]] …)` form for explicit promotion of a parser binding to a fact in the inner recurse (replaces the implicit `:via`-style threading where users want named facts).
- Implicit `:via` fact propagation is preserved — the wrapping program name still accumulates into `:via` automatically; only the user-named bindings change.
- Migration: `may-i migrate` rewrites every Class A transformation. `(tail (after :flags))` → `(flags posix) (rest #cmd)`. `(tail (after "TOK"))` → `(flags (until "TOK")) (rest #cmd)`. `(tail (authorise))` → `(authorise #cmd)`. `(parameter X (authorise))` → `(parameter X #x) … (authorise #x)`. Where the rule body had `(when (positional …) (tail (authorise)))` for ad-hoc structural carving (timeout, ssh, direnv exec), migration emits a warning and a suggested rewrite — the user owns the structural commitment.
- Prelude wrapper parsers rewritten in the new form. `timeout` declares its DURATION positional explicitly; `ssh` declares its HOST positional; `nix` keeps its `(until "--command" "-c")` flag-scanning mode; `mise` keeps `(until "--")`; `find`'s `(many-till …)` parameters gain explicit `#name` bindings.

## Capabilities

### New Capabilities

- `parser-bindings`: The `#var` sigil and the parser-body binder forms (`(rest #var)`, `(positional #var …)`, `(parameter NAME #var)`, `(many-till PAT #var)`). Defines binding scope (parser-eval through inner recurse), value shapes (single token, token list), the `(authorise #var)` consumer verb, the `(bound? #var)` / `(matches? #var …)` rule-body forms, and the explicit `(flags MODE)` flag-scanning mode declaration.

### Modified Capabilities

- `wrapper-tail`: `(tail (after …))` parser-body declaration removed; superseded by `(rest #var)` plus `(flags MODE)`. Rule-body `(tail (authorise))` removed; superseded by `(authorise #var)`. Boundary-absent semantics (no-match when parser declares a tail and the boundary is missing) migrate to "no-match when `#var` is unbound at `(authorise)` time".
- `wrapper-tail-recursion`: `(after "TOK")` and `(after [STR…])` boundary forms removed; their semantics fold into `(flags (until STR…))`. The "boundary token consumed, neither slice contains it" invariant is preserved by the new mode.
- `parameter-many-till`: `(parameter NAME (many-till PAT))` gains an explicit binding form `(parameter NAME (many-till PAT) #var)`. The captured token list is the value of `#var`; `(authorise #var)` recurses on the joined tokens (current join-and-reparse semantics preserved). Rule-body access to a `(many-till …)` capture via `(parameter NAME (authorise))` is removed; users write `(authorise #var)`.
- `prelude-wrapper-parsers`: Every prelude parser declaration is rewritten in the new form. `timeout` and similar gain explicit positional bindings where the current `(tail (after :flags))` was carving the wrong slice (the DURATION class).

## Impact

- **DSL surface**: `(tail …)` removed from both parser and rule bodies. `#var` sigil introduced in the s-expression grammar (alongside existing `:fact` keyword sigil). `(flags MODE)` added; `(rest …)`, `(positional …)`, `(parameter … #var)`, `(many-till … #var)` are parser-body binder forms. `(authorise #var)`, `(bound? #var)`, `(matches? #var …)` added to rule bodies.
- **Engine**: parser representation (`crates/core/src/ast.rs::Parser`) carries a binding map; evaluator (`crates/engine/src/eval/`) threads a binding environment instead of implicit tail slice. `parser_positional_args`, `split_outer_tail`, and the `Tail` enum are replaced by binding-aware evaluation.
- **Migration**: full `may-i migrate` Class A rewrite for the syntactic transformation. Class B warning where structural intent was previously inferred from rule-body guards (timeout, ssh, direnv exec) — the user must commit to a parser-body shape.
- **Prelude**: every wrapper parser in `crates/config/src/prelude.lisp` rewritten; `crates/config/src/prelude.rs` mirror updated.
- **Trust hashes**: every loaded config's canonical form changes. Class A rewrites preserve trust under the same approval (the migration system already handles rehashing).
- **User-facing docs**: REFERENCE.md, CONTEXT.md vocab table (Tail entry deleted, Binding entry added), examples/, starter_config.lisp.
- **Tests**: `(tail …)`-touching tests across `crates/engine/src/eval/tests/`, `crates/config/src/parser_form.rs::tests`, integration tests under `tests/`, and snapshot baselines under `src/snapshots/`.
- **Out of scope**: combinators (`seq`, `or`, `case`) for arbitrary parser composition; recursive parser grammars (find's predicate algebra); subcommand dispatch via parser. The binding mechanism doesn't preclude these as future work but doesn't pre-pay for them.
