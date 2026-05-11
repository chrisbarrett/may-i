## Context

The current parser DSL coordinates between parser-body declarations and rule-body matchers via an implicit, context-sensitive "current tail" slice threaded through `crates/engine/src/eval/`. `(tail (after VALUE))` on the parser side and `(tail (authorise))` on the rule side share only a keyword, not a name. The engine routes the consumer based on:

1. Whether the parser declared `(tail …)` at all (full argv vs. split).
2. If declared, whether the boundary is `:flags` or a literal token.
3. Whether `(authorise)` appears under `(tail …)`, under `(parameter NAME (authorise))`, or under `(positional … (authorise))`.

The combinator-vs-declarative exploration that preceded this proposal converged on a finding: combinators are not needed to fix the warts. The wart is **invisibility of bindings**. Once bindings are explicit, the wrapper class (timeout, sudo, xargs, nice, watch, env, find -exec, ssh, mise, direnv exec, nix shell …) expresses cleanly in flat declarations. Combinators remain available as a future option for find's predicate algebra and kubectl-style dispatch, but neither is in the user's current usage.

The user's primary config (`~/.config/may-i/config.lisp`) exhibits the cost of the side-channel concretely: `(tail (authorise))` appears with five distinct semantics across the wrapper rules, and structural intent for timeout/ssh/direnv is encoded in non-consuming `(when (positional …))` guards that work by happy accident with the engine's residual-positional fallback.

## Goals / Non-Goals

**Goals:**

- Every recurse target has a written name. `(authorise)` always takes a binding reference.
- Flag-scanning mode is a written choice (`posix` / `permute` / `until`), not a hidden default.
- Parser-body declarations carve the argv; rule bodies declare policy. The structural commitment lives in one place.
- Chained wrappers compose correctly: `mise exec -- timeout 30 cargo test` recurses through `mise → timeout → cargo` with each layer's `#cmd` exact and verifiable.
- Migration is mechanical for the syntactic part; Class B warnings highlight the cases where structural intent moves from rule to parser.
- The migration scope stays bounded: no new combinators, no recursive grammars, no subcommand dispatch.

**Non-Goals:**

- Parser combinators (`seq`, `or`, `case`, general `many`). Out of scope.
- Find's predicate algebra (`-and` / `-or` / `\( \)`). `(many-till …)` remains the 80% tool.
- Subcommand dispatch via parser (kubectl `<verb> [verb-flags]`). Rule-body `(cond …)` on a `(positional #verb …)` binding covers the common cases; richer dispatch is future work.
- Removing the implicit `:via` fact propagation. The wrapper-name accumulation stays automatic; only user-named bindings change.
- Defining a total functional language for arg styles. Existing `(define-arg-style …)` plist mechanism stays; styles are not folded into combinators.

## Decisions

### `#var` sigil for parser-bound names

Bindings are named with a leading `#`. The s-expression reader recognises `#NAME` as a distinct atom kind (alongside literals, atoms, `:keyword` facts, and vectors). This keeps bindings lexically distinguishable from fact keys (`:k`), literal strings (`"…"`), and free atoms.

**Alternative considered:** reuse the existing `:k`-style binding pattern (`[:k *]`) for parser bindings. Rejected — that pattern already denotes fact-binding (set-of-values, lives in `ContextFacts`). Conflating parser-local slots with the fact namespace muddies which keys propagate to inner recurses and which stay local. A separate sigil keeps the two regimes legible.

**Alternative considered:** named with no sigil (`(positional duration …)`). Rejected — name resolution becomes ambiguous against free atoms used elsewhere in patterns (style names, keyword tags, …). A sigil is cheap and unambiguous.

### `(rest #var)` replaces `(tail (after …))`

The parser body declares the tail slice by binding it to a name. The flag-scanning mode that previously rode on the boundary form moves to a separate `(flags MODE)` declaration. Concretely:

- `(tail (after :flags))` → `(flags posix) (rest #cmd)`
- `(tail (after "--"))` → `(flags (until "--")) (rest #cmd)`
- `(tail (after ["--command" "-c"]))` → `(flags (until "--command" "-c")) (rest #cmd)`
- No tail at all → `(flags permute)` (no `(rest …)` declared).

`#cmd` is the conventional name for the recurse target, but any `#var` works. The binding is the value; the name is the user's choice.

**Alternative considered:** keep the boundary form and just add a name slot — `(tail (after :flags) #cmd)`. Rejected — the boundary-vs-mode conflation is one of the original warts; separating them earns the line of code. `(rest …)` is the binder, `(flags …)` is the mode.

### `(flags MODE)` enumerates three getopt-aligned modes

The three modes name real getopt behaviours:

- `posix` — outer flags appear only before the first positional; first non-flag stops outer scanning. Matches `POSIXLY_CORRECT` semantics. Used by sudo, timeout, xargs, env, nice, time, watch, su, ionice, chrt, strace, nohup.
- `permute` — outer flags may appear anywhere; outer parser peels declared flags and parameters wherever they occur. Matches GNU getopt's permuting default. Used by git, ls, cp, and most non-wrapper tools.
- `(until STR…)` — outer parser scans up to the first literal token in `STR…`, then stops. The boundary token is consumed and dropped. Used by mise (`--`), nix (`--command` / `-c`).

`(flags MODE)` is mandatory in the new parser body. Authors confront the question at declaration time. The migration tool fills it in for every existing parser.

**Alternative considered:** infer the mode from the presence/shape of `(rest …)`. Rejected — that reintroduces the implicit-default wart. Make the author commit.

**Alternative considered:** add a fourth mode for unknown-flag-permissive permuting (where unknown flag-shaped tokens become positionals rather than errors). Deferred — `permute` already covers the in-tree cases; add later if real demand emerges.

### `(positional [#var] PAT [QUANT])` in parser body

The parser body declares positional slots before `(rest …)`. Each positional binds (optionally) to a `#var` and matches one or more tokens per its quantifier. Quantifiers reuse the existing `Quantifier` enum from `crates/core/src/pattern.rs`:

- `one` (default) — exactly one token.
- `?` — optional, zero or one.
- `*` — zero or more.
- `+` — one or more.

Multi-token positionals (`*` / `+`) bind to a list value. Single-token positionals bind to a string.

**Interaction with `(flags MODE)`:** under `posix`, positionals appear after all outer flags. Under `permute`, positionals are the residual after flag/parameter peeling. Under `(until STR…)`, positionals appear before the boundary token. The matcher walks the appropriate residual slice in declaration order, with existing backtracking semantics for `?` / `*` / `+`.

**Alternative considered:** allow positionals interleaved with flag declarations in parser body. Rejected — adds order significance to body items in a way that's hard to canonicalise for trust-hashing. Body order is independent (style/flags/parameters/positionals/rest); evaluation is implied by the declared mode.

### Parameter binding form

`(parameter NAME)` declares a value-bearing flag. To bind its captured value, add `#var`:

- `(parameter "c" #cmd)` — single-token capture bound to `#cmd`.
- `(parameter "exec" (many-till (or ";" "+")) #args)` — multi-token capture bound to `#args` (list value).

A parameter may appear multiple times in argv; the binding accumulates as a list when the parameter is declared multi-occurrence (separate consideration; default single-occurrence keeps the last value).

`(parameter NAME (authorise))` and `(parameter NAME (many-till PAT) (authorise))` forms are removed. The author writes `(parameter NAME #x)` in the parser and `(authorise #x)` in the rule.

**Alternative considered:** auto-bind every parameter under its declared name (`#c` for `(parameter "c")`). Rejected — sometimes the user wants to declare a parameter purely for tokenisation correctness (so unknown long flags don't get swallowed as values) without binding. Make binding opt-in via the `#var` slot.

### Rule-body forms

Rule bodies consume bindings:

- `(authorise #var)` — recurse on the bound value. Required argument; `(authorise)` with no argument is removed.
- `(bound? #var)` — predicate; true iff `#var` has a value in the current environment (after parser eval). Useful for optional positionals and parameters.
- `(matches? #var PAT)` — predicate; matches the bound value against `PAT` (the existing `Expr<…>` shape). Lifts a bound value into the predicate algebra.
- `(with-facts [[:k #var]] BODY)` — promote `#var` to fact `:k` in the scope of `BODY`. The fact lives in inner-recurse facts when `BODY` contains `(authorise …)`. Replaces the case where users wrote `[:k *]` bindings inside `(positional …)` matchers to push facts into the recurse.

Rule-body `(tail …)` is removed entirely. Rule-body `(positional …)`, `(flag …)`, `(parameter NAME PAT)`, `(anywhere …)`, `(forbidden …)`, `(exact …)`, `(or)`, `(and)`, `(not)`, `(when)`, `(cond)`, `(if)` are unchanged — they remain pure matchers over the outer slice.

**Alternative considered:** make `(authorise #var)` permissive when `#var` is unbound (no-match instead of error). Adopted — matches the existing "no-match" behaviour when a parser declared a tail and the boundary was absent. `(bound? #var)` gives the author the explicit guard.

### `(authorise #var)` is the only recursive verb

The four current spellings collapse to one:

- `(tail (authorise))` → `(authorise #cmd)` where `#cmd` is `(rest …)`'s binding.
- `(parameter X (authorise))` → `(authorise #x)` where `#x` is `(parameter X #x)`'s binding.
- `(positional … (authorise))` → `(authorise #verb)` where `#verb` is the positional's binding.
- `(parameter X (many-till PAT) (authorise))` → `(authorise #x)` where `#x` is the many-till's binding.

The verb's semantics: lift the bound value into a command line (single string → tokenise; list of tokens → join with spaces then tokenise), re-evaluate against the active rule set, accumulate `:via PROG` in inner facts.

### Migration strategy

The migration is two-class, mirroring the dsl-coherence migration shape:

- **Class A (mechanical, semantics-preserving):**
  - `(tail (after :flags))` → `(flags posix) (rest #cmd)`
  - `(tail (after "TOK"))` → `(flags (until "TOK")) (rest #cmd)`
  - `(tail (after [STR…]))` → `(flags (until STR…)) (rest #cmd)`
  - `(parser PROG (style S) …)` with no `(tail …)` → add `(flags permute)`
  - `(tail (authorise))` in rule body → `(authorise #cmd)` (using the migrated parser's `(rest …)` name)
  - `(parameter X (authorise))` in rule body → infer parser-side rewrite to `(parameter X #x)`, rule becomes `(authorise #x)`
  - `(parameter X (many-till PAT) (authorise))` → analogous
  - `[:k *]` fact-binding inside rule-body `(positional …)` is preserved as-is (fact channel is unchanged)

- **Class B (semantic shift, user verification):**
  - Rule-body `(when (positional PAT) (tail (authorise)))` patterns where `PAT` was carving structural intent (timeout, ssh, direnv exec): the migration emits a warning and a suggested rewrite that moves the positional from the rule guard to the parser body. The user owns the structural commitment.

Trust hashes change for every loaded config. Class A rewrites auto-rehash trust under the existing approval (per `migration-system` capability). Class B emits a prominent warning advising `may-i check` re-run; trust still carries.

**Alternative considered:** ship the new forms alongside the old for a transition window. Rejected — pre-1.0, no back-compat requirement, dual grammars compound the cognitive load. Cut once.

### Engine representation

Parser AST gains a binding map and replaces `Tail` with the `FlagsMode` enum:

```rust
pub struct Parser {
    pub program: String,
    pub style_name: String,
    pub flags_mode: FlagsMode,           // new — replaces tail field
    pub flags: Vec<Vec<String>>,         // unchanged
    pub parameters: Vec<ParameterDecl>,  // gains optional binding name
    pub positionals: Vec<PositionalDecl>, // new — declared positional slots
    pub rest: Option<BindingName>,       // new — replaces (tail …)
    pub span: Span,
    pub provenance: Provenance,
}

pub enum FlagsMode {
    Posix,
    Permute,
    Until(Vec<String>),
}

pub struct BindingName(String);  // sans the `#` sigil
```

Evaluator state carries a binding environment:

```rust
pub struct Bindings {
    map: HashMap<BindingName, BindingValue>,
}
pub enum BindingValue {
    Token(String),
    Tokens(Vec<String>),  // many-till lists, multi-token positionals
    Unbound,              // explicit absence marker
}
```

`split_outer_tail`, `parser_positional_args`, `Tail` enum are removed. Replaced by a single `parse_argv(parser, argv) -> (outer, Bindings)` entry point that returns the residual outer slice for rule-body matchers plus the binding environment for `(authorise #var)`.

## Risks / Trade-offs

**[Trust-hash invalidation across all loaded configs]** Every parser declaration changes canonical form. → Class A rewrites preserve trust under existing approval; Class B emits a warning but trust still carries. The migration system already implements rehash-under-same-approval.

**[Migration ambiguity for rule-body guards that carved structure]** `(rule "ssh" (when (positional [:ssh/host *]) (tail (authorise))))` can be auto-rewritten to a parser-body `(positional #host *)` plus a rule-body `(with-facts [[:ssh/host #host]] (authorise #cmd))`, but the inference is heuristic — the migration needs to recognise the "guard + tail-recurse" idiom. → Class B warning lists every affected rule and shows the suggested rewrite for manual review; the user runs `may-i check` against their `(check)` blocks to verify.

**[Reader-monad context for parser-bound names in `(authorise)` becomes explicit, but eval still threads bindings]** The binding environment is engine-internal; users see only the names. → Trace renderer surfaces the binding environment per evaluation step (already render outer/tail split in oracle traces; extend to show binding values).

**[`(flags …)` mandatory is a forcing function]** Existing parsers all need the keyword. → Migration tool inserts it; users with hand-authored parsers see a Class A rewrite. No author writes a parser without confronting the question.

**[Sigil collision risk in the s-expression reader]** `#` is currently unused in may-i's s-expression dialect (no `#t`/`#f`/`#\char`/etc.). → Reader changes are minimal and additive; the `may-i-sexpr` crate gains a new atom kind. No existing config uses `#`-prefixed atoms.

**[Find's predicate algebra still incomplete]** `(many-till …)` covers `-exec`/`-execdir`/`-ok` but not `-and`/`-or`/`\(`/`\)`. → Documented limitation, unchanged from dsl-coherence. The binding refactor doesn't address it but doesn't preclude a future combinator slice that does.

**[xargs/parallel stdin invisibility]** Stdin contents remain unknowable to static analysis. → Documented, unchanged. Inner rules check `(fact? :via "xargs")` and tighten.

**[Surface name "rest" overlaps with positional quantifier intuition]** `(rest #var)` could read as "the rest of the positionals" in a positional-heavy parser. → Documentation clarifies: `(rest #var)` is *after* all declared positionals and parameters and flags; it captures the unconsumed tail. The CONTEXT.md vocab table grows a `Binding` entry and the `Tail` entry is replaced.

**[Optional bindings interact with `(authorise)`]** `(authorise #var)` when `#var` is unbound: no-match (per decision above). Authors who want explicit absence-handling write `(when (bound? #var) (authorise #var))`. → Documented; matches existing boundary-absent semantics. Migration tool inserts `(bound? …)` guards where the old rule had a `(when (positional …))` guard.

## Migration Plan

1. Implement the `#var` reader extension in `may-i-sexpr`.
2. Extend `Parser` AST with `flags_mode`, `positionals`, `rest`; remove `tail`.
3. Implement `parse_argv` returning `(outer, Bindings)`; remove `split_outer_tail`, `parser_positional_args`, `Tail`.
4. Implement rule-body `(authorise #var)`, `(bound? #var)`, `(matches? #var …)`, `(with-facts [[:k #var]] …)`.
5. Implement Class A migration rewrites.
6. Implement Class B detection: rule-body `(when (positional …) (tail (authorise)))` patterns. Emit suggested rewrites.
7. Update `crates/config/src/prelude.lisp` and `prelude.rs` mirror with new-form declarations for sudo, xargs, env, timeout, nice, time, watch, su, ionice, chrt, mise, nix, find. Add timeout's positional explicitly.
8. Update `crates/config/src/starter_config.lisp` with new-form examples.
9. Update REFERENCE.md, CONTEXT.md, examples/.
10. Migrate the user's primary config (`~/.config/may-i/config.lisp`); verify with `may-i check` and trace inspection.
11. Update trace renderer to show binding environment per step.
12. Run full property and integration test suites; update `src/snapshots/` baselines.
13. Cut a release. Pre-1.0; no graceful coexistence period.

## Open Questions

- **Multi-occurrence parameters and their bindings**: when `(parameter "I" #i)` and argv has `-I foo -I bar`, what's `#i` — last value, first value, or list? Default to last (matches current single-value semantics); add an opt-in `(parameter "I" * #i)` form for list-collection? Defer to implementation surface review; not blocking for the wrapper class.
- **Positional binding scope**: does a `(positional #verb …)` binding persist into the inner recurse as a fact? Default: no — bindings are parser-local; promotion to fact is explicit via `(with-facts [[:k #v]] …)`. Confirms the "no invisible side-channel" principle.
- **Where does `(positional)` rule-body matcher live now**? It stays — rule bodies still match against the outer slice's positional tokens. Parser-body `(positional #var …)` *declares*; rule-body `(positional …)` *matches*. Two related forms, two scopes. The vocab table needs to clarify.
- **Trace rendering of bindings**: how prominently? Per-step binding diff vs. summary at recurse boundaries. Defer to UX iteration during implementation.
- **`(check)` blocks in user configs that rely on current `(tail …)` rendering**: minor — they assert decisions, not syntax. Should pass unchanged after migration.
