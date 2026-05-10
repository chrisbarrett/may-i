## Why

The DSL mixes plist and form-list conventions inside one form (`(parser PROG :style S (flag …))`), the recursion verb is named after the binary (`(may-i *)`), and the user-facing spelling of decisions leaks contributor jargon (`(effect :allow)` despite docs telling authors to "say allows / asks / denies"). Worse, wrapper tools without `--` (sudo, xargs, env, timeout, …) silently bypass authorisation: `sudo rm -rf /tmp/x` recurses as `rm /tmp/x` because the outer GNU tokeniser eats `-rf` as if those were sudo's flags. Verified with the `may-i` oracle. Pre-1.0 is the right window to land coherent syntax + the structural fix together rather than across two migrations.

## What Changes

- **BREAKING** Parser body becomes a form-list: `:style STYLE` → `(style STYLE)`. Body is now a uniform sequence of `(KIND ARGS…)` declarations.
- **BREAKING** `define-arg-style` body becomes a form-list of attribute forms (`(overrides gnu)`, `(separators " " "=" ":")`, `(combined-shorts t)`, `(pun :allow)` etc.). PLIST keys retire.
- **BREAKING** `check` body becomes a form-list: `(check (allow CMD) (ask CMD "r") (deny CMD "r"))`.
- **BREAKING** Decision verbs at rule body: `(effect :allow R?)` → `(allow R?)`, `(effect :ask R?)` → `(ask R?)`, `(effect :deny R?)` → `(deny R?)`. The bare-form `(effect …)` retires. Reason string optional in all three.
- **BREAKING** Recursion verb renamed: `(may-i *)` → `(authorise)`. Bare, no arguments. The `*` placeholder retires.
- **BREAKING** Improper lists removed from rule bodies: `(positional X . (may-i *))` → `(positional X)` and `(tail (authorise))` as siblings. The dotted-tail continuation form retires.
- **NEW** Parser-side tail declaration: `(tail (after :flags))` for "implicit boundary at end of outer flags" (sudo, xargs, env, …) and `(tail (after "--"))` for "explicit boundary token" (mise). Body of `(after …)` accepts a keyword for built-in named positions or a string literal for explicit tokens.
- **NEW** Rule-side tail reference: `(tail (authorise))` recurses on whatever the parser-declared slice contains, or — when the parser declares no tail — on residual positionals after preceding `(positional …)` matches. Body restricted to `(authorise)`.
- **NEW** Multi-token parameter capture: `(parameter NAME (many-till PAT))` consumes tokens from after NAME until PAT matches a token. Captured tokens are joined into a string, available to rule-side `(parameter NAME (authorise))` for recursion. Multi-occurrence parameters fire the rule body once per occurrence; strictest decision wins.
- **NEW** Tokeniser splits argv into outer-slice and tail-slice when the parser declares `(tail …)`. Argv matchers (`(flag …)`, `(parameter …)`, `(positional …)`, `(anywhere …)`, `(forbidden …)`) scope to outer. Tail accessible only via `(tail (authorise))`.
- **FIX** `(anywhere …)` and `(forbidden …)` honour `--` as a flag-stop, matching `(flag …)` and `(parameter …)`. Universal lexical fix, independent of `(tail …)` declaration.
- **NEW** Prelude ships parsers for the common wrapper tools: `sudo`, `xargs`, `env`, `timeout`, `nice`, `time`, `watch`, `su`, `ionice`, `chrt`, `mise`, `find` (with `-exec`/`-execdir`/`-ok` declared via `(many-till (or ";" "+"))`).
- **MIGRATION** `may-i migrate` walks the `(load …)` graph transitively and rewrites every reachable file. Syntactic-only rewrites (Class A) auto-update trust hashes under the existing approval. The wrapper-boundary semantic fix (Class B) emits a prominent warning and asks the user to re-run their `(check …)` cases.
- **CANONICAL** Parser body declarations sort alphabetically by kind (style, flag, parameter, tail) for canonical-form hashing. Same for `define-arg-style` attributes. Rule order preserved (rule order is semantic).

## Capabilities

### New Capabilities

- `dsl-form-list-syntax`: form-list discipline across parser, define-arg-style, and check bodies; decision verbs `(allow|ask|deny)`; recursion verb `(authorise)`.
- `wrapper-tail`: `(tail (after :flags|"--"))` parser-side declaration, `(tail (authorise))` rule-side reference, tokeniser outer/tail split, matcher scoping rules.
- `parameter-many-till`: `(parameter NAME (many-till PAT))` multi-token capture-shape and multi-occurrence rule semantics.
- `prelude-wrapper-parsers`: stock parser declarations shipped in the prelude for the common wrapper tools.

### Modified Capabilities

- `pattern-expressions`: `(anywhere …)` and `(forbidden …)` honour `--` as flag-stop. Argv matchers scope to outer slice when parser declares `(tail …)`. Improper-list `(positional X . CONT)` retires.
- `migration-system`: migration walks `(load …)` graph transitively; distinguishes Class A (syntactic, auto-rehash trust) from Class B (semantic shift, warn). Adds Class A rewrites for the syntax changes in this proposal.
- `pretty-printing`: canonical-form sorts parser body declarations and define-arg-style attributes alphabetically.
- `trust-hashing`: trust hashes auto-update for Class A rewrites; user is notified but does not re-approve.

## Impact

- **Surface DSL**: every existing config file requires migration. Pre-1.0 — acceptable with `may-i migrate`.
- **Parser internals** (`crates/engine/src/eval/entry.rs`, `crates/config/src/parser.rs`): tokeniser learns to produce two slices when `(tail …)` declared; argv matchers consult the active slice.
- **Argv matchers** (`crates/engine/src/eval/effects.rs`, `predicates.rs`): scope-to-outer policy added; `(anywhere)`/`(forbidden)` `--` boundary added; `(authorise)` replaces `MayI` effect; `(tail …)` is a new rule-side form.
- **Style and parser config types** (`crates/config/src/style.rs`, `parser.rs`): new form-list grammars, new `Tail` field on resolved parsers, new `ManyTill` capture shape on parameter declarations.
- **Migration** (`crates/config/src/migrate/`): adds rewrite rules for every BREAKING bullet above; load-graph walker; trust-hash rehash flow.
- **Prelude** (`crates/config/src/prelude.rs`): ships the new parser declarations.
- **Trust system** (`crates/engine/src/trust_gate.rs` and friends): Class A rewrites auto-rehash; user-facing notification on migrate.
- **Trace renderer** (`crates/engine/src/trace.rs` or equivalent): renders outer/tail split when `(tail …)` declared.
- **Tests**: rewrite all integration test fixtures using the new syntax; add property tests for tail-scoped matcher invariants and many-till capture; preserve `**/proptest-regressions/` per CLAUDE.md.
- **Docs** (`REFERENCE.md`, `CONTEXT.md`): update vocabulary — drop "effect" from user docs, add "tail" and "authorise"; add stdin-blindspot note for xargs/parallel; document `(many-till …)` and find limitations (predicate algebra still unsupported).
