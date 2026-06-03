## 1. Parser-side shape declarations

- [x] 1.1 Add reader/parser support for `(parameter NAME (one #v))`, `(parameter NAME (last #v))`, `(parameter NAME (set #v))`, `(parameter NAME (command #v))` declaration forms in `crates/config`.
- [x] 1.2 Add reader/parser support for `(flag NAME (count #v))` declaration form.
- [x] 1.3 Extend the parser-body validator to reject (with clear errors): shape forms outside `(parameter …)` / `(flag …)`, multiple shape forms on one declaration, and unknown shape-form heads.
- [x] 1.4 Wire `(parameter NAME #v)` (no shape form) through as sugar for `(one #v)` — same AST node, no separate path; verify canonical-form serialisation is byte-identical to today's output.
- [x] 1.5 Add proptest coverage for parser-body round-trip including all shape forms.

## 2. Binding-shape data model

- [x] 2.1 Define the `Shape` enum (`Token`, `Command`, `CollectionToken`, `Count`) in the engine crate; mark contributor-facing in module docs.
- [x] 2.2 Implement `shape_of_declaration(&ParameterDecl | &FlagDecl | &PositionalDecl | &RestDecl) -> Shape` per the assignments in the `binding-shapes` spec.
- [x] 2.3 Persist declared shapes on the resolved parser entry so rule-body checking can look them up by `#var` name.
- [x] 2.4 Unit-test every (declaration form → shape) mapping including the unannotated fallbacks.

## 3. Multi-occurrence parameter evaluation

- [x] 3.1 Extend the tokeniser to retain all occurrences of a parameter (not just the last) when the declaration's shape is `(set …)` or `(count …)`.
- [x] 3.2 Bind `(set #v)` to a `Vec<String>` (token list) preserving source order, including duplicates.
- [x] 3.3 Bind `(count #v)` to a non-negative integer counting recognised occurrences across short, long, combined-short, and `=value` spellings.
- [x] 3.4 Confirm `(last #v)` and the unannotated `(parameter NAME #v)` path continue to bind only the final occurrence's value — same behaviour as today.
- [x] 3.5 Add proptest coverage for repeated-flag tokenisation under each shape.

## 4. Shape-checker pass

- [x] 4.1 Implement the shape-check pass over rule bodies, invoked after parser resolution and before trust filtering. Walk every rule body and check each `#var` reference's shape against the consuming operator's signature.
- [x] 4.2 Encode operator shape signatures: `authorise → Command`, `bound? → any`, `matches? → Token|Command`, `every? → Collection Token`, `some? → Collection Token`, `with-facts → Token|Command|Collection Token`.
- [x] 4.3 Produce structured diagnostics carrying both spans (rule-body operator and parser declaration) plus the (operator, found shape, expected shape) triple.
- [x] 4.4 Wire shape diagnostics into the existing diagnostic pipeline so they appear at config-load failure and `may-i check` consistently.

## 5. Rule-side quantifier evaluation

- [x] 5.1 Parse `(every? #v PRED)` and `(some? #v PRED)` rule-body forms; `PRED` accepts the same single-token Pattern sublanguage as `(matches? …)`.
- [x] 5.2 Implement evaluation: fold `PRED` over the bound collection; vacuous-true for `every?` on empty, vacuous-false for `some?` on empty.
- [x] 5.3 Implement fact-binding capture under quantifiers per the `patterns` spec: `every?` retains captures only when the fold succeeds; `some?` retains captures of all matching elements.
- [x] 5.4 Add proptest coverage: generate `(set #v)` bindings, random `PRED`s, verify the fold semantics match the reference implementation.

## 6. Elm-style error rendering (miette-backed)

- [x] 6.1 Add `miette` as a workspace dependency; pick a single graphical reporter configuration and wire it into the diagnostic emission path used by config-load failures and `may-i check`.
- [x] 6.2 Define a `ShapeDiagnostic` type implementing `miette::Diagnostic` carrying both spans (rule-body operator site and parser-declaration site) as `#[related]` labels, plus the operator name, found shape, expected shape, and an optional hint string.
- [x] 6.3 Implement the user-facing shape vocabulary mapping (`Token` → "a single value", `Command` → "a command line", `Collection Token` → "a list of values", `Count` → "a count") used in `ShapeDiagnostic`'s rendered prose; assert via tests that the internal names never leak.
- [x] 6.4 Implement per-mismatch hint generation as a centralised function keyed by `(operator, found_shape)` → optional rewrite suggestion. Cover the families enumerated in the `binding-shapes` spec.
- [x] 6.5 Implement the pred-first miscall detector — `(every? PRED #v)` where the first argument is a Pattern and the second is a `#var` reference — and emit a dedicated hint pointing at the corrected `(every? #v PRED)` order (per design D7).
- [x] 6.6 Add golden-output tests for each mismatch family using sample configs in `crates/engine/tests/golden/shape-mismatches/`. Pin rendered output via `insta` snapshots.
- [x] 6.7 Confirm the renderer's output respects existing terminal/colour conventions in `may-i-output`; in hook mode the JSON path SHALL keep using structured fields, with the rendered text suppressed.

## 7. Parser-diagnostic uplift via the same renderer

- [x] 7.1 Survey existing config-load diagnostics in `crates/config` and `crates/sexpr`. Catalogue each error type, the span data it currently emits, and the rendered text quality (terse / no source excerpt / contributor-vocab leakage).
- [x] 7.2 Migrate each surveyed diagnostic to a miette `Diagnostic` implementation, attaching source spans from the sexpr reader. Keep the existing error semantics; only the rendering changes.
- [x] 7.3 Apply the user-facing vocabulary discipline: rename rendered text to remove contributor-internal jargon (`AST`, `Effect`, `Predicate`, `Expr`, `ArgPattern`) following the same mapping principle used for shape mismatches.
- [x] 7.4 Add hints to the high-frequency parse failures (unknown declaration kind, legacy form suggestions, missing `(flags …)`, `#var` outside permitted positions, `(many-till …)` outside parser body). Hint vocabulary lives in the same centralised module as the shape-mismatch hints.
- [x] 7.5 Add golden-output `insta` snapshots covering each migrated diagnostic to lock the rendered format.

## 8. Canonical form and trust integration

- [x] 8.1 Extend the canonical-form serialiser to emit the new shape forms verbatim; preserve the existing unannotated `(parameter NAME #v)` serialisation byte-for-byte.
- [x] 8.2 Classify shape-changing rewrites as Class B in `crates/config/src/migration`; surface a Class B warning when a migration would alter a parameter's shape annotation.
- [x] 8.3 Add hash-stability tests over a corpus of existing rule bundles to confirm trust entries continue to verify after the upgrade.

## 9. Documentation

- [x] 9.1 Update `REFERENCE.md` to document the new shape forms (`(one …)`, `(last …)`, `(set …)`, `(command …)`, `(count …)`) and the new rule-body verbs `(every? …)` / `(some? …)`. Use the user-facing vocabulary throughout (no "shape", no internal type names). Show `(every? #seq PRED)` argument order in every example (per design D7).
- [x] 9.2 Update `CONTEXT.md` contributor vocabulary table to add `Shape` (and its four members) alongside `Effect`, `Predicate`, `ArgPattern`, etc.
- [x] 9.3 Add an `examples/` lisp file demonstrating the `rm` motivating case end-to-end (parser declaration + rule using `(every? …)`).
- [x] 9.4 Cross-link `binding-shapes` from the Purpose of `parser-bindings` and `patterns` stable specs (during archive).

## 10. Verification

- [x] 10.1 Run `cargo fmt` over all touched crates.
- [x] 10.2 Run `may-i fmt` over any updated `examples/*.lisp` files.
- [x] 10.3 Run `cargo test --workspace` and confirm all suites pass.
- [x] 10.4 Run `cargo tarpaulin` and confirm coverage on the new shape checker, quantifier evaluation, and renderer is at parity with surrounding code; add proptests for any branch the existing tests miss.
- [x] 10.5 Run `openspec validate shape-typed-bindings --strict` and resolve any spec/structure findings.
- [x] 10.6 Run `prek` over the working tree; resolve any hook findings.
