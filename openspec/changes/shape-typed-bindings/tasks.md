## 1. Parser-side shape declarations

- [ ] 1.1 Add reader/parser support for `(parameter NAME (one #v))`, `(parameter NAME (last #v))`, `(parameter NAME (set #v))`, `(parameter NAME (command #v))` declaration forms in `crates/config`.
- [ ] 1.2 Add reader/parser support for `(flag NAME (count #v))` declaration form.
- [ ] 1.3 Extend the parser-body validator to reject (with clear errors): shape forms outside `(parameter …)` / `(flag …)`, multiple shape forms on one declaration, and unknown shape-form heads.
- [ ] 1.4 Wire `(parameter NAME #v)` (no shape form) through as sugar for `(one #v)` — same AST node, no separate path; verify canonical-form serialisation is byte-identical to today's output.
- [ ] 1.5 Add proptest coverage for parser-body round-trip including all shape forms.

## 2. Binding-shape data model

- [ ] 2.1 Define the `Shape` enum (`Token`, `Command`, `CollectionToken`, `Count`) in the engine crate; mark contributor-facing in module docs.
- [ ] 2.2 Implement `shape_of_declaration(&ParameterDecl | &FlagDecl | &PositionalDecl | &RestDecl) -> Shape` per the assignments in the `binding-shapes` spec.
- [ ] 2.3 Persist declared shapes on the resolved parser entry so rule-body checking can look them up by `#var` name.
- [ ] 2.4 Unit-test every (declaration form → shape) mapping including the unannotated fallbacks.

## 3. Multi-occurrence parameter evaluation

- [ ] 3.1 Extend the tokeniser to retain all occurrences of a parameter (not just the last) when the declaration's shape is `(set …)` or `(count …)`.
- [ ] 3.2 Bind `(set #v)` to a `Vec<String>` (token list) preserving source order, including duplicates.
- [ ] 3.3 Bind `(count #v)` to a non-negative integer counting recognised occurrences across short, long, combined-short, and `=value` spellings.
- [ ] 3.4 Confirm `(last #v)` and the unannotated `(parameter NAME #v)` path continue to bind only the final occurrence's value — same behaviour as today.
- [ ] 3.5 Add proptest coverage for repeated-flag tokenisation under each shape.

## 4. Shape-checker pass

- [ ] 4.1 Implement the shape-check pass over rule bodies, invoked after parser resolution and before trust filtering. Walk every rule body and check each `#var` reference's shape against the consuming operator's signature.
- [ ] 4.2 Encode operator shape signatures: `authorise → Command`, `bound? → any`, `matches? → Token|Command`, `every? → Collection Token`, `some? → Collection Token`, `with-facts → Token|Command|Collection Token`.
- [ ] 4.3 Produce structured diagnostics carrying both spans (rule-body operator and parser declaration) plus the (operator, found shape, expected shape) triple.
- [ ] 4.4 Wire shape diagnostics into the existing diagnostic pipeline so they appear at config-load failure and `may-i check` consistently.

## 5. Rule-side quantifier evaluation

- [ ] 5.1 Parse `(every? #v PRED)` and `(some? #v PRED)` rule-body forms; `PRED` accepts the same single-token Pattern sublanguage as `(matches? …)`.
- [ ] 5.2 Implement evaluation: fold `PRED` over the bound collection; vacuous-true for `every?` on empty, vacuous-false for `some?` on empty.
- [ ] 5.3 Implement fact-binding capture under quantifiers per the `patterns` spec: `every?` retains captures only when the fold succeeds; `some?` retains captures of all matching elements.
- [ ] 5.4 Add proptest coverage: generate `(set #v)` bindings, random `PRED`s, verify the fold semantics match the reference implementation.

## 6. Elm-style error rendering

- [ ] 6.1 Implement a `render_shape_mismatch(&ShapeDiagnostic, &SourceText) -> String` function producing the format pinned in the `binding-shapes` spec (header, two excerpts with caret underlines, hint).
- [ ] 6.2 Implement the user-facing shape vocabulary mapping (`Token` → "a single value", etc.) used by the renderer; assert via tests that the internal names never leak.
- [ ] 6.3 Implement per-mismatch hint generation as a centralised function keyed by `(operator, found_shape)` → optional rewrite suggestion. Cover the families enumerated in the spec.
- [ ] 6.4 Add golden-output tests for each mismatch family using sample configs in `crates/engine/tests/golden/shape-mismatches/`.
- [ ] 6.5 Confirm the renderer's output respects existing terminal/colour conventions in `may-i-output`.

## 7. Canonical form and trust integration

- [ ] 7.1 Extend the canonical-form serialiser to emit the new shape forms verbatim; preserve the existing unannotated `(parameter NAME #v)` serialisation byte-for-byte.
- [ ] 7.2 Classify shape-changing rewrites as Class B in `crates/config/src/migration`; surface a Class B warning when a migration would alter a parameter's shape annotation.
- [ ] 7.3 Add hash-stability tests over a corpus of existing rule bundles to confirm trust entries continue to verify after the upgrade.

## 8. Documentation

- [ ] 8.1 Update `REFERENCE.md` to document the new shape forms (`(one …)`, `(last …)`, `(set …)`, `(command …)`, `(count …)`) and the new rule-body verbs `(every? …)` / `(some? …)`. Use the user-facing vocabulary throughout (no "shape", no internal type names).
- [ ] 8.2 Update `CONTEXT.md` contributor vocabulary table to add `Shape` (and its four members) alongside `Effect`, `Predicate`, `ArgPattern`, etc.
- [ ] 8.3 Add an `examples/` lisp file demonstrating the `rm` motivating case end-to-end (parser declaration + rule using `(every? …)`).
- [ ] 8.4 Cross-link `binding-shapes` from the Purpose of `parser-bindings` and `patterns` stable specs (during archive).

## 9. Verification

- [ ] 9.1 Run `cargo fmt` over all touched crates.
- [ ] 9.2 Run `may-i fmt` over any updated `examples/*.lisp` files.
- [ ] 9.3 Run `cargo test --workspace` and confirm all suites pass.
- [ ] 9.4 Run `cargo tarpaulin` and confirm coverage on the new shape checker, quantifier evaluation, and renderer is at parity with surrounding code; add proptests for any branch the existing tests miss.
- [ ] 9.5 Run `openspec validate shape-typed-bindings --strict` and resolve any spec/structure findings.
- [ ] 9.6 Run `prek` over the working tree; resolve any hook findings.
