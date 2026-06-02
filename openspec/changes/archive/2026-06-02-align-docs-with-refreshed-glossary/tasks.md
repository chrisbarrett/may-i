# Tasks

## 1. Patterns spec syntax fix (requirement-bearing)

- [x] 1.1 Apply the MODIFIED Requirement from `specs/patterns/spec.md` to `openspec/specs/patterns/spec.md`: replace the `(tail …)`-conditioned outer-slice requirement (around line 162) with the `(flags MODE)`-driven version and its three scenarios.
- [x] 1.2 In the same `openspec/specs/patterns/spec.md`, replace postfix-glyph notation inside the quantifier requirements with prefix s-expr surface syntax: `"branch"?` → `(? "branch")`, `*+` → `(+ *)`, `**` → `(* *)`. Update each scenario's WHEN/THEN to match.
- [x] 1.3 Update `openspec/specs/patterns/spec.md` Purpose prose: `parser-declared tail scoping` → `parser-declared outer-slice scoping`.
- [x] 1.4 Grep `openspec/specs/patterns/spec.md` for any residual `tail slice`, `(tail …)`, `(tail (after …))`, or wrapper-tail references; rewrite each in terms of `(rest …)` and `(flags MODE)` or remove if redundant.

## 2. `wrapper` → `carrier` rename in user-facing spec prose

- [x] 2.1 Rewrite `wrapper`/`wrapping`/`wrapper tool` to `carrier` in `openspec/specs/patterns/spec.md`. Preserve identifier-like uses (e.g. names of forms) untouched.
- [x] 2.2 Same rewrite in `openspec/specs/parser-bindings/spec.md`.
- [x] 2.3 Same rewrite in `openspec/specs/traces/spec.md`.
- [x] 2.4 Same rewrite in `openspec/specs/facts/spec.md`.
- [x] 2.5 Same rewrite in `openspec/specs/fact-predicates-in-args/spec.md`.
- [x] 2.6 Same rewrite in `openspec/specs/output-rendering/spec.md`.
- [x] 2.7 Same rewrite in `openspec/specs/migration-system/spec.md`.
- [x] 2.8 Same rewrite in `openspec/specs/trust-hashing/spec.md`.
- [x] 2.9 Same rewrite in `openspec/specs/pretty-printing/spec.md`.
- [x] 2.10 Same rewrite in `openspec/specs/spec-conventions/spec.md` (and add `Carrier` to the user-vocabulary register summary if listed there).
- [x] 2.11 Sweep remaining `openspec/specs/**/*.md` (excluding `openspec/changes/archive/`) with `rg "\bwrapper" openspec/specs/` and fix any stragglers.

## 3. `wrapper` → `carrier` rename in code comments, rustdoc, and test names

- [x] 3.1 Rewrite `wrapper`/`wrapping` to `carrier`/`carrying` in all rustdoc and comment text under `src/` and `crates/`. Do NOT rename identifiers (function names, struct fields, enum variants, type names) — text edits only.
- [x] 3.2 Rename test function names that contain `wrapper` to use `carrier` (e.g. `wrapper_tail_recurse` → `carrier_rest_recurse`). Update any call sites within tests. Check that test discovery still finds them after rename.
- [x] 3.3 Run `cargo test` to confirm nothing broke and `cargo fmt`.

## 4. `matcher` / `combinator` → `Pattern` in user-facing spec prose

- [x] 4.1 In `openspec/specs/patterns/spec.md`, replace user-facing prose uses of `matcher` and `combinator` with `Pattern`. Keep `(flag …)`, `(parameter …)`, etc. as concrete examples; the umbrella term is `Pattern`.
- [x] 4.2 Same rewrite in `openspec/specs/traces/spec.md`.
- [x] 4.3 Same rewrite in `openspec/specs/fact-predicates-in-args/spec.md`.
- [x] 4.4 Same rewrite in `openspec/specs/facts/spec.md`.
- [x] 4.5 In `openspec/specs/parser-engine-invariants/spec.md`, `testing-strategy/spec.md`, and `code-quality/spec.md` — these are contributor-facing or meta — preserve `matcher`/`combinator` where they sit next to `ArgPattern` / `Expr<T>` / `Predicate enum`. Audit only and leave as-is unless the prose is user-facing.

## 5. Verify and archive

- [x] 5.1 `openspec validate align-docs-with-refreshed-glossary --strict` — expect clean.
- [x] 5.2 Run `scripts/validate-spec-frontmatter.sh` to confirm no frontmatter regressions.
- [x] 5.3 `rg "\bwrapper\b" openspec/specs/ src/ crates/ -g '!archive'` returns zero hits (or only intentional residuals justified in a comment).
- [x] 5.4 `rg "\(tail " openspec/specs/ -g '!archive'` returns zero hits.
- [x] 5.5 `rg '"\w+"\?|\*\+|\*\*' openspec/specs/patterns/spec.md` returns zero hits (no postfix-glyph notation left).
- [ ] 5.6 Run `/opsx:archive align-docs-with-refreshed-glossary` once tasks land.
