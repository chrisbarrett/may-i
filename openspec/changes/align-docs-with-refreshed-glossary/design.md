## Context

This change is a mechanical sweep aligning specs, code comments, rustdoc, and tests with the refreshed glossary in `CONTEXT.md`. Three threads converge:

1. **`wrapper` → `carrier` rename.** Glossary now defines `Carrier` (a program that carries an inner command in its argv) and retires `wrapper` as a casual usage. Specs and code still say wrapper.
2. **`matcher` / `combinator` → `Pattern` collapse** in user-facing prose. Glossary commits to "one kind of thing, the Pattern". The matcher/combinator split is contributor-only vocabulary, attached to `ArgPattern` / `Expr<T>` / `Predicate enum`.
3. **`patterns/spec.md` syntax fixes.** Spec uses postfix-glyph notation (`"branch"?`, `**`, `*+`) and references the retired `(tail …)` parser-body form. Real surface syntax is prefix s-expr (`(? "branch")`, `(* *)`, `(+ *)`) and `(flags MODE) (rest …)`.

## Goals / Non-Goals

**Goals:**
- Spec prose, code comments, rustdoc, and test names use the refreshed vocabulary.
- `patterns/spec.md` syntax notation matches what `crates/config/src/pattern.rs:450-508` actually parses.
- No DSL surface, runtime, or trust-hash behaviour changes.

**Non-Goals:**
- Refactoring the `Wrapping`/`wrapper`-named types in `crates/core/src/ast.rs` and friends (out of scope; internal API rename is a follow-up if it lands).
- Adding new requirements to any spec.
- Reorganising spec files into the new bucket taxonomy (`rules-and-evaluation`, `parsing`, etc.) — separate effort.
- Updating CHANGELOG (pre-1.0; this is internal hygiene).

## Decisions

### Most edits are hygiene, not spec deltas

The `spec-conventions` rule (proposal `rules` field) says "Pure structural / hygiene edits to existing specs (heading shuffles, prose tweaks that touch no `### Requirement:` body) go in tasks.md, not as spec deltas."

The `wrapper → carrier` and `matcher/combinator → Pattern` rewrites are vocabulary swaps in prose and headings; they don't change requirement semantics. They go in tasks.md.

The exception is `patterns/spec.md` line 164, which sits inside a `### Requirement:` body and conditions the requirement on a retired form. The text describes behaviour that doesn't exist any more — a real requirement-text change, not hygiene. This needs a delta.

**Alternative considered:** Treat the postfix-glyph notation (lines 227-268) as a requirement change too, since the wrong syntax is in requirement bodies. Rejected: the surrounding requirements describe semantics (cardinality matching), not syntax — the example notation is a documentation defect, not a behaviour claim. A hygiene rewrite is sufficient.

### One bundled change, not three

User confirmed one change covering all three sweeps. Reasoning: shared theme (glossary alignment), shared review surface (mostly docs), no good seam to split on. Splitting would triple the openspec overhead for what is essentially one editing pass.

### Code rename scope

`wrapper` appears in code comments, rustdoc, and test names. Identifier renames (function names, struct fields, etc.) are out of scope — that would touch the public Rust API surface and is a separate engineering decision. Tasks.md restricts code edits to comments, rustdoc, and test names; not identifiers.

## Risks / Trade-offs

- **Risk:** mechanical rename introduces accidental case mismatches (e.g. `Wrapper` in a type name doesn't get renamed but a `wrapper` in prose does). → Mitigation: tasks.md explicitly limits code edits to comments / rustdoc / test names; preserve identifier casing untouched.
- **Risk:** `(tail …)` is referenced in archived openspec changes under `openspec/changes/archive/*`. → Mitigation: archives are historical and frozen; do not edit.
- **Trade-off:** Bundling three sweeps means a larger diff. Accepted given shared theme.
