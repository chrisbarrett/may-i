## Context

`(tail …)` has two distinct uses in the DSL surface that share a head atom but live in different positions:

1. **Parser-body**: `(parser PROG (style …) (tail (after BOUNDARY)))` — declared a tail slice inside a parser declaration. RETIRED. Replaced by `(flags MODE) (rest #var)`. The loader rejects it at `crates/config/src/parser_form.rs:167-175` with a migration hint.
2. **Rule-body**: `(rule PROG (tail (authorise)))` — recurses on the carrier's rest slice from a rule body. STILL VALID. Parses to `ArgPattern::Tail` via `crates/config/src/pattern.rs:279-303`. Resolves the slice from the parser's `(flags MODE)` at `crates/engine/src/eval/effects.rs:412-462`.

The `align-docs-with-refreshed-glossary` change fixed only `patterns/spec.md`'s parser-body reference. The remaining stale parser-body references in `parser-bindings/spec.md` are the scope of this change.

## Goals / Non-Goals

**Goals:**
- `parser-bindings/spec.md` describes `(parser …)` body kinds the way the loader accepts them.

**Non-Goals:**
- Touching rule-side `(tail (authorise))` references. Still valid.
- Editing `pretty-printing/spec.md`. The canonicaliser at `crates/config/src/canonicalise.rs:13-17` deliberately keeps legacy `(tail …)` sortable "during the migration window" so v1→v2 pretty-printing stays stable. The spec's canonical-sort requirement matches that behaviour.
- Editing `migration-system/spec.md`'s `strip_redundant_boundary` requirement. The migration operates on legacy v1 configs and is still load-bearing.
- Touching archived openspec changes under `openspec/changes/archive/`. Historical.
- Renaming or removing `ArgPattern::Tail` in code. Out of scope.

## Decisions

### One delta spec, one capability touched

Both edits sit inside two `### Requirement:` blocks of `parser-bindings/spec.md`:

- "Parser body is a form-list of declarations" — kinds-list bullet referencing `(tail …)` must go; a rejection scenario is added.
- "`(authorise)` is the sole recursion verb" — the "Authorise inside tail" scenario's `GIVEN` uses the retired parser-body form; rewrite it to use the supported `(flags posix) (rest #cmd)` shape.

Both are requirement-body changes (substance, not prose), so they go in a delta — not in tasks.md hygiene per `spec-conventions`.

### Pretty-printing stays untouched

Initially considered including a `pretty-printing/spec.md` delta to remove `(tail …)` from the canonical parser-body sort. Rejected after reading `crates/config/src/canonicalise.rs:13-17`: the canonicaliser still places legacy `(tail …)` last so that v1 configs round-trip cleanly through `may-i fmt` during the migration window. The spec accurately reflects code behaviour. Removing it from the spec without also removing it from code would create a new divergence — the inverse of the problem we're fixing.

### Migration-system stays untouched

The `strip_redundant_boundary` requirement (lines 122-148) inspects "the prelude's `(tail (after STR…))` token set". The current prelude (`crates/config/src/prelude.lisp`) declares no `(tail …)` forms; the migration runs against legacy v1 configs that may declare them. The requirement text still describes correct behaviour for that purpose. Unchanged.

## Risks / Trade-offs

- **Risk:** A reader sees `(tail (authorise))` retained in rule-body contexts and infers the parser-body form is also retained somewhere. → Mitigation: the modified requirement explicitly lists kinds and adds a rejection scenario showing the loader fails.
- **Risk:** Treating this change as a follow-up makes the picture incomplete until both `align-docs-with-refreshed-glossary` and this change land. → Mitigation: both are small; this one can move quickly.
