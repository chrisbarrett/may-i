## Why

A grilling session against `CONTEXT.md` added 10 missing user/contributor terms (Advisory, Trace, Prelude, Carrier, Quantifier, Wildcard, Many-till, Outer slice, Tokenisation, Integrity) and corrected several existing entries. The specs and codebase still use older vocabulary and stale syntax notation that no longer match the refreshed glossary or current implementation. Aligning them now prevents the inconsistencies from compounding as new specs land.

## What Changes

- **Rename `wrapper` → `carrier`** across user-facing spec prose, code comments, rustdoc, and tests. ~34 spec refs plus code/test occurrences. The Authorise mental model is "recurse into the inner command of a carrier", not "wrap".
- **Replace `matcher` / `combinator` with `Pattern`** in user-facing spec prose (`patterns`, `traces`, `rule-decisions`). Glossary commits to "one kind of thing, the Pattern" — the matcher/combinator split belongs only next to `ArgPattern` / `Expr<T>` / `Predicate enum` in contributor sections.
- **Fix stale syntax notation in `openspec/specs/patterns/spec.md`**:
  - Lines 227-268 use postfix-glyph notation (`"branch"?`, `**`, `*+`) that does not match the real prefix s-expr surface syntax (`(? "branch")`, `(* *)`, `(+ *)`).
  - Line 164 references the retired `(tail …)` parser-body form. The outer/tail split is unconditional and driven by `(flags MODE)`; the requirement text must be rewritten to reflect this.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `patterns`: rewrite the requirement around outer-slice visibility (line 164) to drop the retired `(tail …)` condition and reference `(flags MODE)` instead, since the current text describes behaviour that no longer exists.

## Impact

- Spec prose (multiple files under `openspec/specs/`).
- Rustdoc, code comments, and test names mentioning `wrapper` / `tail`.
- No runtime, DSL surface, or trust-hash impact.
- Glossary entries already updated in `CONTEXT.md`; this change brings the rest of the codebase into line.
