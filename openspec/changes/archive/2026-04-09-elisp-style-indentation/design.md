## Context

The CST pretty-serializer (`pretty_serialize` in `crates/sexpr/src/cst.rs`)
formats all lists identically: children indent to `head_col + 1` (one past the
opening paren). The config language follows Emacs lisp conventions where special
forms indent body by +2 and function-call forms align arguments under the first
argument. The migration command produces output with noticeably wrong indentation
as a result, creating large diffs that obscure the actual syntactic changes.

Comments are also mispositioned: `pretty_write_no_whitespace` strips all
`Trivia::Whitespace` entries, causing whole-line comments to merge onto the
preceding line (their newline is lost).

## Goals / Non-Goals

**Goals:**

- `pretty_serialize` produces Emacs-style lisp indentation for all consumers.
- Whole-line comments are indented at the current indent level.
- Line-trailing comments preserve their exact whitespace gap.
- Blank lines before comments are preserved.
- Migration diffs are minimal (only structural syntax changes, not reformatting).

**Non-Goals:**

- Changing the Doc-based pretty-printer in `crates/pp/src/lib.rs` (separate
  rendering path, not used by migration).
- Modifying rewrite rules in `crates/config/src/migrate.rs` for trivia transfer.
- Special handling of `:effect` keyword-value pairs (being removed separately).

## Decisions

### 1. Form classification via lookup table

A static `&[&str]` array of special-form names determines indent style.

Special forms (body indent +2): `define`, `check`, `with-facts`, `when`,
`unless`, `rule`, `cond`.

Everything else uses function-call indent: align subsequent arguments under the
first argument (`paren_col + 1 + head_atom_width + 1`).

**Why not a trait/enum on CstNode?** The classification is a formatting concern,
not a structural one. Keeping it as a simple list in the pretty-printer avoids
coupling the CST data model to formatting policy.

**Why not configurable?** The set of forms is small, finite, and controlled by
this project. A table literal is the simplest correct solution.

### 2. Comment classification by preceding whitespace

A comment is **whole-line** if the `Trivia::Whitespace` entry immediately before
it in the trivia vector contains a `\n`. Otherwise it is **line-trailing**.

- **Whole-line**: emit `\n` + indent (at current level) before the comment text.
  If preceding whitespace contained `\n\n` or more, emit the blank lines too.
- **Line-trailing**: preserve the exact `Whitespace` entry before the comment
  as-is (it contains the spaces the user placed before `;;`).

This applies in `pretty_write_no_whitespace` — the method that formats rewritten
nodes. The existing `pretty_write` (for preserved nodes) already emits trivia
verbatim and needs no change.

### 3. Function-call indent calculation

For function-call style forms, the indent for arguments 2..N is:

```
paren_col + 1 + width_of_head_atom + 1
```

Example: `(or "a"` → paren at col 5, head is `or` (width 2), so args align at
col 5 + 1 + 2 + 1 = col 9, which is under `"a"`.

If the head is not a bare atom (e.g. a nested list), fall back to `paren_col + 1`
(current behaviour).

### 4. Change is confined to `PrettyCtx` and `pretty_write_no_whitespace`

The `pretty_write` method (used for nodes with intact trivia) writes trivia
verbatim. Only `pretty_write_no_whitespace` (used for rewritten nodes) and the
indent calculation in the standard list-formatting path need changes.

## Risks / Trade-offs

- **Lookup table maintenance**: Adding a new special form to the config language
  requires adding it to the table. → Low risk; the language evolves slowly and
  the table is co-located with the formatter.
- **Snapshot test churn**: Existing tests that assert on `pretty_serialize`
  output will need updating. → Acceptable; the new output is more correct.
- **Edge cases in function-call indent**: If the head atom is very long, aligning
  under the first argument pushes content far right. → The existing column-width
  overflow/cascade logic handles this (breaks to next line when exceeding width).
