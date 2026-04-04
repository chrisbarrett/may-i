## Why

The `migrate` command produces output with poor indentation that doesn't match
the conventions used in the source config file. The pretty-serializer in
`crates/sexpr/src/cst.rs` uses a single indentation strategy (align children
under the opening paren at `col+1`) but the config language follows Emacs
lisp-style conventions: special forms indent body by +2, function-call forms
align arguments under the first argument. This creates unnecessarily large diffs
during migration and makes the output harder to read.

## What Changes

- Add form-aware indentation to `pretty_serialize` in `crates/sexpr/src/cst.rs`:
  special forms (`define`, `check`, `with-facts`, `when`, `unless`, `rule`,
  `cond`) get +2 body indent; everything else aligns arguments under the first
  argument (function-call style).
- Classification via a simple `&[&str]` lookup table of special-form names.
- Fix comment positioning in `pretty_write_no_whitespace`: whole-line comments
  (preceded by whitespace containing `\n`) get newline + indent at current
  level; line-trailing comments (no `\n` in preceding whitespace) preserve
  their exact whitespace gap. Blank lines before comments are preserved.

## Capabilities

### New Capabilities

- `elisp-style-indent`: Emacs-style form-aware indentation for the CST
  pretty-serializer, with correct comment positioning.

### Modified Capabilities

- `cst-roundtrip`: The pretty-serializer output format changes; existing
  roundtrip expectations may need updating.

## Impact

- `crates/sexpr/src/cst.rs`: `PrettyCtx`, `pretty_write`, and
  `pretty_write_no_whitespace` are modified.
- `crates/pp/src/lib.rs`: No changes expected (separate Doc-based formatter).
- `src/cmd_migrate.rs`: No changes expected (consumes `pretty_serialize`).
- `tests/migration_diff.rs`: Snapshot expectations will change.
- Any test in `crates/sexpr` that asserts on `pretty_serialize` output.
