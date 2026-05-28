## Context

Repro (against current `main` / `0.7.0`):

```
$ printf ';; just a top comment\n;; another\n\n;; trailer\n' > /tmp/x.lisp
$ wc -c /tmp/x.lisp
      65 /tmp/x.lisp
$ may-i fmt /tmp/x.lisp ; echo exit=$?
exit=0
$ wc -c /tmp/x.lisp
       1 /tmp/x.lisp
```

The data-loss path is in `src/cmd_fmt.rs::canonical_text` (lines 182–206):

1. `parse_cst(source)` returns `(forms=[], errors=[])`.
2. `canonicalise_forms(vec![])` returns `vec![]`.
3. The join produces `""`, then the trailing-newline preservation block pushes `'\n'` because the source ended in `\n`. Canonical text = `"\n"`.
4. `source != canonical`, so `std::fs::write(path, "\n")` overwrites the file.

`parse_cst` drops the trivia because of `crates/sexpr/src/cst.rs:405-425`:

```rust
while self.chars.peek().is_some() {
    let leading = self.collect_trivia();
    if let Some(node) = self.parse_node() {
        // attach leading to node
        …
    } else if !leading.is_empty()
        && !results.is_empty()                 // <-- never true on a comments-only file
        && let Some(last) = results.last_mut()
    { last.ann.trailing.extend(leading); }
}
```

When the file has no forms at all there is no "last" node to glue the trivia to, and `parse_cst` returns no errors either (comments and whitespace are legal trivia, not parse failures). So the formatter receives an empty form list from a non-empty, valid file.

## Goals / Non-Goals

**Goals:**

- Stop the silent data loss: `may-i fmt` on a formless-but-valid file must leave the file (or stdout) byte-identical.
- `--check` on the same input must report "clean" (exit `0`).
- Surface the invariant as a property test so future refactors of the parser or pretty-printer can't regress it.

**Non-Goals:**

- Reformatting whitespace inside comments-only files. If the user has irregular blank-line patterns between comments, we don't normalise them — preservation wins. (Rare case, and the parser doesn't currently model it.)
- Generalised "preserve all dangling trivia" behaviour in the CST. The parser-level fix is optional follow-up (see Decisions).
- Changing exit-code semantics for any other input shape.

## Decisions

### Fix at `cmd_fmt` rather than at `parse_cst`

**Chosen:** add an early exit in `cmd_fmt::canonical_text` (and propagate through `process_file` / `run_stdin_text`): when `parse_cst` returns zero forms and zero errors, return the source verbatim and signal "clean".

**Alternative considered:** fix `Parser::parse` in `crates/sexpr/src/cst.rs` to retain dangling trailing trivia (e.g. on a sentinel node, or by returning `(forms, dangling_trivia, errors)`).

**Why the cmd_fmt fix wins for this change:**

- The CST contract is "forms with attached trivia"; introducing a dangling-trivia channel ripples through every consumer (`canonicalise_forms`, `pretty_serialize`, migration passes) for a single edge case.
- The user-visible bug is data loss in `fmt`. The smallest correct fix is to not write when we have nothing meaningful to write. `source == canonical` already short-circuits the write — extending that guard to "and zero forms parsed" is one branch.
- A CST-level fix can land later as a separate hygiene change if other passes (e.g. migration) turn out to share the symptom. Currently they don't: `migrate` operates on the same parsed forms and similarly produces no output for a formless file, but its callers don't overwrite the file on empty output the way `fmt` does. (Verified by reading `src/cmd_migrate.rs`.)

### Property: formless input round-trips byte-identically

Add a proptest in `crates/sexpr/` (or `tests/`) generating inputs composed solely of comment lines and whitespace, asserting `parse_cst(s) → (forms, errs)` with `forms.is_empty() && errs.is_empty()` for every such `s`, and asserting `cmd_fmt`-equivalent canonicalisation returns `s` unchanged.

The CST-level property pins down the parser invariant ("no forms ⇒ no errors on legal trivia"). The cmd-level property pins down the user-visible invariant. Both are cheap.

### Exit code in `--check`

A formless file is, by the new requirement, already canonical. `--check` returns `0`, not `1`. This matches the spec's existing wording ("already canonically formatted") and avoids spurious CI failures on files that happen to be comments-only (header/license-only fragments included via `(load …)`).

## Risks / Trade-offs

- **Risk:** A user expects `may-i fmt` to canonicalise odd whitespace inside a comments-only file. → **Mitigation:** out of scope (Non-Goals). Document the behaviour in the spec scenario. The likely "odd whitespace" case (CRLF line endings, trailing tabs) is uncommon for comments-only files and can be handled by a future change if it ever surfaces.
- **Risk:** The early-exit guard hides a real parser bug where forms *should* have been parsed but weren't. → **Mitigation:** the guard only fires when `parse_errors` is also empty. A parse error still flows through the existing `Err(format!("parse error: …"))` path and exits `2`.
- **Trade-off:** We're leaving the parser's dangling-trivia drop in place. A later pass that wants to preserve "trailing comments after the last form" across reformatting (already handled today via `last.ann.trailing.extend`) will continue to work. Only the all-trivia case is special-cased, and only at the `fmt` boundary.
