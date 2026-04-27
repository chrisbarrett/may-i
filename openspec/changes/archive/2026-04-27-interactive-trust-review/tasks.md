## 1. Pretty-printing infrastructure

- [x] 1.1 Make `doc_from_sexpr` public in `crates/pp/src/lib.rs` — remove `#[cfg(test)]` gate, add `pub` visibility
- [x] 1.2 Add `pretty_form(canonical: &str, width: usize, color: bool) -> String` helper in `src/interactive.rs`
- [x] 1.3 Add test: canonical form string round-trips through `parse → doc_from_sexpr → pretty` producing indented output

## 2. Interactive review enhancements

- [x] 2.1 Add `term.clear_screen()` before rendering each rule in `interactive_review`
- [x] 2.2 Add trusted summary line at top of each screen ("N rules trusted across M files")
- [x] 2.3 Add progress HRule separator with label: `──── Rule 3/5 ── NEW ──`
- [x] 2.4 Replace `rule_meta.canonical_form.dimmed()` with `pretty_form()` in `render_rule_detail`
- [x] 2.5 Pretty-print both sides of diff in `render_diff` for CHANGED rules

## 3. list_status flow rewire

- [x] 3.1 When interactive + pending: skip `list_status_human` dump, call `interactive_review` directly
- [x] 3.2 After review, show grouped-by-file trusted summary (reuse existing code)
- [x] 3.3 Verify non-interactive and JSON paths are unchanged

## 4. Remaining display sites

- [x] 4.1 Update `list_status_human` pending rule display to use `pretty_form`
- [x] 4.2 Update `render_entry_detail` legacy view to use `pretty_form`
