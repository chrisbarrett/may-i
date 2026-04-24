## Why

`may-i trust` dumps all rules at once (58KB+ of output), then asks if you want to review. The review flow uses program-level approval with dialoguer confirms rather than per-rule decisions. Canonical forms are displayed as flat single-line strings, making complex rules hard to read. Users can't focus on one rule at a time.

## What Changes

- **`git add -p` style interactive flow**: `may-i trust` presents one pending rule at a time on a cleared screen with `y/n/s/q` keybindings, a progress counter, and a trusted summary line for context.
- **Pretty-printed rule forms**: All canonical form display sites use the pretty-printer (`parse → Doc → may_i_pp::pretty`) instead of showing flat single-line strings. This applies to interactive review, the listing view, and diff rendering for changed rules.
- **Public `doc_from_sexpr`**: The existing `doc_from_sexpr` function in the pp crate is made public so canonical form strings can be converted to Doc trees for pretty-printing outside of tests.
- **Streamlined `list_status` path**: When interactive with pending rules, skip the full dump and go straight into per-rule review. Show the trusted summary after review completes.

## Capabilities

### New Capabilities

- `interactive-trust-review`: Screen-cleared per-rule review flow with progress tracking, pretty-printed forms, and single-key approval.

### Modified Capabilities

- `pretty-printing`: `doc_from_sexpr` becomes public API for converting s-expression strings to Doc trees.
- `trust-command`: `list_status` path changes from dump-then-ask to direct interactive review.

## Impact

- `crates/pp/src/lib.rs` — `doc_from_sexpr` visibility change from `#[cfg(test)]` to `pub`.
- `src/interactive.rs` — `interactive_review` gains screen clearing, progress counter, trusted summary, pretty-printed forms. `render_rule_detail` and `render_diff` updated to pretty-print.
- `src/cmd_trust.rs` — `list_status` rewired to skip dump when interactive + pending. `list_status_human` canonical form display updated.
- `src/cmd_trust.rs` — `render_entry_detail` legacy view updated to pretty-print forms.
