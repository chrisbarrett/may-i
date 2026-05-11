## Context

The pretty-printer (`crates/pp/src/render/`) renders `Doc` trees back to
s-expression text with width-aware layout. It chooses among five layout
strategies — flat, fill, broken, broken-conservative, all-drop, and a
trivia-guided variant when source trivia is present — based on whether
the form's children fit, what their head atom is, and whether source
trivia forces breaks.

Two regimes already exist for indent computation:

1. **Body indent** (`render_body_indent`): forms with declared `indent N`
   place their first N arguments inline (special) and put body args at
   `paren_col + 2`. Used for `when`, `if`, `rule`, `define`, etc.

2. **Function-call alignment** (`render_broken_delim`,
   `render_broken_conservative_delim`): default forms align subsequent
   args under the first arg's start column. Cascade column is fixed at
   `paren_col + head_width + 2`.

The third path — **trivia-guided** (`render_trivia_guided_delim`) —
exists for forms whose source contains explicit newlines between
children. It emits per-child trivia rather than reflowing freely.
Trivia-guided cascade was *intended* to match function-call alignment
but currently drifts: each inline child updates `cascade_col` to its own
start column, so by the time a break is needed, cascade_col points at
the *last* inline arg, not the first.

`render_cond` is the fifth path: a dedicated renderer for `(cond …)`
that hardcodes clauses at `paren_col + 2`. Per Emacs / Common-Lisp
convention, cond clauses live at `paren_col + 1` (under the column
where the first clause would sit if inline).

The two output bugs (cond `+2`, cascade drift) become acutely visible
when `may-i migrate` rewrites a hand-formatted config — the diff is
unreadable, with clause columns shifted right and `(cond …)` blocks
floating 50+ columns out from their parent.

## Goals / Non-Goals

**Goals:**

- Cond clauses indent at `+1`, matching Emacs / Common-Lisp convention.
- Trivia-guided cascade matches function-call alignment: fixed under
  first inline arg, no drift.
- Hand-formatted configs round-trip stably through `may-i migrate
  --dry-run` (modulo intentional rewrites).
- Snapshot suite reviewed and accepted in one pass.

**Non-Goals:**

- Reworking the layout-strategy selection (flat/fill/broken/etc.). The
  bugs are localised to two functions.
- Adding new indent specs or new layout strategies. The contract gets
  *clearer*, not larger.
- Per-style/per-team indentation customisation (no `.editorconfig`-style
  knobs). The pretty-printer is opinionated.
- `may-i fmt` as a separate CLI command. That belongs to the next spec
  (canonicaliser scope).
- Cascade discipline beyond what trivia-guided needs. `render_broken_delim`
  is already correct.

## Decisions

### Cond renderer overrides body-indent computation

Currently `cond` is in `INDENT_SPECS` with N=0, which `render_body_indent`
interprets as "all body, indent +2". `render_cond` is dispatched ahead of
the indent-spec path in `render_node`, so the body-indent never actually
runs for cond — `render_cond` does its own computation.

The fix is purely inside `render_cond`: change `body_indent = indent + 2`
to `indent + 1` (and `body_col = body_indent + 1` follows naturally). The
INDENT_SPECS entry stays for keyword-coloring; the spec table now
explicitly documents that N=0 is reserved for forms with dedicated
renderers and the default body-indent does NOT apply.

**Alternative considered:** remove `cond` from INDENT_SPECS entirely.
Rejected — the same table feeds the syntax-highlighter, and we want
`cond` highlighted as a special form.

**Alternative considered:** change N=0 globally to mean `+1`. Rejected —
no other forms use N=0 today, but the semantic "all body at +2" is the
established defun-style and we don't want to change it covertly.

### Cascade discipline: fix at first inline arg, never update

`render_trivia_guided_delim` initialises cascade_col to either `+2`
(indent-spec forms) or `+1` (default). On each inline child, line 116
updates `cascade_col = child_start`. The intent was "track where the
last inline arg is" so that a subsequent break drops below it; the
effect is rightward drift.

Fix: update cascade_col only on the *first* inline child, then never
again. Track this with a flag or by comparing against the initial
sentinel value.

```rust
let mut cascade_col = if has_indent_spec { indent + 2 } else { indent + 1 };
let initial_cascade = cascade_col;
// …
if !has_broken && !has_indent_spec && cascade_col == initial_cascade {
    cascade_col = child_start;
}
```

After the first inline child, `cascade_col != initial_cascade` and the
condition stops firing. Subsequent inline children leave cascade fixed.

**Alternative considered:** initialise cascade_col directly to
`paren_col + head_width + 2` (under would-be first arg) and never
update. Rejected — when source trivia forces the first arg onto its own
line (head-alone case), we want cascade at `paren_col + 1`, not under a
phantom first-arg column. The "update on first inline child" formulation
handles both cases naturally.

**Alternative considered:** unify trivia-guided with `render_broken_delim`
entirely. Rejected for scope — trivia-guided exists to honour
per-child source trivia, which `render_broken_delim` doesn't do. Bring
the cascade behaviour into line; leave the trivia handling alone.

### Snapshot review, not blanket accept

The fix changes the output of many existing snapshots. Each snapshot
diff is reviewed by hand and committed deliberately. `INSTA_UPDATE=always`
runs are quick but invite false negatives where output drifts in a way
that masks regressions. Reviewing each diff catches both the targeted
fixes and any unexpected fallout.

## Risks / Trade-offs

**[Snapshot churn]** Many `oracle_trace_v1__*.snap` files contain
pretty-printed rule sources and will shift indent. → Reviewed
hand-by-hand during implementation; large changes flagged for closer
inspection. The changes should be *narrowing*: shifting cond clauses
and deeply-nested cascade columns *leftward*.

**[Existing cascade-aware tests]** A handful of unit tests in
`crates/pp/src/tests/rendering.rs` explicitly assert cascade-under-last
behaviour. → Inspected one-by-one; updated to assert
cascade-under-first. Tests that were passing only because the form was
small enough that "first" and "last" coincided continue to pass.

**[Trust hash stability]** Trust hashes are computed from canonical-form
strings. Whitespace is stripped before hashing (canonical form is
whitespace-insensitive), so indentation changes do NOT invalidate trust
hashes. Verified by inspecting `canonical_effect` and the hash input
pipeline.

**[`may-i fmt` is out of scope]** The fixed-point property "running
`may-i fmt` twice produces the same output" is a future concern. After
this change, the property holds for the cases tested but is not
formally established. The next spec (canonicaliser) will land it.

## Migration Plan

1. Implement `render_cond` clause-indent fix.
2. Implement `render_trivia_guided_delim` cascade fix (single-update
   guard).
3. Run `cargo test`. Fix the small set of unit tests that asserted the
   old behaviour.
4. Run with `INSTA_UPDATE=always`, then review each `.snap` diff
   manually. Reject any change that doesn't narrow indent or reflect
   the targeted fix.
5. Re-run `may-i migrate --dry-run` against `~/.config/may-i/config.lisp`
   and verify the diff is now readable.
6. Land in one or two commits per fix, with snapshot updates batched
   into their own commit for review legibility.

## Open Questions

- Does `render_broken_delim` need a parallel adjustment? It already uses
  fixed cascade under first arg, but we should verify with a property
  test that its output doesn't drift under any input.
- Are there any forms we should *add* to INDENT_SPECS as part of this
  pass (e.g. `match`, `cond`-likes)? Probably not — leave the table
  alone, focus on correctness of the existing rules.
