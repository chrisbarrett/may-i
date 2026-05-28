## Context

The `may-i trust` listing for fully-approved programs is built in `src/output/trust_groups.rs` using `Layout::Columns`. Each `ColRow` carries program names (comma-joined) on the left and the source file (`shorten_home`-ed, dimmed) on the right. The divider column is computed in `crates/may-i-output/src/lib.rs:343-351` as `max(left_width) + 1`, with no terminal-width cap. `ColContent::Breakable` (lib.rs:193-200) provides wrapping only for the right side; the left side is always atomic.

In practice the left side is the variable-length thing (any user may have a config file with many long script paths as program names), while the right side is uniformly long file paths. Any single wide left value pushes the divider — and therefore the right column — past the terminal edge.

## Goals / Non-Goals

**Goals:**

- Listing fits any reasonable terminal width without horizontal overflow on the right side.
- Program names from a single source file wrap naturally across multiple lines.
- File paths remain visible in full (or `~`-shortened) without truncation.
- Reuse existing `may-i-output` primitives. No new `Layout` variant.

**Non-Goals:**

- Re-architecting the `Layout::Columns` divider mechanism for other call sites (eval/check rendering).
- Changing JSON output.
- Changing the pending-program "detail" rendering above the trusted listing.
- Changing the trust store, hashing, or gate.

## Decisions

### D1. Sectioned layout, not a wrappable two-column layout

The trusted listing becomes a stack of sections. Each section is `Stack(Indent(2, Text(file-heading)), Indent(4, Wrap(program-items)))` separated by `Blank`.

```
  ~/.config/nix-configuration/.may-i.lisp
    op

  ~/.../emacs.lisp
    ./scripts/test-affected.sh, ./scripts/affected-tests.sh,
    ./scripts/run-tests.sh, emacs, emacs-present, emacsclient
```

**Alternatives considered:**

- *Extend `ColContent::Breakable` to the left side.* Would preserve the column aesthetic. Rejected: requires a new primitive (`BreakableLeft`) and a non-trivial divider constraint-solve when both sides can wrap; the column itself buys little when right-side content is uniformly long.
- *Swap orientation (file left, programs right via `Breakable`).* Reuses existing primitive. Rejected: file paths are themselves ~70 chars, so the divider still gets pushed far right — same disease, different patient. Reading order also reverses.
- *Cap divider, elide left.* Trivial. Rejected: throws away the information users explicitly came to read (which programs are trusted).

### D2. Use `Layout::Wrap`, not `ColContent::Breakable`

`Wrap` (lib.rs:444-486) inserts the separator between items and word-wraps to `term.width - indent`. It does not append a trailing separator on the wrapped boundary the way `Breakable` does. For comma-separated program names this is the conventional flow style (`a, b, c,\nd, e`) — acceptable; matches how prose-style lists wrap in CLI output.

### D3. Heading styling: dimmed full home-shortened path

The current right column uses `shorten_home(file).dimmed()`. Carrying `dimmed()` to the heading keeps the file path visually subordinate to the program names (content > context). Same `shorten_home` applies.

### D4. Inter-section gap: single blank line

A blank line per section gives the eye a clear group boundary without inflating vertical space. Zero blanks risks the heading visually merging with the previous section's wrapped tail.

### D5. Pending-rule path unchanged

`list_status_human` in `src/cmd_trust.rs:245` already renders pending programs with badges in a different format; this change only touches `TrustListing::render` / `render_trusted_groups`, which is the surface used for fully-approved entries (with optional `Trusted:` banner when pending entries are also present).

## Risks / Trade-offs

- **Reduced density** → Sectioned format uses more vertical space than the original two-column layout when many files each have a single program. Acceptable: vertical scrolling is cheap, horizontal overflow is not.
- **Snapshot churn** → Snapshots in `src/output/snapshots/` and any integration tests asserting the trusted listing format must regenerate. Acceptable, expected.
- **Spec scenario rewrite** → The `Trust listing groups by file when all trusted` scenarios literally show the old two-column shape; they need to be rewritten to show the new shape. This is the substantive spec delta.

## Migration Plan

Pre-1.0 project, no user-config migration needed. Format change is observed by users in human-readable output only; scripts use `--json` (unchanged).

## Open Questions

None blocking.
