## Context

The human-readable `may-i check` trace currently emits the resolved parser as a standalone right-aligned row at the very top of the trace block, followed by a blank line, followed by the `command` row and rule listings. Rendering is driven by `TraceEntry::Parser` in `src/annotation.rs` and `src/output/mod.rs:202-223`. Order of emission already places `TraceEntry::Parser` first; the visual gap is produced by how that variant is laid out, not by trace-order plumbing.

The other "header" rows in the trace (`command`, `facts`) use `ColRow::kv` so they share the two-column kv geometry — a left-side label, a `│` divider, and a right-side value. The parser row deliberately diverges by spanning the left column with `ColAlign::Right` and an empty right column, producing the lone top-of-trace banner.

## Goals / Non-Goals

**Goals:**
- Render the parser row as a sibling of the `command` row, using the same kv geometry.
- Eliminate the blank line currently introduced by the standalone parser banner.
- Preserve the full information currently carried: style name, parameter spellings (when non-empty), tail boundary spec (when present).

**Non-Goals:**
- No suppression of the parser row when the parser is the default `gnu` with no parameters/tail. (Considered and rejected for this cut — see Decisions.)
- No change to JSON trace output.
- No change to `ParseDiagnostics` row placement.

## Decisions

### Use `ColRow::kv` with label `parser`, render under `command`

Switch the `TraceEntry::Parser` arm in `src/output/mod.rs` to push a `ColRow::kv("parser", <value>)` instead of a right-aligned standalone row. Move the entry's emission so it lands in the same `current_rows` group as the `command` row, immediately after it.

The right-side value reuses the current formatting logic, just without the leading space and with the surrounding label/divider responsibilities transferred to the kv helper:

```
parser │ gnu
parser │ gnu  parameters (-X --request)
parser │ gnu  parameters (-X --request)  tail (after :flags)
```

**Alternative considered**: Inline the parser tag on the `command` row itself (`command │ git push  (parser: gnu)`). Rejected because right-column width pressure on long commands would force wrapping, and the kv layout keeps each fact independently legible.

### Always show, even for default `gnu`

The discovery conversation considered suppressing the row when style is default and no tail/parameters are present. Deferred — keeping the row unconditional avoids a branch in this first cut and lets us see the relocated layout before deciding what to hide. A follow-up change can introduce suppression if the `gnu`-only row still reads as noise post-relocation.

### Order of emission stays as-is

`TracingFold::record_parser` already runs before the rule-trace entries are pushed, so `TraceEntry::Parser` is the first entry in `traces`. The renderer in `src/output/mod.rs` is responsible for pairing it with the `command` row. No changes to `TracingFold` are required.

## Risks / Trade-offs

- [Existing snapshot tests capture trace text] → Update insta snapshots and any oracle-trace fixtures. Run `cargo insta review` after the change.
- [Parser row still rendered for the no-info case] → Accepted for this cut; suppression deferred to a follow-up change.
- [Right-column value for parser with parameters and tail can be long] → The kv layout already wraps long right values; same behaviour applies here.
