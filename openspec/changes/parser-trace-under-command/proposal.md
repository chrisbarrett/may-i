## Why

In `may-i check` failure traces, the resolved parser is rendered as a standalone right-aligned row at the top of the trace, separated from the `command` row by a blank line. The visual gap and position imply parser is independent context, when in fact it is metadata about how the immediately-following `command` was tokenised. Pairing the two rows makes the relationship obvious and removes a blank line of vertical clutter per failure.

## What Changes

- Render the resolved parser as a sibling row directly under the `command` row in the human-readable trace, sharing the same two-column geometry: `parser │ <style>[ parameters (...)][ tail (...)]`.
- Drop the standalone parser row that currently sits above `command` along with its trailing blank line.
- JSON trace output is unchanged.

## Capabilities

### New Capabilities
*(none)*

### Modified Capabilities
- `human-evaluation-trace`: parser row placement moves from above `command` to immediately below it, sharing the kv layout used by other header rows.

## Impact

- Affected code: `src/output/mod.rs` (parser-row layout for `TraceEntry::Parser`); `src/annotation.rs` only insofar as ordering of `TraceEntry` emission relative to the command header may need adjustment.
- Affected output: text-mode `may-i check` failure traces, and any other surface that renders `TraceEntry::Parser` (currently only `cmd_check`).
- Snapshot tests under `crates/engine/src/test_generators/` and any insta snapshots in `src/snapshots/` that capture trace text will need updating.
- No API, config-syntax, or wire-format changes.
