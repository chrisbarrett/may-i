## Why

The trusted-programs listing in `may-i trust` uses a two-column layout where a single wide row (e.g. a config file declaring many long-named programs) pins the divider far to the right, blowing the right column past the terminal edge. The layout has no terminal-width awareness and the left column cannot wrap, so users on any non-trivially wide config see a broken, unreadable listing.

## What Changes

- **BREAKING (output format):** Replace the two-column "programs on left, file on right" layout with a sectioned layout: one section per source file, file path as a dimmed heading, comma-separated program names wrapped underneath at terminal width.
- Update the `Trust listing groups by file when all trusted` requirement and its scenarios in the `trust-command` spec to describe the new shape.
- JSON output is unchanged.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `trust-command`: the "Trust listing groups by file when all trusted" requirement changes from a two-column layout to a sectioned (heading + wrapped flow) layout.

## Impact

- `src/output/trust_groups.rs`: `render_trusted_groups` rewritten to emit `Layout::Stack` of `(heading, Indent(Wrap(program-names)))` sections.
- `src/cmd_trust.rs`: callers (`list_status_human`, `print_trusted_summary`) unaffected at API boundary — `TrustListing::render` keeps its signature.
- Snapshot tests for `trust_groups` and any `cmd_trust` integration snapshots regenerate.
- No change to `may-i-output` primitives — reuses existing `Stack`, `Indent`, `Text`, `Wrap`.
- No change to the trust store, hashing, gate, or JSON output.
