## Context

Currently, the migration command uses a two-phase diff system:
1. `compute_diff()` in `sexpr/src/diff.rs` compares CST structures node-by-node
2. `render_diff()` in `output/src/diff_renderer.rs` (~1040 lines) handles two-column layout, ANSI colors, terminal width detection, truncation, alignment, and fold markers

The custom renderer is complex and prone to edge-case bugs (multi-byte characters, ANSI escape sequences, column alignment). The CST-based diff compares structures, then pretty-prints both versions - which can differ from actual text output.

## Goals / Non-Goals

**Goals:**
- Replace custom diff rendering with simplified text-based diff using `similar` crate
- Show changed lines with `+` / `-` prefixes and 3 lines of context
- Display file path header with `~` for HOME prefix
- Color output when stdout is TTY and `NO_COLOR` is not set
- Simplify error messages and make interactive prompt safer (default to No)
- Reduce code complexity and maintenance burden
- Use snapshot tests for diff output verification

**Non-Goals:**
- Preserving the two-column layout format
- Preserving pager support (users can pipe to `less` if needed)
- Detecting specific form counts (just text diff)
- Custom color schemes

## Decisions

### Decision: Use `similar` crate with simplified format (no hunk headers)

**Rationale**: We want clean output without the complexity of standard unified diff headers. The file path header provides sufficient context.

**Alternatives considered:**
- Full git-style unified diff with `---` / `+++` headers and `@@` hunk markers: Too verbose for our use case
- No headers at all: Hard to tell which file is being migrated
- File path header only: Clean and sufficient

### Decision: 3 lines of context

**Rationale**: Standard git diff default, provides enough context without being overwhelming.

### Decision: Default prompt to "No" (`[y/N]`)

**Rationale**: Safer - accidental Enter press cancels instead of applies. Users must explicitly confirm.

### Decision: Remove pager support

**Rationale**: Migration diffs are typically small (only changed forms). Users can pipe to `less` if needed.

### Decision: Use snapshot tests with `insta`

**Rationale**: `insta` is already a dev dependency. Snapshot tests capture exact output format and make it easy to review changes.

## Risks / Trade-offs

**Risk**: Users familiar with two-column format may be confused
**Mitigation**: Simplified format is actually more standard (like git diff). Document in release notes.

**Risk**: Long diffs without pager may scroll off screen
**Mitigation**: Rare case - migration typically changes only a few forms. Users can pipe to `less`.

**Risk**: Removing `compute_diff()` may break other code
**Mitigation**: Check all usages - it appears only used in `cmd_migrate.rs` and tests.

## Open Questions

None - all requirements confirmed with user:
- Simplified format with file path header ✓
- 3 lines of context ✓
- Colors with NO_COLOR support ✓
- No form counting ✓
- [y/N] prompt ✓
- Snapshot tests ✓
