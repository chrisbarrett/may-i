## Why

The CLI bucket contains 4 specs: `claude-code-hook`, `opencode-context`,
`eval-stdin`, `fmt-command`. Three of those — Claude Code hook protocol,
OpenCode context ingestion, eval-via-stdin — describe the same surface
from a different angle: how an external harness hands a command (and
optional context) to `may-i` and consumes the response. They overlap in
how stdin is parsed, how missing input is handled, and what facts the
harness can supply.

This change folds `opencode-context` and `eval-stdin` into
`claude-code-hook` so the harness-input contract lives in one place. The
broader rename `claude-code-hook` → `harness-integration` (the umbrella
name that better fits the absorbed scope) is deferred to the
`rename-specs-to-vocab` change.

Net 4 → 2 CLI specs.

## What Changes

- **Fold `opencode-context` → `claude-code-hook`**: 3 requirements about
  explicit OpenCode-agent context ingestion, gating, and trace
  inspectability.
- **Fold `eval-stdin` → `claude-code-hook`**: 3 requirements about
  reading commands from stdin, ambiguous-input detection, and
  missing-input detection — all part of the harness-input contract.
- **Keep `fmt-command` standalone** (143 lines, 5 reqs — distinct CLI
  surface, no harness coupling).

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `claude-code-hook` — ABSORBS `opencode-context` and `eval-stdin`. 6
  requirements added to its existing 4.

### Removed Capabilities

- `opencode-context` — folded into `claude-code-hook`. Directory removed
  at archive.
- `eval-stdin` — folded into `claude-code-hook`. Directory removed at
  archive.

## Spec-delta convention

Source-spec deltas list `## REMOVED Requirements` as `### Requirement:
NAME` blocks with **Reason** and **Migration** lines. Target-spec deltas
list `## ADDED Requirements` with full body and `#### Scenario:` children
copied verbatim from the source files.

## Impact

- `openspec/specs/claude-code-hook/spec.md` — receives 3 from
  `opencode-context` and 3 from `eval-stdin`. Total 10 requirements
  after the change archives. Purpose may need expansion to mention
  OpenCode and stdin handling.
- 2 source spec directories removed at archive.
- No source-code, test, or runtime config changes.

## Compatibility

No requirement content changes.
