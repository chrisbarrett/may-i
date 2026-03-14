## Context

The `eval --json` command currently outputs a `spans` array where each span represents a segment of the command with its permission level. When commands contain multiple operators or whitespace, consecutive `ignore` permission spans are emitted separately:

```json
[
  {"text": "true", "permission": "allow"},
  {"text": " ", "permission": "ignore"},
  {"text": "&&", "permission": "ignore"},
  {"text": " ", "permission": "ignore"},
  {"text": "curl", "permission": "ask"}
]
```

This is faithful to the parser output but creates unnecessary noise for consumers who want to render syntax-highlighted commands. The optimization coalesces adjacent `ignore` spans while preserving semantic command boundaries.

## Goals / Non-Goals

**Goals:**
- Reduce JSON payload size for commands with multiple operators/whitespace
- Simplify consumer code by reducing the number of spans to iterate
- Maintain exact text reconstruction (concatenating spans reproduces original command)
- Preserve semantic boundaries between evaluated commands

**Non-Goals:**
- Changing the output schema or structure
- Coalescing `allow`/`ask`/`deny` spans (these represent distinct commands)
- AST-level changes to the parser
- Breaking changes to existing consumers

## Decisions

**Decision: Coalesce only `ignore` spans**

Rationale: Commands with `allow`/`ask`/`deny` permissions represent separate evaluation units. Keeping them separate allows consumers to:
- Apply per-command tooltips or actions
- Display individual command boundaries clearly
- Map spans back to their evaluation results

`ignore` spans (whitespace, operators) are purely syntactic - merging them doesn't lose semantic information.

**Decision: Implement as a separate `coalesce_spans()` function**

Rationale: Separating coalescing from span building:
- Keeps `build_spans()` focused on its single responsibility
- Allows independent testing of coalescing logic
- Makes the transformation explicit in the pipeline
- Easier to modify or disable if needed

**Decision: Coalesce after building, before JSON serialization**

Rationale: This maintains a clean separation:
1. Parse command → segments
2. Build spans from segments + decisions
3. **Coalesce adjacent ignore spans**
4. Serialize to JSON

## Risks / Trade-offs

**[Risk] Consumers might rely on span count or structure**
→ **Mitigation**: The output schema is unchanged - only the number of spans varies. This is additive optimization, not a breaking change. Consumers that iterate spans will continue to work correctly.

**[Risk] Performance overhead of an extra pass**
→ **Mitigation**: Coalescing is O(n) and only runs in `--json` mode. The overhead is negligible compared to parsing and evaluation. The reduced JSON payload size may actually improve overall performance.

**[Trade-off] Loses operator/whitespace distinction within ignore spans**
→ **Acceptance**: Consumers rendering syntax highlighting don't need to distinguish between `" "` and `"&&"` - both are rendered the same way (non-highlighted). The original command can still be reconstructed exactly.

## Migration Plan

No migration needed. This is a backward-compatible optimization:
- Existing code continues to work unchanged
- Output schema is identical
- Only the number of spans (and their text content) changes
- The spans array can still be concatenated to reproduce the original command exactly

## Open Questions

None. The approach is straightforward and low-risk.
