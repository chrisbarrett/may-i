## Why

The `spans` array in `eval --json` output currently includes consecutive `ignore` permission spans (whitespace, operators) as separate entries. This creates unnecessary noise for consumers who want to render syntax-highlighted commands with permission-based coloring. By coalescing adjacent `ignore` spans, we provide a cleaner, more compact output that's easier for consumers to process while maintaining the semantic boundaries between evaluated commands.

## What Changes

- Add a `coalesce_spans()` function that merges consecutive spans with `"ignore"` permission
- Modify the span generation pipeline to coalesce spans before JSON serialization
- Preserve semantic boundaries: `allow`/`ask`/`deny` spans remain separate for per-command coloring
- Maintain backward compatibility: output structure unchanged, just fewer spans for contiguous ignored text

## Capabilities

### New Capabilities
- `span-coalescing`: Optimization pass that consolidates adjacent ignored text spans in eval output

### Modified Capabilities
- *No spec-level requirement changes - this is an implementation optimization*

## Impact

- Affects `src/cmd_eval.rs`: adds coalescing logic to span generation
- Reduces JSON payload size for commands with multiple operators/whitespace
- Simplifies consumer code that iterates spans for rendering
- No breaking changes to output schema or structure
