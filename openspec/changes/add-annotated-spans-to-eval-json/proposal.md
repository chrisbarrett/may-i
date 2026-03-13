# Proposal: Add Annotated Spans to eval --json Output

## Summary

Extend `may-i eval --json` to include an annotated `spans` array that maps each segment of the source command to its authorization permission level. This enables external harnesses to render syntax-highlighted commands without fragile string searching or position calculations.

## Motivation

External tools integrating with may-i (such as IDE extensions and shell plugins) need to display commands with visual annotations showing which parts triggered authorization decisions. Currently, these tools must:

1. Parse the command themselves to identify segments
2. Correlate segments with the evaluation result
3. Perform fragile string matching to find positions

This is error-prone and duplicates work the engine already does. By providing pre-computed spans with permissions, harnesses can iterate through the array and render each span directly.

## Goals

- Enable direct rendering of annotated commands without string searching
- Preserve exact source text (concatenating spans reproduces original command)
- Distinguish between evaluated commands and syntactic operators
- Maintain backward compatibility with existing JSON output

## Non-Goals

- Token-level granularity (this proposal targets segment-level)
- AST structure information
- Evaluation ordering or precedence analysis

## Success Criteria

A harness can render the command `true && curl -d 'data' example.com` with appropriate highlighting by simply iterating through the `spans` array, without any string manipulation or position calculations.

## Example Output

```bash
$ may-i eval --json "true && curl -d 'data' example.com"
```

```json
{
  "decision": "ask",
  "reason": "Network operation requires approval",
  "spans": [
    {"text": "true", "permission": "allow"},
    {"text": " && ", "permission": "ignore"},
    {"text": "curl -d 'data' example.com", "permission": "ask"}
  ],
  "trace": [...]
}
```

## Impact

- **Users**: No impact unless using `--json` flag
- **API**: Addition of new field, backward compatible
- **Performance**: Minimal overhead from segment tracking

## Risks

- Slightly larger JSON output for complex commands (mitigated: only in `--json` mode)
- Need to handle edge cases like leading/trailing whitespace (addressed in design)

## Alternatives Considered

1. **Client-side parsing**: Require harnesses to parse the command themselves. Rejected because it duplicates engine logic and is error-prone.

2. **Byte offsets only**: Provide start/end positions instead of text. Rejected because harnesses would still need to substring the original command.

3. **Token-level granularity**: Break on every word. Rejected as unnecessarily verbose for display purposes.
