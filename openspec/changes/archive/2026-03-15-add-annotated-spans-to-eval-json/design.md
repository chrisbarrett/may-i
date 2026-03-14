# Design: Add Annotated Spans to eval --json Output

## Overview

Extend the `may-i eval --json` command to include a `spans` array that maps each segment of the source command to its authorization permission level.

## Data Structures

### Span Representation

```rust
/// A span of source text with its permission level
#[derive(Debug, Clone, serde::Serialize)]
struct PermissionSpan {
    /// The exact source text for this span
    text: String,
    /// The permission level: "allow", "ask", "deny", or "ignore"
    permission: String,
}
```

The `permission` field uses string values for JSON compatibility:
- `"allow"` - Command evaluated to allow
- `"ask"` - Command evaluated to ask
- `"deny"` - Command evaluated to deny  
- `"ignore"` - Syntactic element (operator, whitespace) that is not evaluated

## Algorithm

The span generation algorithm works in three phases:

### Phase 1: Segment the Command

Use the existing `segment()` function to split the command at top-level operators:

```rust
let segments = parser::segment(command);
```

This returns a `Vec<Segment>` where each segment has:
- `start: usize` - Byte offset in original command
- `end: usize` - Byte offset in original command
- `is_operator: bool` - True if this is an operator (`&&`, `||`, `|`, etc.)

### Phase 2: Fill Gaps and Map Permissions

Iterate through segments and gaps to build the spans array:

```
Algorithm: build_permission_spans
Input: command string, segments Vec<Segment>, segment_decisions Vec<Decision>
Output: Vec<PermissionSpan>

1. Initialize spans = []
2. Initialize last_end = 0
3. For each (segment, decision) in zip(segments, segment_decisions):
   a. If segment.start > last_end:
      - This is leading/interstitial whitespace
      - spans.push({text: command[last_end..segment.start], permission: "ignore"})
   b. If segment.is_operator:
      - spans.push({text: command[segment.start..segment.end], permission: "ignore"})
   c. Else:
      - spans.push({text: command[segment.start..segment.end], permission: decision.to_string()})
   d. last_end = segment.end
4. If last_end < command.len():
   - This is trailing whitespace
   - spans.push({text: command[last_end..], permission: "ignore"})
5. Return spans
```

### Phase 3: Include in JSON Output

Modify the JSON construction in `cmd_eval.rs`:

```rust
let json = serde_json::json!({
    "decision": result.decision.to_string(),
    "reason": result.reason.unwrap_or_default(),
    "spans": spans,  // NEW
    "trace": crate::output::trace_to_json(&result.trace),
});
```

## Edge Cases

### Empty Command
- Returns empty spans array
- Decision remains "ask" (default behavior)

### Single Command (No Operators)
- Single span with the full command text
- Permission reflects the evaluation result

### Leading/Trailing Whitespace
- Captured as "ignore" spans at start/end
- Preserves exact source reproduction

### Multiple Operators
- Each operator is its own "ignore" span
- Commands between operators get evaluated independently

### Newlines at Depth 0
- Treated as operators by segmenter
- Become "ignore" spans

## Integration Points

### Modified Files

1. **`src/cmd_eval.rs`**
   - Add `PermissionSpan` struct
   - Add `build_spans()` function
   - Modify JSON output construction to include spans

### Dependencies

- Uses existing `parser::segment()` from `may-i-shell-parser`
- Uses existing `Decision` type from `may-i-core`
- No new crate dependencies

## JSON Schema

```json
{
  "spans": {
    "type": "array",
    "items": {
      "type": "object",
      "properties": {
        "text": { "type": "string" },
        "permission": { 
          "type": "string",
          "enum": ["allow", "ask", "deny", "ignore"]
        }
      },
      "required": ["text", "permission"]
    }
  }
}
```

## Testing Strategy

### Unit Tests
- Empty command
- Single command
- Commands with operators
- Leading/trailing whitespace
- Multiple operators in sequence

### Integration Tests
- Full `may-i eval --json` output validation
- Verify concatenating spans reproduces original command
- Verify permissions match evaluation results

## Performance

- **Time**: O(n) where n is number of segments
- **Memory**: O(n) for spans vector
- **Overhead**: Negligible - only affects `--json` mode, uses existing segment data
