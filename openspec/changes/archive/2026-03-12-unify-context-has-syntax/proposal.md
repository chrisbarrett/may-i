## Why

Context fact queries currently use three different surface forms - `(has :key)`, `(= :key "value")`, and `(matches :key "regex")` - even though they all ask whether a fact set contains a matching entry. That split makes the DSL harder to learn, produces awkward trace output for missing values, and obscures the fact-vector model already used by `with-facts`.

## What Changes

- **BREAKING** Replace context-level `=` and `matches` predicates with a unified `has` query syntax based on fact-entry shapes.
- Allow `(has :key)` and `(has [:key])` as interchangeable presence queries, and add scalar/pattern queries such as `(has [:key "value"])` and `(has [:key (regex "^pat")])`.
- Add a restricted fact-value pattern grammar inside `has` for `*`, `(regex ...)`, `(and ...)`, `(or ...)`, and `(not ...)`, with short-circuit evaluation and unevaluated branches remaining visible in traces.
- Redesign human-readable context trace rendering so it preserves the source query on the left and shows compact observed-value evidence on the right, while JSON trace output remains fully explicit.

## Capabilities

### New Capabilities
- `human-evaluation-trace`: Specify the human and JSON trace behavior for context fact queries, including compact right-column evidence and structured machine-readable annotations.

### Modified Capabilities
- `context-aware-configuration`: Change context fact query syntax to use unified `has` forms and add restricted fact-value patterns.
- `opencode-context`: Update OpenCode-gated rule examples and scenarios to use the unified `has` syntax for exact fact matching.

## Impact

- Affected code includes context expression parsing, context evaluation annotations, trace rendering/JSON serialization, starter config examples, README/docs, and tests covering context-aware evaluation.
- Existing local configs using `(= ...)` or `(matches ...)` will need to be rewritten to `has` forms.
