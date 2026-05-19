## ADDED Requirements

### Requirement: Trace renderers consume an opaque TraceNode tree

The trace-rendering paths in `crate::output` (the text path through `transform`, `render_rule`, and `mod`; and the JSON path through `json`) SHALL consume an opaque `TraceNode` tree exported by the trace producer and SHALL NOT pattern-match on engine-internal annotation variants. Renderers SHALL NOT import `may_i_core::pattern::{ArgPattern, CommandPattern, MatchMode, Quantifier}` for annotation purposes, and SHALL NOT destructure pattern-internal fields (e.g. `search_tokens`, `arg_set`, regex pattern strings, positional match-mode booleans) from trace nodes.

The `TraceNode` accessor surface SHALL be the only path by which renderers read trace-node content; renderers SHALL access node label, role, evidence, and children via accessors, not by matching on internal enum variants.

#### Scenario: No ArgPattern import in output trace renderers

- **WHEN** scanning `src/output/transform.rs`, `src/output/render_rule.rs`, `src/output/json.rs`, and `src/output/mod.rs` for imports of `may_i_core::pattern::{ArgPattern, CommandPattern, MatchMode, Quantifier}`
- **THEN** zero matches are found

#### Scenario: No Ann variant matches in output trace renderers

- **WHEN** scanning the same files for `Ann::` (the legacy annotation enum) match arms
- **THEN** zero matches are found
- **AND** the `Ann` enum itself is no longer defined in `src/annotation.rs` (or its successor module)

#### Scenario: Renderers reach trace-node content via accessors

- **WHEN** a trace renderer needs a node's label, role, evidence, or children
- **THEN** it reads via the `TraceNode` accessor surface (e.g. `node.role()`, `node.evidence()`, `node.children()`)
- **AND** it does not pattern-match on internal enum variants of `TraceNode` or its sub-types
