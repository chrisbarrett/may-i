## Requirements

### Requirement: Preserved children use source trivia for rendering
When `pretty_serialize` renders a list node, children that carry original source
trivia (non-zero span) SHALL be rendered via the trivia-preserving path
(`pretty_write`), emitting their original whitespace verbatim.

#### Scenario: Cloned or node preserves packed layout
- **WHEN** a rewrite rule extracts `(or "cat" "bat" "zat" "head")` from inside
  `(command (or "cat" "bat" "zat" "head"))` by cloning the `or` node
- **AND** the original source had all arguments on one line
- **THEN** `pretty_serialize` SHALL render the `or` node with arguments on one
  line (preserving the packed layout)

#### Scenario: Cloned or node preserves multi-line packed layout
- **WHEN** a rewrite rule extracts an `or` node whose source had arguments
  packed across two lines:
  ```
  (or "cat" "bat" "zat" "head"
      "tail" "less" "ls")
  ```
- **THEN** `pretty_serialize` SHALL preserve the two-line packed layout

#### Scenario: Cloned list preserves cascaded layout
- **WHEN** a rewrite rule extracts a list node whose source had one child per
  line:
  ```
  (or (positional "repo" "clone")
      (positional "pr" "checkout"))
  ```
- **THEN** `pretty_serialize` SHALL preserve the cascaded layout

### Requirement: Constructed children use reflow rendering
Children that were freshly constructed by rewrite rules (zero span / default
trivia) SHALL be rendered via the whitespace-stripping path
(`pretty_write_no_whitespace`), applying the standard reflow and indentation
logic.

#### Scenario: Freshly constructed when node uses reflow
- **WHEN** a rewrite rule constructs `(when PRED EFFECT)` using
  `CstNode::list(...)` with default trivia
- **THEN** `pretty_serialize` SHALL render it using the standard reflow logic
  (cascading breaks, elisp-style indentation)

#### Scenario: Freshly constructed and node uses reflow
- **WHEN** a rewrite rule constructs `(and CHILD1 CHILD2)` with default trivia
- **THEN** `pretty_serialize` SHALL render it using standard reflow logic

### Requirement: Source trivia detection via span
A node SHALL be considered to have source trivia if its annotation span is
non-zero (i.e., `span.start != 0 || span.end != 0`).

#### Scenario: Parsed node has non-zero span
- **WHEN** the CST parser produces a node from source text
- **THEN** the node's span SHALL be non-zero

#### Scenario: Constructed node has zero span
- **WHEN** a node is created via `CstNode::atom(_, Default::default())` or
  `CstNode::list(_, Default::default())`
- **THEN** the node's span SHALL be zero (start == 0 and end == 0)

#### Scenario: Constructed node at source position zero
- **WHEN** the CST parser produces a node starting at byte offset 0
- **THEN** the node's span end SHALL be non-zero (since the node has non-zero
  width), so the detection heuristic still identifies it as a source node
