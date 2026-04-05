## ADDED Requirements

### Requirement: Trivia-annotated Doc conversion

`CstNode<TriviaAnn>` SHALL provide a `to_doc_with_trivia()` method that produces
a `Doc<Option<TriviaAnn>>` preserving trivia from source-parsed nodes.

#### Scenario: source-parsed node carries trivia
- **WHEN** a `CstNode` was parsed from source (non-zero span)
- **THEN** `to_doc_with_trivia()` SHALL produce a `Doc` node with annotation
  `Some(trivia_ann)`

#### Scenario: constructed node carries no trivia
- **WHEN** a `CstNode` was freshly constructed (zero span, default trivia)
- **THEN** `to_doc_with_trivia()` SHALL produce a `Doc` node with annotation
  `None`

#### Scenario: nested structure preserved
- **WHEN** a list contains a mix of source-parsed and constructed children
- **THEN** each child's annotation SHALL independently reflect its origin

### Requirement: Trivia-aware rendering

The renderer SHALL use trivia annotations to decide between preserving source
layout and computing fresh layout.

#### Scenario: forced break from trivia
- **WHEN** a child's leading trivia contains a newline
- **THEN** the renderer SHALL emit a line break before the child, preserving
  the author's line-breaking decision

#### Scenario: constructed node gets speculative layout
- **WHEN** a child has no trivia (`None` annotation)
- **THEN** the renderer SHALL use speculative rendering (try flat, measure
  width, fall back to broken/all-drop) to determine optimal layout

#### Scenario: comment preservation
- **WHEN** a child's leading trivia contains a comment
- **THEN** the comment SHALL be emitted at the current indent level on its own
  line, with blank lines preserved from preceding whitespace

#### Scenario: trailing comment preservation
- **WHEN** a node has a trailing comment
- **THEN** the trailing comment SHALL be emitted with its original spacing
  preserved

### Requirement: Cascade across mixed children

Line-break cascading SHALL work across a mix of preserved and constructed
children within the same list.

#### Scenario: preserved break triggers cascade
- **WHEN** a preserved child forces a line break (newline in trivia)
- **THEN** subsequent children (whether preserved or constructed) SHALL also
  break to new lines

#### Scenario: constructed break triggers cascade
- **WHEN** a constructed child breaks because it exceeds the column width
- **THEN** subsequent children (whether preserved or constructed) SHALL also
  break to new lines

#### Scenario: no cascade when all children fit
- **WHEN** all children (preserved and constructed) fit on one line
- **AND** no preserved child has a forced break in its trivia
- **THEN** the list SHALL be rendered flat (single line)

### Requirement: Unified special-form table

There SHALL be exactly one special-form classification table used by all
rendering paths.

#### Scenario: special forms use body indent
- **WHEN** the head atom of a list is a special form (`rule`, `define`, `check`,
  `with-facts`, `when`, `unless`, `if`, `cond`, `case`)
- **THEN** the body SHALL be indented by 2 from the opening paren

#### Scenario: non-special forms use function-call indent
- **WHEN** the head atom of a list is not in the special-form table
- **THEN** subsequent arguments SHALL align under the first argument
  (`paren_col + 1 + head_atom_width + 1`)

#### Scenario: consistent between pretty printing and formatting
- **WHEN** a tree is rendered for trace output (pure pretty printing)
- **AND** the same tree structure is rendered via `pretty_serialize` (formatting)
- **THEN** both SHALL use the same indentation rules

## MODIFIED Requirements

### Requirement: `pretty_serialize` uses unified renderer

`CstNode::pretty_serialize` SHALL be reimplemented to use `to_doc_with_trivia()`
followed by the unified `pp` renderer, replacing the `PrettyCtx`-based
implementation.

#### Scenario: faithful serialize unchanged
- **WHEN** `serialize()` is called on a `CstNode`
- **THEN** the output SHALL be identical to the current behaviour (verbatim
  trivia roundtrip, no reformatting)

#### Scenario: pretty_serialize produces equivalent output
- **WHEN** `pretty_serialize(width)` is called on a source-parsed `CstNode`
- **THEN** the output SHALL preserve the author's line breaks and comments
  (same as current behaviour)

#### Scenario: pretty_serialize improves constructed-node layout
- **WHEN** `pretty_serialize(width)` is called on a tree containing freshly
  constructed nodes
- **THEN** the constructed nodes SHALL use speculative layout (flat/broken/
  all-drop) rather than single-pass heuristic layout

### Requirement: Trace output unaffected

The `pp` crate's existing `pretty()` and `pretty_into()` functions for `Doc<()>`
SHALL produce identical output to their current behaviour.

#### Scenario: Doc<()> rendering unchanged
- **WHEN** `pretty()` is called with a `Doc<()>` (no trivia annotations)
- **THEN** the output SHALL be identical to the current output

## REMOVED Requirements

### Requirement: PrettyCtx-based formatting removed

The following items in `crates/sexpr/src/cst.rs` SHALL be removed:

- `PrettyCtx` struct
- `pretty_write` method
- `pretty_write_no_whitespace` method
- `compute_child_indent` function
- `estimate_width` function
- `SPECIAL_FORMS` table (in `cst.rs`; the unified table lives in `pp`)
- `is_special_form` function (in `cst.rs`)

#### Scenario: no duplicate layout logic
- **WHEN** the codebase is searched for special-form classification tables
- **THEN** exactly one table SHALL exist (in the `pp` crate or `core` crate)
