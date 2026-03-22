## ADDED Requirements

### Requirement: Diff computation annotates changed nodes
The system SHALL compute diffs by comparing original and migrated CSTs, annotating each node with its change status.

#### Scenario: Unchanged nodes are marked
- **WHEN** comparing two identical CST nodes
- **THEN** the node SHALL be annotated with `ChangeType::Unchanged`
- **AND** no replacement SHALL be stored

#### Scenario: Modified nodes carry replacement
- **WHEN** comparing different CST nodes at the same position
- **THEN** the node SHALL be annotated with `ChangeType::Modified`
- **AND** the replacement node SHALL be stored in the annotation

#### Scenario: Deleted nodes are detected
- **WHEN** an original node has no corresponding migrated node
- **THEN** the node SHALL be annotated with `ChangeType::Deleted`
- **AND** the replacement SHALL be None

### Requirement: Two-column diff layout displays changes
The diff renderer SHALL display changed forms in a two-column layout when terminal width permits.

#### Scenario: Side-by-side layout for wide terminals
- **WHEN** terminal width is ≥80 columns
- **THEN** the diff SHALL render in two columns labeled "BEFORE" and "AFTER"
- **AND** each column SHALL have equal width
- **AND** a vertical separator SHALL appear between columns

#### Scenario: Line numbers in left gutter
- **WHEN** displaying the diff
- **THEN** line numbers from the original file SHALL appear in the left gutter
- **AND** the gutter width SHALL adjust based on the maximum line number
- **AND** line numbers SHALL only appear for the BEFORE column

#### Scenario: Fold markers for unchanged sections
- **WHEN** consecutive unchanged forms exceed threshold
- **THEN** a centered vertical ellipsis (⋮) SHALL indicate folded content
- **AND** the fold marker SHALL appear on its own line

### Requirement: Inline diff fallback for narrow terminals
The system SHALL fall back to inline diff display when terminal width is insufficient.

#### Scenario: Vertical layout below threshold
- **WHEN** terminal width is <80 columns
- **THEN** the diff SHALL display forms sequentially (BEFORE then AFTER)
- **AND** each form SHALL be labeled clearly

### Requirement: Pretty-printing via pp crate
Both columns SHALL be pretty-printed using the existing `pp` crate for consistent formatting.

#### Scenario: Before column is pretty-printed
- **WHEN** rendering the BEFORE column
- **THEN** the CST SHALL be converted to a `Doc` tree
- **AND** `pp::pretty()` SHALL format it with appropriate line breaks

#### Scenario: After column is pretty-printed
- **WHEN** rendering the AFTER column
- **THEN** the replacement node SHALL be pretty-printed
- **AND** the formatting SHALL match the BEFORE column's style
