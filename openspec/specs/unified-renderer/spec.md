## MODIFIED Requirements

### Requirement: Heading and label widths use visible character width
The layout renderer SHALL compute visible character width (not byte length) for NoteHeading text and ColRow label text. This ensures correct column alignment when headings or labels contain multi-byte Unicode characters or ANSI escape codes.

#### Scenario: Unicode heading alignment
- **WHEN** a NoteHeading is created from a string containing Unicode characters (e.g., "ℹ Info")
- **THEN** the visible_width field SHALL equal the number of visible characters, not the byte length

#### Scenario: ColRow label with Unicode
- **WHEN** a ColRow::kv is created with a label containing Unicode characters
- **THEN** the width used for column arithmetic SHALL equal the visible character width
