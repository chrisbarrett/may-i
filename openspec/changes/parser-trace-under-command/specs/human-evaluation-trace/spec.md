## ADDED Requirements

### Requirement: Human trace renders the resolved parser as a kv row beneath the command row
The human-readable evaluation trace SHALL render the resolved parser for the evaluated command as a key-value row using the same two-column geometry as the `command` row, with label `parser` on the left and the parser description on the right. The `parser` row SHALL appear immediately beneath the `command` row, with no intervening blank line. The right column SHALL contain the resolved style name; when the parser declares parameter spellings, they SHALL follow as ` parameters (<token> <token> …)`; when the parser declares a tail boundary, it SHALL follow as ` tail (after <spec>)`.

#### Scenario: Default gnu parser with no parameters or tail
- **WHEN** rendering a failure trace whose resolved parser has style `gnu`, no parameter spellings, and no tail
- **THEN** the trace contains a `command │ <command-string>` row
- **AND** the next rendered row is `parser │ gnu`
- **AND** there is no blank line between the `command` row and the `parser` row

#### Scenario: Parser with parameter spellings
- **WHEN** rendering a failure trace whose resolved parser has style `gnu` and parameter spellings `-X` and `--request`
- **THEN** the `parser` row's right column reads `gnu  parameters (-X --request)`

#### Scenario: Parser with a tail boundary
- **WHEN** rendering a failure trace whose resolved parser has style `gnu` and tail `Tail::AfterFlags`
- **THEN** the `parser` row's right column reads `gnu  tail (after :flags)`

#### Scenario: Parser with both parameters and a tail boundary
- **WHEN** rendering a failure trace whose resolved parser has style `gnu`, parameter spellings `-c`, and tail `Tail::AfterToken(["--"])`
- **THEN** the `parser` row's right column reads `gnu  parameters (-c)  tail (after "--")`

### Requirement: Standalone right-aligned parser banner is removed
The human-readable evaluation trace SHALL NOT render the parser as a standalone right-aligned banner row above the `command` row. The previously emitted blank line that followed the standalone banner SHALL also be removed.

#### Scenario: No top-of-trace parser banner
- **WHEN** rendering any failure trace
- **THEN** the trace does not contain a row whose left column is the entire width and whose visible text begins with `parser:` followed by the style name
- **AND** the first rendered content row of the trace is the `command` row
