## ADDED Requirements

### Requirement: Files with no rules are preserved verbatim

`may-i fmt` SHALL treat an input that parses successfully but contains no top-level forms (for example, a file consisting only of `;;` comments and blank lines) as already canonical. In this case:

- In file mode, the file SHALL NOT be rewritten; on-disk bytes SHALL be unchanged.
- In stdin filter mode, stdout SHALL receive the input verbatim.
- In `--check` mode, the input SHALL count as clean (exit `0`), not as "would change".

A parse error SHALL still flow through the existing error path (exit `2`); the preservation rule applies only when parsing produced zero forms *and* zero errors.

#### Scenario: Comments-only file preserved on disk

- **WHEN** `may-i fmt foo.lisp` runs against a file whose entire contents are comment lines (`;; …`) and blank lines
- **THEN** `foo.lisp` is left byte-identical on disk
- **AND** the command exits `0`

#### Scenario: Comments-only file preserved through stdin filter

- **WHEN** a stream consisting only of comments and whitespace is piped to `may-i fmt`
- **THEN** stdout receives the input bytes unchanged
- **AND** the command exits `0`

#### Scenario: Comments-only file reported clean in check mode

- **WHEN** `may-i fmt --check foo.lisp` runs against a comments-only file
- **THEN** the command exits `0`
- **AND** stdout is empty

#### Scenario: Whitespace-only file preserved

- **WHEN** `may-i fmt foo.lisp` runs against a file containing only whitespace (blank lines, spaces, tabs)
- **THEN** `foo.lisp` is left byte-identical on disk
- **AND** the command exits `0`
