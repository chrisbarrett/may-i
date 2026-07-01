## MODIFIED Requirements

### Requirement: Parser returns diagnostics alongside AST

The `parse()` function SHALL accept a shell dialect (see the `shell-dialect`
capability) and return a `ParseResult` containing both the best-effort AST and
a list of `ParseDiagnostic` values. Diagnostics SHALL be **dialect-relative**:
a construct that is well-formed in the active dialect SHALL NOT produce a
diagnostic, and a construct malformed in the active dialect SHALL retain its
existing severity. Under `Dialect::Bash` the AST output for any given input
SHALL be identical to the parser output prior to this change.

#### Scenario: Well-formed input has no diagnostics

- **WHEN** the input is `echo hello`
- **THEN** `ParseResult.diagnostics` SHALL be empty
- **AND** `ParseResult.command` SHALL be a Simple command

#### Scenario: Malformed input has diagnostics and AST

- **WHEN** the input is `echo "unterminated`
- **THEN** `ParseResult.diagnostics` SHALL contain one entry
- **AND** `ParseResult.command` SHALL still be a valid AST

#### Scenario: Bash-dialect AST is unchanged

- **WHEN** any input is parsed under `Dialect::Bash`
- **THEN** the `ParseResult.command` SHALL be identical to the parser output
  prior to the introduction of the dialect parameter

#### Scenario: A zsh-only construct is not diagnosed under the zsh dialect

- **WHEN** the input is `foo() { echo hi }` under `Dialect::Zsh`
- **THEN** `ParseResult.diagnostics` SHALL be empty (the missing terminator is
  well-formed in zsh, so the dialect-relative rule suppresses the diagnostic
  that the bash dialect would emit)
