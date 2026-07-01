## ADDED Requirements

### Requirement: The parser accepts a shell dialect

`parse()` SHALL accept a shell **dialect** that selects which grammar the
input is judged against. The supported dialects SHALL be `Dialect::Bash` and
`Dialect::Zsh`. The dialect governs only which constructs are well-formed; it
SHALL NOT change how a construct that is well-formed in both dialects is
represented in the AST.

zsh has no published formal grammar, so the zsh dialect is defined as bash
plus an explicit, enumerated set of additional accepted constructs (below).
Any construct not in that set behaves under the zsh dialect exactly as it
does under the bash dialect.

#### Scenario: A dialect is required to parse

- **WHEN** a caller invokes `parse()` with `Dialect::Bash`
- **THEN** the returned `ParseResult` SHALL reflect the bash grammar
- **AND** invoking with `Dialect::Zsh` SHALL reflect the zsh grammar

#### Scenario: Shared constructs parse identically across dialects

- **WHEN** the input is `if true; then echo hi; fi`
- **THEN** the `ParseResult.command` SHALL be identical under `Dialect::Bash`
  and `Dialect::Zsh`
- **AND** `ParseResult.diagnostics` SHALL be empty under both

### Requirement: Bash is the default dialect

Absent an explicit selection, evaluation SHALL use `Dialect::Bash`. The
`check` invocation mode SHALL always use `Dialect::Bash` so its results stay
hermetic and independent of the ambient shell.

#### Scenario: `check` is dialect-hermetic

- **WHEN** `may-i check` runs
- **THEN** parsing SHALL use `Dialect::Bash` regardless of the ambient
  `$SHELL`

### Requirement: The dialect is resolved from the executing shell

In the hook and `eval` invocation modes, the dialect SHALL be resolved from
the shell that will execute the command: when the basename of the executing
shell path is `zsh`, the dialect SHALL be `Dialect::Zsh`; otherwise it SHALL
be `Dialect::Bash`. The executing shell is observed ground truth (the `$SHELL`
value the harness reports), not a Fact, and SHALL NOT be reachable through
`(fact? …)`.

An explicit override SHALL be available on `eval` to force a dialect, so a
decision can be reproduced under a chosen dialect independent of the ambient
`$SHELL`. When the override is given it SHALL take precedence over the
`$SHELL`-derived dialect.

#### Scenario: A zsh login shell selects the zsh dialect

- **WHEN** the executing shell resolves to a path whose basename is `zsh`
- **THEN** the hook mode SHALL parse the command under `Dialect::Zsh`

#### Scenario: An unrecognised or absent shell falls back to bash

- **WHEN** the executing shell is absent, empty, or has a basename other than
  `zsh` (e.g. `bash`, `sh`, `fish`)
- **THEN** the dialect SHALL be `Dialect::Bash`

#### Scenario: The explicit override wins over `$SHELL`

- **WHEN** `eval` is invoked with an explicit dialect override
- **THEN** parsing SHALL use the overridden dialect regardless of the
  `$SHELL`-derived value

### Requirement: The zsh dialect accepts a no-semicolon brace terminator

Under `Dialect::Zsh`, a `}` SHALL close a brace-group command list without a
preceding `;` or newline, matching zsh. This applies both to a bare brace
group and to a function body. The resulting AST SHALL be the same brace-group
/ function-definition structure that the equivalent `;`-terminated input
produces, and `ParseResult.diagnostics` SHALL be empty.

Under `Dialect::Bash`, the same input SHALL retain its current behaviour
(bash requires the `;` or newline before `}`), producing the same diagnostic
it produces today.

#### Scenario: Function body without a trailing semicolon parses under zsh

- **WHEN** the input is `foo() { echo hi }` under `Dialect::Zsh`
- **THEN** `ParseResult.command` SHALL be a function definition named `foo`
  whose body runs `echo hi`
- **AND** `ParseResult.diagnostics` SHALL be empty

#### Scenario: Bare brace group without a trailing semicolon parses under zsh

- **WHEN** the input is `{ echo a }` under `Dialect::Zsh`
- **THEN** `ParseResult.command` SHALL be a brace group running `echo a`
- **AND** `ParseResult.diagnostics` SHALL be empty

#### Scenario: The embedded command in a no-semicolon body is still evaluated

- **WHEN** the input is `cleanup() { rm -rf "$wt" }; cleanup` under
  `Dialect::Zsh`
- **AND** a rule asks about recursive `rm`
- **THEN** the decision SHALL be at least `:ask` from the body's `rm`

#### Scenario: Bash dialect still requires the terminator

- **WHEN** the input is `foo() { echo hi }` under `Dialect::Bash`
- **THEN** the behaviour SHALL be unchanged from today (the missing terminator
  is diagnosed as it is now)

### Requirement: The zsh dialect accepts glob qualifiers

Under `Dialect::Zsh`, a trailing parenthesised **glob qualifier** SHALL parse
as part of the glob word rather than as a subshell or a syntax error. The
qualifier SHALL be treated as an unresolved glob for evaluation:
the word remains expansion-bearing and floors an `:allow` exactly as a
plain glob does, so recognising the qualifier SHALL only remove a spurious
diagnostic — it SHALL NOT widen any decision.

Under `Dialect::Bash`, the same input SHALL retain its current behaviour.

#### Scenario: A glob qualifier parses under zsh

- **WHEN** the input is `ls **/*(.)` under `Dialect::Zsh`
- **THEN** `ParseResult.diagnostics` SHALL be empty
- **AND** the qualifier SHALL be carried as part of the glob argument word

#### Scenario: A qualified glob remains unresolved

- **WHEN** the input is `print -l *(.om[1])` under `Dialect::Zsh`
- **AND** a rule allows `print`
- **THEN** the qualified glob word SHALL be treated as expansion-bearing
- **AND** an `:allow` resting on matching it SHALL floor to `:ask` as an
  unresolved glob does today

#### Scenario: Bash dialect is unaffected by glob qualifiers

- **WHEN** the input is `ls **/*(.)` under `Dialect::Bash`
- **THEN** the behaviour SHALL be unchanged from today
