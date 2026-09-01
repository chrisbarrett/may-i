## Delta: shell-command-security-model

## ADDED Requirements

### Requirement: Quoted delimiters do not terminate substitution scans

The parser SHALL honour shell quoting while locating the end of every
substitution or expansion construct. A delimiter character (`)`, `))`, `]`,
`}`, backtick) that appears inside single or double quotes, or is preceded by a
backslash escape where bash honours one, SHALL be treated as literal text and
SHALL NOT close the construct. Each construct's scan SHALL capture the entire
body bash would parse: command substitution `$(…)`, process substitution
`<(…)`/`>(…)`, arithmetic `$((…))` (counting nested parentheses), the
deprecated arithmetic `$[…]` (counting nested brackets), parameter-expansion
operator operands (`${x:-…}` and every other operator form), array subscripts
(`${arr[…]}`), backtick bodies (where bash honours `` \` ``), and the embedded
`$(…)`/`` `…` ``/`$((…))` regions of an unquoted heredoc body.

A command whose substitution body contains quoted delimiters SHALL parse to the
same structure as the equivalent command without them, and commands following
the substitution SHALL NOT be swallowed into it.

#### Scenario: Single-quoted open paren inside command substitution

- **WHEN** the input is `n=$(grep -c 'may_i(' "$f"); echo "$n"`
- **THEN** the command substitution's body SHALL be `grep -c 'may_i(' "$f"`
- **AND** no diagnostic SHALL be emitted
- **AND** the `echo` command SHALL be parsed as a separate command, not
  swallowed into the substitution

#### Scenario: Double-quoted close paren inside command substitution

- **WHEN** the input is `echo $(echo "a)b")`
- **THEN** the command substitution's body SHALL be `echo "a)b"`
- **AND** no diagnostic SHALL be emitted

#### Scenario: Quoted paren inside process substitution

- **WHEN** the input is `diff <(echo "a)b") x`
- **THEN** the process substitution's body SHALL be `echo "a)b"`
- **AND** `x` SHALL be parsed as a separate word, not part of the substitution

#### Scenario: Nested substitution with quoted parens inside arithmetic

- **WHEN** the input is `echo $(( $(echo '))' >/dev/null; echo 5) + 0 ))`
- **THEN** the arithmetic body SHALL be ` $(echo '))' >/dev/null; echo 5) + 0 `
- **AND** no diagnostic SHALL be emitted

#### Scenario: Nested brackets in deprecated arithmetic

- **WHEN** the input is `echo $[a[1]]`
- **THEN** the arithmetic body SHALL be `a[1]`
- **AND** no diagnostic SHALL be emitted

#### Scenario: Quoted close brace in a parameter-expansion operand

- **WHEN** the input is `echo ${FOO:-"a}b"}`
- **THEN** the default operand SHALL be `"a}b"`
- **AND** no unterminated-parameter-expansion diagnostic SHALL be emitted

#### Scenario: Escaped close brace in a parameter-expansion operand

- **WHEN** the input is `echo ${x:-a\}b}`
- **THEN** the default operand SHALL be `a\}b`
- **AND** no unterminated-parameter-expansion diagnostic SHALL be emitted

#### Scenario: Quoted close bracket in an array subscript

- **WHEN** the input is `echo ${arr["a]b"]}`
- **THEN** the subscript SHALL be parsed as the quoted word `"a]b"`
- **AND** no unterminated-parameter-expansion diagnostic SHALL be emitted

#### Scenario: Escaped backtick inside a backtick body

- **WHEN** the input is `` echo `echo a\`b` ``
- **THEN** the backtick body SHALL be `echo a\`b`
- **AND** no unterminated-backtick diagnostic SHALL be emitted

#### Scenario: Quoted parens in an embedded heredoc substitution

- **WHEN** the input is an unquoted heredoc whose body contains
  `$(echo "a)b")`
- **THEN** the embedded command substitution's body SHALL be `echo "a)b"`
- **AND** no diagnostic SHALL be emitted for the heredoc body

#### Scenario: Loop body after a quoted-delimiter substitution is evaluated

- **WHEN** the input is
  `for f in tests/*.rs; do n=$(grep -c 'may_i(' "$f"); echo "$n $f"; done | sort -rn`
- **THEN** the decision SHALL be computed from the command's real structure,
  including the loop body's `echo` and the trailing `sort` pipeline stage
- **AND** the reason SHALL NOT be `empty command`
