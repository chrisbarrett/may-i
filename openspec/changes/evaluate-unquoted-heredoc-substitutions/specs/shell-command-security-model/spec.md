## ADDED Requirements

### Requirement: Unquoted heredoc bodies are evaluated for embedded commands

The evaluator SHALL extract and evaluate embedded commands (command
substitution `$(…)`/`` `…` ``, arithmetic `$((…))`) found
in the body of an **unquoted** heredoc (`<<EOF` — i.e. one whose opening
delimiter is neither single-quoted, double-quoted, nor backslash-escaped),
because real bash performs expansion in such a body. Each embedded command SHALL
become its own evaluation unit and SHALL be aggregated strictest-wins with the
rest of the command. An embedded command in an unquoted heredoc body MUST NOT be
dropped from evaluation.

Process substitution (`<(…)`, `>(…)`) SHALL NOT be extracted from a heredoc
body: bash performs only parameter, command, and arithmetic expansion there, so
`<(…)` in a heredoc body is literal text that never executes. Extracting it
would evaluate (and potentially deny) text that never runs — heredoc bodies
commonly carry example code and documentation.

This complements "Quoted heredoc bodies are inviolable": a quoted heredoc
(`<<'EOF'`, `<<"EOF"`, `<<\EOF`) suppresses expansion and its body SHALL remain
inert; only the unquoted form is evaluated. The distinguishing signal is the
delimiter's quoting, which the lexer records.

#### Scenario: Command substitution in an unquoted heredoc body is evaluated

- **WHEN** the input is `cat <<EOF` / `$(rm --force)` / `EOF`
- **AND** a rule denies `rm --force`
- **THEN** the inner `rm --force` SHALL be evaluated and the decision SHALL be
  `:deny`
- **AND** the `rm` SHALL NOT be absent from evaluation

#### Scenario: Quoted heredoc body stays inert

- **WHEN** the input is `cat <<'EOF'` / `$(rm --force)` / `EOF`
- **AND** a rule denies `rm --force`
- **THEN** no `EvalUnit` SHALL be emitted for the body `$(rm --force)` (the
  quoted heredoc suppresses expansion; existing inviolability is preserved)

#### Scenario: Backslash-escaped delimiter is inert

- **WHEN** the input is `cat <<\EOF` / `$(rm --force)` / `EOF`
- **THEN** the body SHALL remain inert (backslash-escaped delimiter suppresses
  expansion, like the single-quoted form)

#### Scenario: Process substitution in a heredoc body stays literal

- **WHEN** the input is `cat <<EOF` / `<(rm --force)` / `EOF`
- **AND** a rule denies `rm --force`
- **THEN** no `EvalUnit` SHALL be emitted for `<(rm --force)` (bash does not
  perform process substitution in heredoc bodies; the text is inert)

#### Scenario: Unterminated substitution in an unquoted heredoc body is not recursed into

- **WHEN** the input is an unquoted heredoc whose body contains `$(rm --force`
  (unterminated)
- **THEN** the unterminated substitution SHALL NOT be extracted as an embedded
  command
- **AND** the Error-severity floor SHALL own the outcome (decision at least
  `:ask`), per "Unterminated substitutions are not recursed into"
