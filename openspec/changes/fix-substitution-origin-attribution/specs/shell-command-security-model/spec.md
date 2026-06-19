## ADDED Requirements

### Requirement: Substitution-origin annotation names the lexical owner

The substitution-origin annotation SHALL describe the syntactic position that
**lexically contains** the substitution (`$(…)`, backticks, or process
substitution) — naming the simple command, the assignment target, or the `for` /
`case` / redirect context that owns it. The annotation SHALL NOT attribute the
substitution to a command that does not own it (for example, an unrelated
command appearing earlier in the input).

When the substitution's owner is a simple command, the annotation SHALL name
that command. When the owner is a position with no command name — an assignment
value, a `for` list word, a `case` subject or pattern, or a redirect target —
the annotation SHALL describe that position rather than reaching past it to an
unrelated command.

#### Scenario: Substitution in an assignment names the assignment target

- **WHEN** the input is `set -euo pipefail; main() { dest=$(badcmd); }; main`
- **AND** no rule matches `badcmd`
- **THEN** the reason's origin annotation SHALL describe the assignment to
  `dest`
- **AND** the annotation SHALL NOT name `set`

#### Scenario: Substitution in a simple command names that command

- **WHEN** the input is `grep "$(badcmd)" file`
- **AND** no rule matches `badcmd`
- **THEN** the reason's origin annotation SHALL name `grep`

#### Scenario: Substitution in a redirect target names the redirect context

- **WHEN** the input is `cat > "$(badcmd)"`
- **AND** no rule matches `badcmd`
- **THEN** the reason's origin annotation SHALL describe the redirect target
- **AND** the annotation SHALL NOT attribute the substitution to an unrelated
  command
