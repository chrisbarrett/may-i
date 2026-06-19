## ADDED Requirements

### Requirement: Substitution-origin annotation integrity is structural, not text-derived

The annotation's presence and form SHALL be determined by the command's
syntactic structure, not by the textual content of the reason. Text appearing in
a command — a command name, an argument, or an assignment target — SHALL NOT be
able to suppress, duplicate, or forge the origin annotation of any substitution
that encloses it.

Every input-derived name interpolated into a reason SHALL be control-escaped, so
that the reason remains a single-line value containing no raw newline or other
control character. This preserves the integrity of the host harness's decision
surface, which consumes each reason as a single value.

#### Scenario: A command name containing the annotation phrase does not suppress the clause

- **WHEN** the input is `echo "$('a substitution in b')"`, whose inner command
  name is the literal text `a substitution in b`
- **AND** no rule matches that inner command
- **THEN** the reason SHALL still carry the substitution-origin annotation naming
  `echo`
- **AND** the annotation SHALL NOT be suppressed by the phrase embedded in the
  command name

#### Scenario: A control character in a command name keeps the reason single-line

- **WHEN** a substitution's inner command name contains a newline, for example
  via ANSI-C quoting (`$'\n'`)
- **THEN** the reason SHALL contain no raw newline or other control character
