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

This control-escaping SHALL be guaranteed by construction: a command-evaluation
reason SHALL be representable only as a type whose sole constructor performs the
control-escape, so that no reason-building site can emit an unescaped reason and
no future site can regress the invariant. The escaped value SHALL be the one
observed on every surface that consumes the reason — the decision result, the
audit/trace record, and any rendered output.

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

#### Scenario: A control character on any reason-interpolated path is escaped

- **WHEN** a control character reaches a reason through any interpolated
  input-derived name — a static command name, a dynamic command name (a command
  substitution or parameter expansion in command position), an environment
  variable name, or a redirect target
- **THEN** the reason observed on every surface SHALL contain no raw control
  character
- **AND** this SHALL hold by construction of the reason's type, not by an
  escape call repeated at each site
