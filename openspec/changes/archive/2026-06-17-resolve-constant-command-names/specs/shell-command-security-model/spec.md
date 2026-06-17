## ADDED Requirements

### Requirement: Provably-constant variable command names are resolved

The evaluator SHALL resolve a variable command name to its value when that value
is provably constant within the command, and evaluate the resulting literal as
the command name. A value is provably constant only when ALL of the following
hold; otherwise the command name SHALL remain a dynamic command and ask as
before:

- the variable has exactly one assignment in the command, and its right-hand
  side is a static literal (no command substitution, no unresolved variable, no
  glob);
- that assignment executes unconditionally before the use (straight-line
  precedence — not inside a conditional, loop, or function body that may not run
  or may run after the use);
- the variable is not reassigned or `unset` anywhere in the command.

Resolution SHALL only narrow the set of dynamic-command asks; it SHALL NOT change
any decision that did not previously rest on a dynamic command name. When in
doubt, the command name stays dynamic.

#### Scenario: Constant assignment resolves the command name

- **WHEN** the input is `BIN=./target/debug/may-i; $BIN eval foo`
- **AND** no rule matches `./target/debug/may-i`
- **THEN** the command name SHALL be evaluated as `./target/debug/may-i`
- **AND** the reason SHALL be `No rule for command `./target/debug/may-i`` — not
  `dynamic command name: $BIN`

#### Scenario: Resolved command name is gated by its rule

- **WHEN** the input is `R=rm; $R -rf /danger`
- **AND** a rule asks about recursive `rm`
- **THEN** the resolved `rm` SHALL be evaluated and the decision SHALL be at
  least `:ask`

#### Scenario: Assignment from a substitution stays dynamic

- **WHEN** the input is `BIN=$(which terragrunt); $BIN apply`
- **THEN** the command name SHALL remain a dynamic command and the decision SHALL
  be `:ask` with a dynamic-command reason

#### Scenario: A loop variable command name stays dynamic

- **WHEN** the input is `for c in rm cp; do $c x; done`
- **THEN** `$c` SHALL remain a dynamic command (it has no constant assignment)

#### Scenario: Reassignment makes the value not provable

- **WHEN** the input is `B=echo; B=rm; $B x`
- **THEN** `$B` SHALL remain a dynamic command (more than one assignment)
