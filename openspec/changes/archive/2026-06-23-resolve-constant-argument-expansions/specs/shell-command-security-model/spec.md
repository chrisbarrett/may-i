## MODIFIED Requirements

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
  or may run after the use, and not lexically preceding the use on the
  straight-line spine);
- the variable is not reassigned or `unset` anywhere in the command.

A variable used before its sole assignment SHALL NOT be treated as provably
constant at that use, because its value there is the inherited environment, not
the later assignment. Resolution SHALL only narrow the set of dynamic-command
asks; it SHALL NOT change any decision that did not previously rest on a dynamic
command name. When in doubt, the command name stays dynamic.

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

#### Scenario: Use before the assignment stays dynamic

- **WHEN** the input is `$B x; B=rm`
- **THEN** `$B` SHALL remain a dynamic command, because at the use site the
  assignment has not yet executed and the value is the inherited environment, not
  `rm`

## ADDED Requirements

### Requirement: Provably-constant variable arguments are resolved

The evaluator SHALL resolve an argument word against the command's
provably-constant variables before matchers evaluate it, using the same
provably-constant definition that governs command-name resolution (single
unconditional straight-line assignment executing before the use, never
reassigned or `unset`, static-literal right-hand side).

Resolution is **all-or-nothing per word**: when every parameter expansion in an
argument word resolves to a provably-constant literal, matchers SHALL see the
resolved value and the word SHALL NOT floor an `:allow` as an unresolved
expansion. When any part of the word remains unresolved — an expansion of a
variable that is not provably constant, a command substitution, or a glob — the
whole word SHALL remain expansion-bearing and floor an `:allow` exactly as
before.

Resolution SHALL only narrow the set of unresolved-expansion asks; it SHALL NOT
change any decision that did not previously rest on an unresolved expansion. A
provably-constant argument word SHALL receive the same internal/external rule
classification it would receive had its resolved literal been written directly.

#### Scenario: Constant variables resolve a mixed argument word

- **WHEN** the input is `BUCKET=b; KEY=k; aws s3 cp "s3://$BUCKET/$KEY" /tmp/x`
- **AND** a rule allows `aws s3 cp` whose target matches `s3://b/k`
- **THEN** matchers SHALL see the argument as `s3://b/k`
- **AND** the decision SHALL be `:allow` without an
  `unresolved shell expansion … cannot satisfy an allow rule` floor

#### Scenario: A partially-resolved argument word still floors

- **WHEN** the input is `BUCKET=b; aws s3 cp "s3://$BUCKET/$KEY" /tmp/x`
- **AND** `KEY` has no provably-constant assignment
- **THEN** the argument word SHALL remain expansion-bearing
- **AND** an `:allow` that rests on matching it SHALL floor to `:ask` with an
  unresolved-expansion reason

#### Scenario: A resolved argument is gated by a deny rule

- **WHEN** the input is `P=/etc/shadow; cat "$P"`
- **AND** a rule denies `cat` of `/etc/shadow`
- **THEN** the resolved argument `/etc/shadow` SHALL be evaluated and the
  decision SHALL be `:deny`

#### Scenario: An argument from a substitution stays unresolved

- **WHEN** the input is `T=$(mktemp); rm "$T"`
- **THEN** the argument word SHALL remain expansion-bearing and floor an
  `:allow` as before (the value is not provably constant)

#### Scenario: An argument used before its assignment stays unresolved

- **WHEN** the input is `rm "$T"; T=/tmp/x`
- **THEN** the argument word SHALL remain expansion-bearing, because at the use
  site `T` is the inherited environment, not `/tmp/x`
