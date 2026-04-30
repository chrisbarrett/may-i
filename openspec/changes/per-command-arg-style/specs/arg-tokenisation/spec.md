## ADDED Requirements

### Requirement: `args-style` declares the tokenisation profile per program

The config language SHALL accept a top-level form `(args-style PROGRAM
:PROFILE [:flags-with-values (FLAG ...)])` declaring how the named program's
arguments are tokenised into flags, flag values, and positional arguments.

`PROFILE` SHALL be one of: `:gnu`, `:single-dash-long`, `:legacy-bundle`,
`:key-value`.

When multiple `args-style` declarations exist for the same program, the last
declaration in load order SHALL win. A warning SHALL be emitted at config
load time.

When no `args-style` is declared for a program, the program SHALL be
tokenised under `:gnu`.

#### Scenario: GNU profile is the default

- **GIVEN** no `args-style` declaration for `git`
- **WHEN** evaluating `git push --force`
- **THEN** the tokeniser SHALL apply `:gnu` rules
- **AND** `--force` SHALL be a long flag
- **AND** the result SHALL match the pre-existing behaviour byte-for-byte

#### Scenario: Single-dash-long does not split combined alpha clusters

- **GIVEN** `(args-style "find" :single-dash-long)`
- **WHEN** evaluating `find . -name foo`
- **THEN** `-name` SHALL be a single long flag
- **AND** `(forbidden "-n")` SHALL NOT match
- **AND** `(flag "name")` SHALL match (in conjunction with the
  `flag-and-parameter-patterns` change)

#### Scenario: Legacy bundle treats first cluster as flags

- **GIVEN** `(args-style "tar" :legacy-bundle)`
- **WHEN** evaluating `tar xvzf archive.tgz`
- **THEN** `xvzf` SHALL be tokenised as the bundle of flags `x`, `v`, `z`,
  `f`
- **AND** subsequent tokens SHALL be tokenised under `:gnu` rules

#### Scenario: Key-value treats `key=value` tokens as flags

- **GIVEN** `(args-style "dd" :key-value)`
- **WHEN** evaluating `dd if=foo of=bar bs=1M`
- **THEN** `if=foo`, `of=bar`, and `bs=1M` SHALL each be tokenised as a
  flag-with-value pair
- **AND** no token SHALL be classified as positional

### Requirement: `:flags-with-values` lists additional value-bearing flags

`(args-style PROGRAM :PROFILE :flags-with-values (FLAG ...))` SHALL declare
that each listed flag consumes the immediately following argument as its
value. This SHALL apply on top of the chosen profile.

#### Scenario: Short flag with value is correctly grouped

- **GIVEN** `(args-style "kubectl" :gnu :flags-with-values ("-n"
  "--namespace"))`
- **WHEN** evaluating `kubectl -n my-ns get pods`
- **THEN** `-n my-ns` SHALL be a flag-value pair
- **AND** the positional stream SHALL be `[get, pods]`
- **AND** `(rule "kubectl" (positional "get" "pods"))` SHALL match

### Requirement: Convention applies to the command being evaluated

When a command's args are tokenised, the convention SHALL be looked up by
the name of the command being evaluated (not the wrapping command). When
`(may-i ...)` recurses into an inner command, the inner command's
convention SHALL apply to the inner argv.

#### Scenario: Inner command uses its own convention under `(may-i)`

- **GIVEN** `(args-style "find" :single-dash-long)`
- **AND** `(rule "sudo" (positional . (may-i *)))`
- **WHEN** evaluating `sudo find . -name foo`
- **THEN** the recursion SHALL tokenise the inner `find . -name foo` under
  `:single-dash-long`
- **AND** `-name` SHALL be a single long flag in the inner evaluation

### Requirement: Trace output surfaces the resolved convention

The trace renderer SHALL include the resolved convention for the
command-under-evaluation in its output, so that a user can diagnose why a
given tokenisation occurred.

#### Scenario: Trace shows the active profile

- **WHEN** running `may-i eval` against any command
- **THEN** the trace SHALL include a line indicating the resolved profile
  and any flags-with-values overrides
