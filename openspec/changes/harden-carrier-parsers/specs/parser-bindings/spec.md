## ADDED Requirements

### Requirement: Prelude Carrier parsers declare their value-taking option flags

Each Carrier parser shipped in the prelude SHALL declare, as `(parameter …)`,
every option flag that takes a value in the tool it models. This ensures the
flag's value is consumed as the flag's argument rather than being mistaken for
the first token of the inner command. A Carrier whose value-taking flags are not
declared misidentifies the inner command (the flag value is read as the command
name), which lets the real command escape its rule; declaring the flags is
therefore a correctness-and-security requirement, not a convenience.

This requirement covers the prelude parsers for `sudo`, `env`, `ssh`, `ionice`,
`chrt`, `strace`, `time`, and `xargs`. `chrt` SHALL additionally declare a single
required `#priority` positional ahead of `(rest #cmd)`, mirroring `timeout`'s
`#duration` shape, because its scheduling priority is a positional operand.

#### Scenario: sudo recurses past a value-flag to the real command

- **GIVEN** the prelude `sudo` parser and `(rule "sudo" (authorise #cmd))`, `(rule "rm" (deny "no rm"))`
- **WHEN** evaluating `sudo -u postgres rm -rf /`
- **THEN** the inner command SHALL be `rm` (not `postgres`)
- **AND** the decision SHALL be `:deny`

#### Scenario: ssh recurses past value-flags to the real command

- **GIVEN** the prelude `ssh` parser and `(rule "ssh" (authorise #cmd))`, `(rule "rm" (deny "no rm"))`
- **WHEN** evaluating `ssh -i key -p 22 host rm -rf /tmp`
- **THEN** the bound `#host` SHALL be `host` (not `22`), the inner command SHALL be `rm`, and the decision SHALL be `:deny`

#### Scenario: env recurses past -u to the real command

- **GIVEN** the prelude `env` parser and `(rule "env" (authorise #cmd))`, `(rule "rm" (deny "no rm"))`
- **WHEN** evaluating `env -u SDKROOT rm -rf /tmp`
- **THEN** the inner command SHALL be `rm` (not `SDKROOT`), and the decision SHALL be `:deny`

#### Scenario: chrt reads its priority as a positional, not the command

- **GIVEN** the prelude `chrt` parser and `(rule "chrt" (authorise #cmd))`, `(rule "rm" (deny "no rm"))`
- **WHEN** evaluating `chrt -r 10 rm -rf /tmp`
- **THEN** `#priority` SHALL bind `10`, the inner command SHALL be `rm`, and the decision SHALL be `:deny`

### Requirement: Prelude Carrier flag declarations are valid on both macOS and Linux

The value-flag declarations for prelude Carriers SHALL be correct for both the
BSD variant (macOS) and the GNU / util-linux variant (Linux) of each tool. A flag
SHALL be declared value-taking only if it takes a value on every platform on which
it exists, so that a declaration never causes the *opposite* mis-parse (consuming
a following operand as a flag value) on a platform where the flag is valueless.
Where a value-flag exists on only one platform (e.g. BSD `env -P`, GNU
`env --chdir`), declaring it is safe because the other platform never emits it.
Linux-only Carriers (`ionice`, `chrt`, `strace`) SHALL be grounded in their
util-linux / strace documentation.

#### Scenario: A platform-divergent flag set is the union of both variants

- **WHEN** the prelude `env` parser is inspected
- **THEN** its declared value-flags include the BSD set (`-u`, `-C`, `-P`, `-S`) and the GNU long forms (`--unset`, `--chdir`, `--split-string`), and none of them is valueless on either platform

#### Scenario: No declaration makes a valueless flag consume an operand

- **WHEN** any hardened Carrier parser is evaluated against an invocation valid on either macOS or Linux
- **THEN** no token that the tool treats as a valueless flag's neighbour or as the command operand is consumed as a flag value
