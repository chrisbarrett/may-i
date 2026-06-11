## ADDED Requirements

### Requirement: Redirect targets are not silently ignored

A command carrying a redirection to a file target SHALL NOT be evaluated as if
the redirection were absent. The redirection forms in scope are `>`, `>>`, `<`,
`<>`, `&>`, `>|`, and fd duplication to a path. A command with a redirect to a
non-standard file target SHALL floor to at least `:ask`, with a reason naming
the redirect operator and target.

Redirections to `/dev/null` and to standard fd numbers (`2>&1`, `>&2`) are
standard plumbing and SHALL NOT floor on their own.

This change provides no way to opt a redirect out of the floor: `may-i`
classifies by command, and constraining *where* a redirect points is the job of
sandboxing layers beneath it. A capability-style opt-in (a rule declaring that
its command may carry redirects) is deferred to a separate proposal; when it
lands, an expansion-bearing target SHALL be handled per "Match and parse
imprecision never widens toward allow" (it cannot satisfy an opt-in toward
`:allow`).

#### Scenario: Write redirect to a file floors an otherwise-allow command

- **GIVEN** `(rule "echo" (allow))`
- **WHEN** evaluating `echo x > /home/u/.ssh/authorized_keys`
- **THEN** the decision SHALL be at least `:ask`
- **AND** the reason SHALL name the redirect target

#### Scenario: Standard plumbing does not floor

- **GIVEN** `(rule "echo" (allow))`
- **WHEN** evaluating `echo x 2>&1` or `echo x > /dev/null`
- **THEN** the decision SHALL be `:allow`

#### Scenario: Expansion-bearing redirect target floors

- **WHEN** evaluating `echo x > /tmp/$NAME` under `(rule "echo" (allow))`
- **THEN** the decision SHALL be at least `:ask` (the target is both a
  non-standard file target and expansion-bearing; either alone floors)

### Requirement: Environment-assignment prefixes gate the decision

The evaluator SHALL NOT discard a simple command's `NAME=VALUE` environment-
assignment prefixes. A prefix assigning a `NAME` that is not in the effective
`safe-env-vars` set SHALL floor the enclosing segment to at least `:ask`, with a
reason naming the variable.
Prefixes assigning only names in `safe-env-vars` SHALL pass through and the
command SHALL be evaluated as if unprefixed.

The rationale is that prefix-position assignments to names such as `LD_PRELOAD`,
`BASH_ENV`, `ENV`, `IFS`, `PATH`, and `SHELLOPTS` change what executes; treating
the command as unprefixed authorises a materially different command.

#### Scenario: Dangerous env prefix floors an allowed command

- **GIVEN** `(rule "git" (allow))` and no `safe-env-vars` entry for `LD_PRELOAD`
- **WHEN** evaluating `LD_PRELOAD=/evil.so git status`
- **THEN** the decision SHALL be at least `:ask`
- **AND** the reason SHALL name `LD_PRELOAD`

#### Scenario: Allowlisted env prefix passes through

- **GIVEN** `(rule "git" (allow))` and `(safe-env-vars "GIT_PAGER")` in the primary config
- **WHEN** evaluating `GIT_PAGER=cat git status`
- **THEN** the decision SHALL be `:allow` (the command evaluates as `git status`)

#### Scenario: Mixed prefixes floor if any name is not allowlisted

- **GIVEN** `(rule "git" (allow))` and `(safe-env-vars "GIT_PAGER")`
- **WHEN** evaluating `GIT_PAGER=cat LD_PRELOAD=/evil.so git status`
- **THEN** the decision SHALL be at least `:ask` (the non-allowlisted
  `LD_PRELOAD` floors regardless of the allowlisted `GIT_PAGER`)

### Requirement: The effective safe-env-vars set is primary-config-governed

The `(safe-env-vars STR…)` form SHALL declare environment-variable names that
may appear in command prefix position without flooring. Like `(audit …)`, it
SHALL be honoured only from the primary config; a `(safe-env-vars …)` form in a
`(load …)`-included or repo-local file SHALL be subject to the trust scope
defined in `trust-hashing` (its merged set hashed under the `:safe-env-vars`
scope and inert until approved). When no `(safe-env-vars …)` form is present, the
effective set SHALL be empty and every env prefix SHALL floor.

#### Scenario: Loaded safe-env-vars is inert until approved

- **WHEN** a `(load …)`-included file contributes `(safe-env-vars "FOO")` and the
  `:safe-env-vars` scope has no trust approval
- **THEN** the `FOO` entry SHALL NOT be in the effective set
- **AND** a `FOO=bar cmd` prefix SHALL floor to `:ask`

#### Scenario: Empty set floors every prefix

- **WHEN** no `(safe-env-vars …)` form is configured
- **THEN** any `NAME=VALUE` prefix SHALL floor the segment to at least `:ask`
