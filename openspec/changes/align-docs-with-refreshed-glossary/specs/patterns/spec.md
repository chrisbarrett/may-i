## MODIFIED Requirements

### Requirement: Argv matchers scope to the outer slice

The matchers `(flag …)`, `(parameter …)`, `(positional …)`, `(exact …)`, `(anywhere …)`, `(forbidden …)` SHALL operate exclusively on the outer slice produced by tokenisation. Tokens past the outer slice (claimed by the parser's `(rest …)` binding) SHALL NOT be visible to these matchers.

The outer/rest split SHALL be determined by the parser's `(flags MODE)`:

- Under `(flags posix)` the outer slice ends at the first non-flag token; everything from that point on is rest.
- Under `(flags (until STR…))` the outer slice ends immediately before the first matching boundary token; the boundary token is consumed and dropped, and the remainder is rest.
- Under `(flags permute)` (the default for undeclared programs) the outer slice is the whole argv and there is no rest unless a positional declaration leaves a residual.

The rest slice SHALL be addressable only via `(authorise #var)` where `#var` is the parser's `(rest …)` binding (typically `#cmd`).

#### Scenario: Flag matcher does not see rest tokens under posix

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))` and `(rule "sudo" (and (flag "r") (deny "outer flag")))`
- **WHEN** evaluating `sudo rm -rf /tmp/x`
- **THEN** `(flag "r")` SHALL NOT match (the `-r` is in the rest slice).

#### Scenario: Forbidden matcher does not see rest tokens under posix

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))` and `(rule "sudo" (and (forbidden "secret") (allow)))`
- **WHEN** evaluating `sudo echo secret`
- **THEN** `(forbidden "secret")` SHALL succeed (the `secret` token is in the rest slice, not visible).

#### Scenario: Outer slice ends at boundary token under until

- **GIVEN** `(parser "nix" (style gnu) (flags (until "--command" "-c")) (rest #cmd))` and `(rule "nix" (and (flag "i") (deny "no impure")))`
- **WHEN** evaluating `nix --command bash -i`
- **THEN** `(flag "i")` SHALL NOT match (the `-i` is past the `--command` boundary, in the rest slice).

### Requirement: Optional quantifier matches with or without arg

A pattern wrapped in `(? PAT)` (the optional quantifier) SHALL match even when the arg at that position is absent. When the arg is present, it MUST match `PAT`.

#### Scenario: Optional positional present

- **WHEN** matching the positional patterns `"branch" (? "branch")` against the args `branch branch`
- **THEN** matching SHALL succeed.

#### Scenario: Optional positional absent

- **WHEN** matching the positional patterns `"push" (? "origin")` against the args `push`
- **THEN** matching SHALL succeed.

#### Scenario: Optional positional present but value mismatch

- **WHEN** matching the positional patterns `"branch" (? "branch")` against the args `branch tag`
- **THEN** matching SHALL NOT succeed.

### Requirement: One-or-more quantifier requires at least one match

A pattern wrapped in `(+ PAT)` (the one-or-more quantifier) SHALL require at least one arg at the pattern's position. All remaining args from that position onward MUST match `PAT`.

#### Scenario: One-or-more wildcard with one arg

- **WHEN** matching the positional pattern `(+ *)` against the args `file1`
- **THEN** matching SHALL succeed.

#### Scenario: One-or-more wildcard with multiple args

- **WHEN** matching the positional pattern `(+ *)` against the args `file1 file2 file3`
- **THEN** matching SHALL succeed.

#### Scenario: One-or-more with no args

- **WHEN** matching the positional patterns `"cmd" (+ *)` against the args `cmd`
- **THEN** matching SHALL NOT succeed.

### Requirement: Zero-or-more quantifier matches any count

A pattern wrapped in `(* PAT)` (the zero-or-more quantifier) SHALL match zero or more remaining args from that position. All remaining args MUST match `PAT`.

#### Scenario: Zero-or-more wildcard with no args

- **WHEN** matching the positional patterns `"cmd" (* *)` against the args `cmd`
- **THEN** matching SHALL succeed.

#### Scenario: Zero-or-more wildcard with multiple args

- **WHEN** matching the positional pattern `(* *)` against the args `a b c`
- **THEN** matching SHALL succeed.
