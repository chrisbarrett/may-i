## ADDED Requirements

### Requirement: `(tail (after VALUE))` declares a tail slice in a parser

The parser body SHALL accept at most one `(tail (after VALUE))` declaration. `VALUE` SHALL be either:

- a keyword tag from the closed enum `{:flags}` — built-in named position; `:flags` means "after outer flags and parameters are consumed".
- a string literal — the explicit boundary token.

`VALUE` of any other shape SHALL be a config-load error naming the offending form.

When a parser declares `(tail …)`, the tokeniser SHALL produce two slices for any argv:

- **outer**: tokens up to the boundary, parsed under the active style.
- **tail**: tokens after the boundary, kept verbatim with no flag interpretation.

For `(tail (after :flags))`, the outer slice ends after the last flag/parameter consumed; the tail begins at the first non-flag token. For `(tail (after "--"))`, the outer slice ends before the literal `--`; the boundary token itself is dropped and the tail begins at the next token.

#### Scenario: Parser declares `(tail (after :flags))`

- **GIVEN** `(parser "sudo" (style gnu) (tail (after :flags)))`
- **WHEN** tokenising `sudo rm -rf /tmp/x`
- **THEN** outer SHALL be `[sudo]` and tail SHALL be `[rm, -rf, /tmp/x]`.

#### Scenario: Parser declares `(tail (after "--"))`

- **GIVEN** `(parser "mise" (style gnu) (tail (after "--")))`
- **WHEN** tokenising `mise exec foo -- rm -rf /tmp/x`
- **THEN** outer SHALL be `[mise, exec, foo]` and tail SHALL be `[rm, -rf, /tmp/x]`.

#### Scenario: Multiple `(tail …)` declarations fail at load

- **GIVEN** `(parser "x" (style gnu) (tail (after :flags)) (tail (after "--")))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error.

#### Scenario: `(after …)` body of unrecognised shape fails at load

- **GIVEN** `(parser "x" (style gnu) (tail (after 42)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail naming the unrecognised body.

### Requirement: `(tail (authorise))` recurses on the tail slice

The rule body form `(tail (authorise))` SHALL recursively authorise the tail slice as a command line:

- The tail tokens SHALL be joined by single spaces.
- The joined string SHALL be parsed by the shell command parser into an inner command and inner argv.
- The inner command SHALL be re-evaluated against the active rule set, with `:via PROG` accumulating into facts.
- The result SHALL be the recursed decision.

`(tail X)` body SHALL be restricted to `(authorise)`. Any other body SHALL be a config-load error.

#### Scenario: `(tail (authorise))` recurses

- **GIVEN** `(parser "sudo" (style gnu) (tail (after :flags)))`, `(rule "sudo" (tail (authorise)))`, and `(rule "rm" (and (flag "r") (deny "no rm -r")))`
- **WHEN** evaluating `sudo rm -rf /tmp/x`
- **THEN** the inner evaluation SHALL see argv `[-rf, /tmp/x]` for `rm` and the rule SHALL return `:deny`.

#### Scenario: `(tail (authorise))` records `:via`

- **GIVEN** the configuration above
- **WHEN** evaluating `sudo rm -r /tmp/x`
- **THEN** the inner evaluation's facts SHALL include `:via "sudo"`.

#### Scenario: `(tail (regex …))` fails at load

- **GIVEN** `(rule "sudo" (tail (regex "^safe")))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail naming the unrecognised body.

### Requirement: When parser declares `(tail …)`, argv matchers scope to outer slice

When the resolved parser for the command-under-evaluation declares `(tail …)`, the matchers `(flag …)`, `(parameter …)`, `(positional …)`, `(exact …)`, `(anywhere …)`, `(forbidden …)` SHALL operate exclusively on the outer slice. The tail slice SHALL be addressable only via `(tail (authorise))`.

#### Scenario: Outer-only flag scope under `(tail …)`

- **GIVEN** `(parser "sudo" (style gnu) (tail (after :flags)))` and `(rule "sudo" (and (flag "r") (deny "outer flag")))`
- **WHEN** evaluating `sudo rm -rf /tmp/x`
- **THEN** `(flag "r")` SHALL NOT match (outer slice contains only `[sudo]`).

#### Scenario: Outer-only positional scope under `(tail …)`

- **GIVEN** `(parser "mise" (style gnu) (tail (after "--")))` and `(rule "mise" (positional "exec"))`
- **WHEN** evaluating `mise exec -- rm -rf /tmp/x`
- **THEN** `(positional "exec")` SHALL match (outer slice is `[mise, exec]`).

#### Scenario: Outer-only forbidden scope under `(tail …)`

- **GIVEN** `(parser "sudo" (style gnu) (tail (after :flags)))` and `(rule "sudo" (and (forbidden "secret") (allow)))`
- **WHEN** evaluating `sudo echo secret`
- **THEN** `(forbidden "secret")` SHALL succeed (outer slice does not contain `secret`).

### Requirement: `(tail (authorise))` without parser-declared tail uses residual positionals

When a rule contains `(tail (authorise))` and the parser for the command does NOT declare `(tail …)`, `(tail (authorise))` SHALL operate on the residual positional stream — positionals not consumed by preceding `(positional …)` matchers in the same rule body.

#### Scenario: ssh-style fact-bind then recurse without parser-declared tail

- **GIVEN** `(parser "ssh" (style gnu))` (no tail) and `(rule "ssh" (and (positional [:ssh/host *]) (tail (authorise))))`
- **WHEN** evaluating `ssh user@host rm -rf /tmp/x`
- **THEN** `(positional [:ssh/host *])` SHALL bind `user@host` as `:ssh/host`
- **AND** `(tail (authorise))` SHALL recurse on `rm -rf /tmp/x`.

#### Scenario: Quoted single-string inner cmd

- **GIVEN** the configuration above
- **WHEN** evaluating `ssh user@host "rm -rf /tmp/x"`
- **THEN** `(tail (authorise))` SHALL recurse on `rm -rf /tmp/x` (joined-and-reparsed from the single quoted positional).

### Requirement: Trace surfaces outer/tail split

When a parser declares `(tail …)`, the trace renderer SHALL include both slices in its output for the command under evaluation. The output SHALL clearly distinguish outer and tail tokens and SHALL identify the resolved boundary (keyword tag or literal token).

#### Scenario: Trace shows outer/tail split

- **WHEN** running `may-i eval 'sudo rm -rf /tmp/x'` with prelude parsers
- **THEN** the trace SHALL include a section showing outer = `[sudo]`, tail = `[rm, -rf, /tmp/x]`, and the boundary as `(after :flags)`.

### Requirement: Improper-list `(positional X . CONT)` retires

The dotted-tail continuation form `(positional X . CONT)` SHALL retire. It SHALL be replaced by sibling forms — `(positional X)` and `(tail (authorise))` — composed via `(and …)` or other rule-body combinators.

#### Scenario: Improper-list rule fails at load

- **GIVEN** `(rule "sudo" (positional . (may-i *)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error suggesting the migrated form.
