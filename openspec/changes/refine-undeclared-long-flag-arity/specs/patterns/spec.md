## ADDED Requirements

### Requirement: Undeclared long-flag value consumption under gnu Styles is value-shaped

Under gnu-shaped Styles, the Tokenisation SHALL resolve an undeclared long
flag's unknown arity by consuming the next token as its value **only when that
token is a plausible value**, and SHALL otherwise treat the flag as value-less
(boolean), leaving the following token in the positional residual. A gnu-shaped
Style has `--` long-prefix, `-` short-prefix, and `=` among its separators. An
"undeclared" long flag is one that is **neither** declared as a `(parameter …)`
on the active Parser **nor** implicitly registered by a `(parameter …)` Pattern
in a matching Rule.

A token is **not** a plausible value (i.e. it is flag-shaped, so it is not
consumed) when it begins with the Style's long-prefix or short-prefix and the
character immediately after the prefix is a letter. A token whose first
post-prefix character is a digit (e.g. `-5`), a bare `-`, or a token bearing no
flag-prefix at all IS a plausible value and SHALL be consumed.

A flag declared as a `(parameter …)` — on the Parser or implicitly via a Rule
Pattern — has author-asserted arity and SHALL continue to consume its next token
regardless of that token's shape.

This requirement governs only the positional residual seen by `(positional …)`
Patterns. `(flag …)`, `(anywhere …)`, and `(forbidden …)` scan the raw argv and
are unaffected by value consumption.

#### Scenario: Undeclared boolean does not consume a following flag

- **GIVEN** no Parser declaration for `cargo` and no Rule referencing `--quiet`
  or `--bin` as a `(parameter …)`
- **WHEN** evaluating `cargo run --quiet --bin may-i -- eval`
- **THEN** `--quiet` SHALL be treated as value-less
- **AND** `--bin` SHALL consume `may-i` as its value
- **AND** the positional residual SHALL be `[run, --, eval]`, so `(positional
  "run" "--")` matches adjacently

#### Scenario: Undeclared boolean does not consume a subcommand it precedes

- **GIVEN** no Parser declaration for `cargo`
- **WHEN** evaluating `cargo --release build`
- **THEN** `--release` SHALL be treated as value-less
- **AND** `build` SHALL remain in the positional residual, so `(positional
  "build")` matches

#### Scenario: Undeclared flag consumes a plausible (non-flag) value

- **GIVEN** no Parser declaration for `tool`
- **WHEN** evaluating `tool --output report.txt`
- **THEN** `--output` SHALL consume `report.txt`
- **AND** the positional residual SHALL be empty

#### Scenario: A negative-number token is a plausible value

- **GIVEN** no Parser declaration for `tool`
- **WHEN** evaluating `tool --threshold -5 input`
- **THEN** `--threshold` SHALL consume `-5`
- **AND** `input` SHALL remain in the positional residual

#### Scenario: A declared parameter consumes a flag-shaped value

- **GIVEN** `(parser "grep" (style gnu) (parameter ["e" "regexp"]))`
- **WHEN** evaluating `grep --regexp --foo file`
- **THEN** `--regexp` SHALL consume `--foo` as its value (author-asserted arity)
- **AND** `file` SHALL remain in the positional residual

### Requirement: The `--` flag-stop is never consumed as a flag value

The `--` flag-stop SHALL never be absorbed as the value of an undeclared long
flag. Its terminator semantics — every subsequent token is a positional —
SHALL hold regardless of any preceding undeclared flag.

#### Scenario: Undeclared flag before `--` does not eat the terminator

- **GIVEN** no Parser declaration for `tool`
- **WHEN** evaluating `tool --undeclared -- value`
- **THEN** `--undeclared` SHALL be treated as value-less
- **AND** `--` SHALL retain its flag-stop role
- **AND** `value` SHALL be a positional via the flag-stop

### Requirement: An undeclared long-flag arity guess is surfaced as an Advisory

The evaluation SHALL emit an Advisory in the Trace whenever the Tokenisation has
to guess — an undeclared, gnu-shaped long flag immediately followed by a
plausible (non-flag) value, where consuming versus not consuming would change
the positional residual. The Advisory SHALL name the flag and the consumed token
so the guess is observable rather than silent, and SHALL NOT, by itself, change
the Decision. No Advisory SHALL be emitted when no guess was made (the flag was
declared, or the following token was flag-shaped and left unconsumed).

#### Scenario: Guess on a non-flag value emits an Advisory

- **GIVEN** no Parser declaration for `tool` and no Rule referencing `--output`
  as a `(parameter …)`
- **WHEN** evaluating `tool --output report.txt`
- **THEN** the Trace SHALL include an Advisory naming `--output` and the
  consumed token `report.txt`

#### Scenario: No guess, no Advisory

- **GIVEN** no Parser declaration for `tool`
- **WHEN** evaluating `tool --verbose --quiet run`
- **THEN** `--verbose` and `--quiet` SHALL be value-less (their successors are
  flag-shaped or already resolved)
- **AND** no arity-guess Advisory SHALL be emitted for them

#### Scenario: Declared parameter does not emit an arity-guess Advisory

- **GIVEN** `(parser "tool" (style gnu) (parameter "output"))`
- **WHEN** evaluating `tool --output report.txt`
- **THEN** no arity-guess Advisory SHALL be emitted (the arity was declared, not
  guessed)
