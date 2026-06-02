## MODIFIED Requirements

### Requirement: Parser body is a form-list of declarations

The `(parser PROG …)` body SHALL be a sequence of zero or more `(KIND ARGS…)` declarations. The legacy `:style STYLE` PLIST key SHALL retire. Style is declared as `(style STYLE)` within the body.

Recognised declaration kinds SHALL be:

- `(style NAME)` — names a style defined in prelude or user config; required, exactly one.
- `(flag NAME)` — declares a pure boolean flag spelling.
- `(parameter NAME [BODY])` — declares a value-bearing parameter spelling.

(See "`(flags MODE)` declares flag-scanning mode" and "`(rest #var)` declares the rest-slice binding" elsewhere in this spec for the remaining recognised kinds.)

The legacy `(tail (after …))` parser-body form SHALL retire and SHALL be a config-load error suggesting `(flags MODE)` plus `(rest #var)`.

Unknown declaration kinds SHALL be a config-load error naming the unknown kind.

#### Scenario: Form-list parser body parses

- **GIVEN** `(parser "kubectl" (style gnu) (parameter ["n" "namespace"]))`
- **WHEN** the config is loaded
- **THEN** the resolved parser for `kubectl` SHALL use `gnu` style and treat `n`/`namespace` as value-bearing.

#### Scenario: Legacy `:style` PLIST key fails at load

- **GIVEN** `(parser "kubectl" :style gnu (parameter ["n"]))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a clear error pointing to the `:style` key.

#### Scenario: Unknown declaration kind fails at load

- **GIVEN** `(parser "x" (style gnu) (frobnicate))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error naming `frobnicate`.

#### Scenario: Legacy `(tail (after …))` parser-body fails at load

- **GIVEN** `(parser "sudo" (style gnu) (tail (after :flags)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error suggesting `(flags posix) (rest #cmd)`.

### Requirement: `(authorise)` is the sole recursion verb

The recursion verb SHALL be spelled `(authorise)`. It SHALL take no arguments. The legacy `(may-i *)` form SHALL retire. The bare `*` placeholder SHALL retire from this position.

`(authorise)` SHALL only appear nested in a host context that delivers a string operand:

- inside `(parameter NAME (authorise))` — the parameter's captured value
- inside `(tail (authorise))` — the rule-side rest slice (scoped by the parser's `(flags MODE)`)
- as a leaf element of `(positional X (authorise) Y)` — the single positional at this slot

Bare `(authorise)` outside any host context SHALL be a config-load error.

#### Scenario: Authorise inside parameter

- **GIVEN** `(parser "bash" (style gnu) (parameter "c" (authorise)))` and rules covering `echo`
- **WHEN** evaluating `bash -c "echo hi"`
- **THEN** the inner `echo hi` SHALL be re-authorised.

#### Scenario: Authorise inside tail

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))` and `(rule "sudo" (tail (authorise)))`, with rules covering `rm`
- **WHEN** evaluating `sudo rm -rf /tmp/x`
- **THEN** the inner `rm -rf /tmp/x` SHALL be re-authorised.

#### Scenario: Bare `(authorise)` at rule body fails at load

- **GIVEN** `(rule "sudo" (authorise))` with no host context
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error suggesting `(tail (authorise))` or a positional context.
