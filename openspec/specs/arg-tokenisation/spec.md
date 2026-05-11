# arg-tokenisation Specification

## Purpose
TBD - created by archiving change per-command-arg-style. Update Purpose after archive.
## Requirements
### Requirement: `(define NAME (PLIST))` declares a parsing style

The config language SHALL accept a top-level form `(define NAME (PLIST))`
that binds `NAME` to a parsing style described by `PLIST`. `PLIST` is a
property list whose keys are drawn from the style schema (see below).

Recognised PLIST keys SHALL be:

- `:long-prefix STRING` — prefix for long flags (default `"--"`).
- `:short-prefix STRING` — prefix for short flags (default `"-"`).
- `:separators (STRING …)` — separators allowed between a parameter and
  its value (default `(" ")`).
- `:combined-shorts BOOL` — whether `-rf` expands to `-r -f` (default
  `nil`).
- `:first-token-bundle BOOL` — whether the first non-dashed alpha cluster
  is treated as a flag bundle (default `nil`).
- `:pun KEYWORD` — `:allow` or `:error`. Decides what a bare parameter
  occurrence (no value, no separator) means: `:allow` ⇒ value-less
  presence (matches `(flag X)` only); `:error` ⇒ tokenisation error
  (default `:allow`).
- `:overrides NAME` — derive from a previously-defined style, replacing
  keys listed in this PLIST.

Unknown PLIST keys SHALL be a config-load error.

When a name is re-defined, the last `(define …)` SHALL win and a warning
SHALL be emitted.

#### Scenario: Define a custom style

- **GIVEN** `(define java (:overrides gnu :separators (" " "=" ":")))`
- **THEN** the resolved `java` style SHALL accept `-Xmx=512m`,
  `-Xmx 512m`, and `-Xmx:512m` as parameter-with-value forms

#### Scenario: Style derivation replaces list-valued keys

- **GIVEN** `(define gnu (… :separators (" " "=") …))`
- **AND** `(define java (:overrides gnu :separators (" " "=" ":")))`
- **THEN** `java` resolved `:separators` SHALL be `(" " "=" ":")` exactly
  (no merge with `gnu`'s separators)

#### Scenario: Unknown PLIST key fails at load

- **GIVEN** `(define bad (:wibble t))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error naming `:wibble`

#### Scenario: Cycle in `:overrides` fails at load

- **GIVEN** `(define a (:overrides b))` and `(define b (:overrides a))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error naming the cycle

### Requirement: Prelude ships standard styles

The prelude SHALL define the following styles before any user config is
loaded:

- `gnu` — long-prefix `"--"`, short-prefix `"-"`, separators `(" " "=")`,
  combined-shorts `t`, first-token-bundle `nil`, pun `:allow`.
- `single-dash-long` — long-prefix `"-"`, short-prefix `"-"`,
  separators `(" " "=")`, combined-shorts `nil`, first-token-bundle
  `nil`, pun `:allow`.
- `legacy-bundle` — `:overrides gnu :first-token-bundle t`.
- `key-value` — long-prefix `""`, short-prefix `""`, separators `("=")`,
  combined-shorts `nil`, first-token-bundle `nil`, pun `:error`.

User `(define …)` forms MAY shadow or `:overrides` these names.

#### Scenario: Prelude styles are referenceable without explicit definition

- **GIVEN** no user `(define …)` for `gnu`
- **THEN** `(parser "git" :style gnu)` SHALL resolve successfully

### Requirement: `(parser PROGRAM :style STYLE BODY…)` declares a parser

The config language SHALL accept a top-level form `(parser PROGRAM :style
STYLE BODY…)` that declares how `PROGRAM`'s argv is parsed. `STYLE` MUST
name a style defined in the prelude or user config.

`BODY` SHALL be a sequence of zero or more declarations, each of:

- `(flag NAME)` — `NAME` is the spelling of a pure boolean flag. `NAME`
  is a string (length 1 ⇒ short, longer ⇒ long) or a vector
  `[short long]` of two strings.
- `(parameter NAME [FORM])` — `NAME` is the spelling of a value-bearing
  parameter. `NAME` follows the same rules as `(flag …)`. `FORM` is
  optional:
  - omitted ⇒ register `NAME` as value-bearing for tokenisation only.
  - `(may-i *)` ⇒ at evaluation time, parse the captured value as a
    command line and re-authorise it via the standard `(may-i …)`
    recursion. The recursion result is recorded as a fact (`:via NAME`)
    and surfaced in the trace; it does NOT short-circuit the rule
    evaluation for `PROGRAM`.
  - any other expression ⇒ rejected at parse time.

When the same parameter or flag name is declared twice in one parser
body, the last declaration SHALL win and a warning SHALL be emitted.

When multiple `(parser …)` forms exist for the same program, the last
SHALL win and a warning SHALL be emitted.

#### Scenario: Parser-level parameter registers as value-bearing

- **GIVEN** `(parser "kubectl" :style gnu (parameter ["n" "namespace"]))`
- **WHEN** evaluating `kubectl -n my-ns get pods`
- **THEN** the tokeniser SHALL group `-n my-ns` as a parameter-value pair
- **AND** the positional stream SHALL be `[get, pods]`

#### Scenario: Parser-level `(parameter X (may-i *))` triggers always-on recursion

- **GIVEN** `(parser "bash" :style gnu (parameter "c" (may-i *)))`
- **AND** rules covering `echo`
- **WHEN** evaluating `bash -c "echo hi"`
- **THEN** the inner `echo hi` SHALL be re-authorised by `(may-i)`
- **AND** the trace SHALL show the inner evaluation under the parser
  declaration

#### Scenario: Boolean flag declaration

- **GIVEN** `(parser "rm" :style gnu (flag "r"))`
- **WHEN** evaluating `rm -r foo`
- **THEN** `(flag "r")` SHALL match in any rule body for `rm`
- **AND** `(parameter "r" *)` SHALL fail at config-load (parameter
  declared as flag)

### Requirement: Default fallback is the `gnu` style with no parameters

When no `(parser …)` declaration exists for a program, the program SHALL
be tokenised under the `gnu` style with no parameter declarations.

#### Scenario: GNU is the default

- **GIVEN** no `(parser …)` declaration for `git`
- **WHEN** evaluating `git push --force`
- **THEN** the tokeniser SHALL apply the `gnu` style
- **AND** `--force` SHALL be classified as a long flag

### Requirement: Pun policy controls bare parameter occurrence

The tokeniser SHALL apply the `:pun` policy of the resolved style when a
parameter `X` is declared at the parser level and the input contains a
bare occurrence of `X` (no value, no separator):

- under `:pun :allow`, the tokeniser SHALL emit `X` as a value-less
  presence — `(flag X)` SHALL match and `(parameter X FORM)` SHALL return
  Nil for any non-trivial `FORM`.
- under `:pun :error`, the tokeniser SHALL fail with a parse error naming
  the offending token.

#### Scenario: Bare parameter under `:pun :allow`

- **GIVEN** `(parser "kubectl" :style gnu (parameter "enable"))`
- **WHEN** evaluating `kubectl --enable get pods`
- **THEN** `(flag "enable")` SHALL match
- **AND** `(parameter "enable" "true")` SHALL NOT match

#### Scenario: Bare parameter under `:pun :error`

- **GIVEN** `(parser "dd" :style key-value (parameter "if"))`
- **WHEN** evaluating `dd if foo`
- **THEN** loading the input SHALL fail with a tokenisation error

### Requirement: Parser applies to the command being evaluated

When a command's args are tokenised, the parser SHALL be looked up by the
name of the command being evaluated (not the wrapping command). When
`(may-i …)` recurses into an inner command, the inner command's parser
SHALL apply to the inner argv.

#### Scenario: Inner command uses its own parser under `(may-i)`

- **GIVEN** `(parser "find" :style single-dash-long)`
- **AND** `(rule "sudo" (positional . (may-i *)))`
- **WHEN** evaluating `sudo find . -name foo`
- **THEN** the recursion SHALL tokenise the inner `find . -name foo`
  under the `single-dash-long` style
- **AND** `-name` SHALL be a single long flag in the inner evaluation

### Requirement: Trace surfaces the resolved parser

The trace renderer SHALL include the resolved parser declaration for the
command-under-evaluation in its output: program name, style name, and
the list of flag/parameter declarations.

#### Scenario: Trace shows the active parser

- **WHEN** running `may-i eval` against any command
- **THEN** the trace SHALL include a section identifying the resolved
  parser and any parser-level flag/parameter declarations

