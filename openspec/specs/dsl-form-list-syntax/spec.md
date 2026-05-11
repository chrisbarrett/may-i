# dsl-form-list-syntax Specification

## Purpose

The form-list calling convention for DSL bodies (`(parser …)`, `(define-arg-style …)`, `(check …)`) and the canonical surface syntax for decision verbs (`(allow …)`, `(ask …)`, `(deny …)`) and recursion (`(authorise)`). Legacy PLIST-style bodies and the `(effect …)` form are retired and rejected at config-load time.

## Requirements

### Requirement: Parser body is a form-list of declarations

The `(parser PROG …)` body SHALL be a sequence of zero or more `(KIND ARGS…)` declarations. The legacy `:style STYLE` PLIST key SHALL retire. Style is declared as `(style STYLE)` within the body.

Recognised declaration kinds SHALL be:

- `(style NAME)` — names a style defined in prelude or user config; required, exactly one.
- `(flag NAME)` — declares a pure boolean flag spelling.
- `(parameter NAME [BODY])` — declares a value-bearing parameter spelling.
- `(tail …)` — declares a wrapper-tail slice; at most one.

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

### Requirement: `define-arg-style` body is a form-list of attribute forms

The `(define-arg-style NAME …)` body SHALL be a sequence of attribute forms. The legacy PLIST `(define-arg-style NAME (:k v :k v))` body SHALL retire.

Recognised attribute forms SHALL be:

- `(overrides NAME)` — derive from a previously-defined style.
- `(long-prefix STRING)` — long-flag prefix.
- `(short-prefix STRING)` — short-flag prefix.
- `(separators STRING…)` — variadic; allowed value separators.
- `(combined-shorts BOOL)` — whether `-rf` expands to `-r -f`.
- `(first-token-bundle BOOL)` — whether the first non-dashed alpha cluster is a flag bundle.
- `(pun KEYWORD)` — `:allow` or `:error`; bare-parameter occurrence policy.

Unknown attribute forms SHALL be a config-load error naming the unknown attribute.

When an attribute is declared more than once, the last declaration SHALL win and a warning SHALL be emitted.

#### Scenario: Form-list define-arg-style parses

- **GIVEN** `(define-arg-style java (overrides gnu) (separators " " "=" ":"))`
- **WHEN** the config is loaded
- **THEN** the resolved `java` style SHALL accept `-Xmx=512m`, `-Xmx 512m`, and `-Xmx:512m`.

#### Scenario: Legacy PLIST define-arg-style fails at load

- **GIVEN** `(define-arg-style java (:overrides gnu :separators (" " "=" ":")))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a clear error.

### Requirement: `check` body is a form-list of decision-tagged commands

The `(check …)` body SHALL be a sequence of `(DECISION COMMAND-STRING REASON?)` forms where `DECISION` is one of `allow`, `ask`, `deny`. The legacy PLIST form `(check :allow CMD :ask CMD :deny CMD)` SHALL retire.

#### Scenario: Form-list check parses

- **GIVEN** `(check (allow "ls -la") (ask "rm -rf /tmp/foo") (deny "rm -rf /"))`
- **WHEN** `may-i check` is invoked
- **THEN** each case SHALL be evaluated and the result compared to its tagged decision.

#### Scenario: Legacy PLIST check fails at load

- **GIVEN** `(check :allow "ls -la" :deny "rm -rf /")`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a clear error.

### Requirement: Decision verbs replace `(effect …)`

Rule body decisions SHALL be expressed as `(allow REASON?)`, `(ask REASON?)`, `(deny REASON?)`. The legacy `(effect DECISION REASON?)` form SHALL retire from surface syntax.

`REASON` SHALL be an optional string. When present, it SHALL be surfaced in traces and permission prompts identically to today's `(effect …)` reason.

#### Scenario: Bare decision verb

- **GIVEN** `(rule "ls" (allow))`
- **WHEN** evaluating `ls`
- **THEN** the rule SHALL return `:allow`.

#### Scenario: Decision verb with reason

- **GIVEN** `(rule "rm" (and (flag "r") (ask "Recursive deletion")))`
- **WHEN** evaluating `rm -r foo`
- **THEN** the rule SHALL return `:ask` with reason "Recursive deletion".

#### Scenario: Legacy `(effect …)` form fails at load

- **GIVEN** `(rule "ls" (effect :allow))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a clear error pointing to `(effect …)`.

### Requirement: `(authorise)` is the sole recursion verb

The recursion verb SHALL be spelled `(authorise)`. It SHALL take no arguments. The legacy `(may-i *)` form SHALL retire. The bare `*` placeholder SHALL retire from this position.

`(authorise)` SHALL only appear nested in a host context that delivers a string operand:

- inside `(parameter NAME (authorise))` — the parameter's captured value
- inside `(tail (authorise))` — the tail slice
- as a leaf element of `(positional X (authorise) Y)` — the single positional at this slot

Bare `(authorise)` outside any host context SHALL be a config-load error.

#### Scenario: Authorise inside parameter

- **GIVEN** `(parser "bash" (style gnu) (parameter "c" (authorise)))` and rules covering `echo`
- **WHEN** evaluating `bash -c "echo hi"`
- **THEN** the inner `echo hi` SHALL be re-authorised.

#### Scenario: Authorise inside tail

- **GIVEN** `(parser "sudo" (style gnu) (tail (after :flags)))` and `(rule "sudo" (tail (authorise)))`, with rules covering `rm`
- **WHEN** evaluating `sudo rm -rf /tmp/x`
- **THEN** the inner `rm -rf /tmp/x` SHALL be re-authorised.

#### Scenario: Bare `(authorise)` at rule body fails at load

- **GIVEN** `(rule "sudo" (authorise))` with no host context
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error suggesting `(tail (authorise))` or a positional context.

### Requirement: Decision verbs and recursion verb retire keyword usage

After this change, keyword (colon-prefixed) tokens in user-written DSL SHALL appear only in:

- fact keys (`:via`, `:ssh/host`, user-defined fact keys)
- enum values inside forms (`(pun :allow)`, `(pun :error)`, `(after :flags)`)

Keywords as PLIST keys SHALL NOT appear in any body. Keywords as decision tags inside `(effect …)` SHALL NOT appear (the form retires).

#### Scenario: Lint-style assertion across DSL

- **WHEN** the config-load pass scans surface forms
- **THEN** every keyword token SHALL be either a fact key or an enum value inside a form
- **AND** any other keyword usage SHALL produce a load-time diagnostic.
