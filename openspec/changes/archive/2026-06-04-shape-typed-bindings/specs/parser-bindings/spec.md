## ADDED Requirements

### Requirement: Parameter shape declarations select binding semantics

The parser-body parameter declaration SHALL accept an explicit shape
form between the parameter name and the `#var` slot. The recognised
shape forms SHALL be:

- `(parameter NAME (one  #v))` — single-occurrence; `#v` binds to a
  single token (the value of the parameter). If the parameter occurs
  more than once in argv, only the last occurrence's value SHALL be
  bound (matching today's silent behaviour). Equivalent to writing
  `(parameter NAME #v)` with no shape form.
- `(parameter NAME (last #v))` — multi-occurrence-tolerant; `#v` binds
  to the value of the *last* occurrence as a single token. Identical
  in evaluation to `(one #v)`, but signals to readers and to the type
  checker that the parameter is expected to repeat and that last-wins
  is the intended semantics.
- `(parameter NAME (set  #v))` — multi-occurrence; `#v` binds to the
  collection of all values, in source order. When the parameter does
  not appear in argv, `#v` SHALL bind to the empty collection (not
  unbound); `(bound? #v)` SHALL return false for an empty collection,
  consistent with the existing `(bound? …)` semantics for empty
  bindings.
- `(parameter NAME (command #v))` — single-occurrence command-bearing
  parameter; equivalent to `(one #v)` but marks the binding as
  `Command`-shaped for the type checker. Used for parameters whose
  captured value is a command line, e.g. `bash -c`.

Exactly one shape form per parameter declaration SHALL be permitted.
The legacy `(parameter NAME #v)` form (no shape) SHALL be accepted and
SHALL behave as `(one #v)`.

The shape forms `(one …)`, `(last …)`, `(set …)`, `(command …)` SHALL
appear only inside `(parameter …)` declarations. Their appearance in
any other context SHALL be a config-load error.

#### Scenario: `(set #v)` accumulates all occurrences

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)) (rest #cmd))`
- **WHEN** tokenising `ssh -o BatchMode=yes -o StrictHostKey=yes host`
- **THEN** `#opts` SHALL bind to the token list `["BatchMode=yes", "StrictHostKey=yes"]`.

#### Scenario: `(set #v)` with no occurrences binds empty collection

- **GIVEN** the same parser
- **WHEN** tokenising `ssh host`
- **THEN** `#opts` SHALL bind to the empty token list
- **AND** `(bound? #opts)` SHALL return false.

#### Scenario: `(last #v)` keeps only the final value

- **GIVEN** `(parser "gcc" (style gnu) (flags permute) (parameter "O" (last #opt)))`
- **WHEN** tokenising `gcc -O0 -O2 file.c`
- **THEN** `#opt` SHALL bind to the string `"2"`.

#### Scenario: Unannotated parameter still binds last value

- **GIVEN** `(parser "gcc" (style gnu) (flags permute) (parameter "O" #opt))`
- **WHEN** tokenising `gcc -O0 -O2 file.c`
- **THEN** `#opt` SHALL bind to the string `"2"`
- **AND** the behaviour SHALL be identical to `(last #opt)`.

#### Scenario: `(command #v)` marks bash -c style parameters

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" (command #cmd)))`
- **WHEN** tokenising `bash -c "echo hi"`
- **THEN** `#cmd` SHALL bind to the string `"echo hi"`
- **AND** the binding SHALL be `Command`-shaped for the type checker.

#### Scenario: Shape form outside parameter fails at load

- **GIVEN** `(parser "x" (style gnu) (flags posix) (positional #p (set #q)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error indicating that shape forms
  are valid only inside `(parameter …)` declarations.

### Requirement: `(flag NAME (count #v))` declares a counted-flag binding

The parser-body flag declaration SHALL accept an optional shape form
`(count #v)` that binds `#v` to the non-negative integer count of
occurrences of the flag in argv. The flag SHALL otherwise behave like
an ordinary `(flag NAME)` declaration — it consumes no value and
contributes only its presence (and, with this shape, its count).

`NAME` SHALL be a short flag, a long flag, or a `[short long]` vector,
following existing `(flag …)` grammar. Counting SHALL include every
recognised spelling (short, long, combined-short cluster member,
`--name=true`/`--name=false` forms count once each, with `=false`
counting as one occurrence — the count tracks token occurrences, not
boolean truth values).

`(count #v)` SHALL appear only inside `(flag …)` declarations.

When the flag is absent from argv, `#v` SHALL bind to the integer `0`.
`(bound? #v)` SHALL return true for a `Count`-shaped binding regardless
of the value, including `0`.

#### Scenario: `-vvv` counts three

- **GIVEN** `(parser "curl" (style gnu) (flags permute) (flag "v" (count #verbosity)))`
- **WHEN** tokenising `curl -vvv https://example.com`
- **THEN** `#verbosity` SHALL bind to `3`.

#### Scenario: Repeated long flag counts each occurrence

- **GIVEN** `(parser "grep" (style gnu) (flags permute) (flag ["r" "recursive"] (count #r)))`
- **WHEN** tokenising `grep --recursive -r pattern path`
- **THEN** `#r` SHALL bind to `2`.

#### Scenario: Flag absent counts zero

- **GIVEN** `(parser "curl" (style gnu) (flags permute) (flag "v" (count #verbosity)))`
- **WHEN** tokenising `curl https://example.com`
- **THEN** `#verbosity` SHALL bind to `0`
- **AND** `(bound? #verbosity)` SHALL return true.

## MODIFIED Requirements

### Requirement: `(parameter NAME #var)` binds the captured parameter value

The parser-body `(parameter NAME)` declaration SHALL accept an optional
trailing `#var` slot, or an explicit shape form before the `#var` slot.
The recognised forms SHALL be:

- `(parameter NAME)` — no binding; the parameter is consumed for
  tokenisation purposes but no value is captured for rule access.
- `(parameter NAME #v)` — sugar for `(parameter NAME (one #v))`. When
  the parameter occurs in argv, `#v` SHALL bind to the single string
  value of the last occurrence. When the parameter is absent, `#v`
  SHALL be unbound.
- `(parameter NAME (one  #v))` — explicit single-occurrence form.
  Semantics as for the sugar.
- `(parameter NAME (last #v))` — explicit last-wins form across
  multiple occurrences. `#v` SHALL bind to the value of the last
  occurrence.
- `(parameter NAME (set  #v))` — collection-of-occurrences form. `#v`
  SHALL bind to the list of all values, in source order. When the
  parameter is absent, `#v` SHALL bind to the empty list, and `(bound?
  #v)` SHALL return false.
- `(parameter NAME (command #v))` — single-occurrence command-bearing
  form. `#v` SHALL bind to the captured value as a string; the type
  checker SHALL treat the binding as `Command`-shaped.
- `(parameter NAME (many-till PAT) #v)` — multi-token capture (existing
  form, see the dedicated `(many-till …)` requirement). The binding
  SHALL be `Command`-shaped — see `binding-shapes` for details.

A `(parameter …)` declaration SHALL include at most one shape form.

#### Scenario: Single-value parameter binding

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" #cmd))`
- **WHEN** tokenising `bash -c "echo hi"`
- **THEN** `#cmd` SHALL bind to the string `"echo hi"`.

#### Scenario: Explicit `(one …)` matches sugar behaviour

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" (one #cmd)))`
- **WHEN** tokenising `bash -c "echo hi"`
- **THEN** `#cmd` SHALL bind to the string `"echo hi"`.

#### Scenario: `(many-till …)` parameter with binding

- **GIVEN** `(parser "find" (style single-dash-long) (flags permute) (parameter "exec" (many-till (or ";" "+")) #args))`
- **WHEN** tokenising `find . -exec rm -rf / \;`
- **THEN** `#args` SHALL bind to the token list `[rm, -rf, /]`.

#### Scenario: Parameter absent leaves single-occurrence binding unbound

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" #cmd))`
- **WHEN** tokenising `bash script.sh`
- **THEN** `#cmd` SHALL be unbound
- **AND** `(bound? #cmd)` SHALL return false.

#### Scenario: Parameter absent leaves `(set …)` binding empty

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))`
- **WHEN** tokenising `ssh host`
- **THEN** `#opts` SHALL bind to the empty token list
- **AND** `(bound? #opts)` SHALL return false.

#### Scenario: Parameter without `#var` matches but does not bind

- **GIVEN** `(parser "xargs" (style gnu) (flags posix) (parameter "n") (rest #cmd))`
- **WHEN** tokenising `xargs -n 1 rm -rf`
- **THEN** the parameter `n` SHALL be consumed as a tokenisation effect
- **AND** `#cmd` SHALL bind to `[rm, -rf]`.

#### Scenario: Repeated parameter under `(last …)` keeps final value

- **GIVEN** `(parser "gcc" (style gnu) (flags permute) (parameter "O" (last #opt)))`
- **WHEN** tokenising `gcc -O0 -O2 file.c`
- **THEN** `#opt` SHALL bind to the string `"2"`.

#### Scenario: Repeated parameter under `(set …)` collects all values

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)) (rest #cmd))`
- **WHEN** tokenising `ssh -o BatchMode=yes -o StrictHostKey=yes host rm /tmp/x`
- **THEN** `#opts` SHALL bind to `["BatchMode=yes", "StrictHostKey=yes"]`.

#### Scenario: Multiple shape forms fails at load

- **GIVEN** `(parser "x" (style gnu) (flags posix) (parameter "k" (set #a) (last #b)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error indicating that at most one
  shape form is permitted per parameter.
