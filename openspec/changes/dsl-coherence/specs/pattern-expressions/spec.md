## MODIFIED Requirements

### Requirement: `(parameter X FORM)` matches flag value

The pattern `(parameter X FORM)` SHALL extract the value of the named flag
from the tokenised arg stream and evaluate `FORM` against that value. If
the flag is absent, the pattern SHALL return Nil. If the flag is present,
the pattern's result SHALL be the result of `FORM` evaluated against the
flag's value.

`(parameter X FORM)` SHALL match the value regardless of whether it was
attached via `=` or supplied as the next argument:

- `-X VAL`
- `-X=VAL`
- `--long VAL`
- `--long=VAL`

`(parameter X FORM)` SHALL consume both the flag token and its value from
the stream visible to sibling matchers in the same rule.

`(parameter X FORM)` SHALL implicitly register `X` as a value-bearing flag
for the active tokenisation, so that the surrounding evaluation tokenises
the input with the flag-value pair correctly grouped, even when no
`(parser …)` declaration lists `X` as a parameter.

`FORM` SHALL be either:

- `(authorise)` — the value is parsed as a command line and recursively
  evaluated against the rule set; the recursed decision propagates;
- any expression form (string literal, `(regex …)`, `*`, `(or …)`,
  `(and …)`, `(not …)`, fact-bind `[:k EXPR]`) — the value is matched as a
  single token against the expression.

The legacy `(may-i …)` form SHALL retire from this position. Configs using
`(may-i *)` as the parameter body SHALL be a config-load error suggesting
`(authorise)`.

When the parameter is parser-declared with `(many-till PAT)` capture-shape
(see parameter-many-till spec), `FORM` SHALL operate on the joined-tokens
string of the captured value.

#### Scenario: Recurse into the value of a flag via `(authorise)`

- **GIVEN** `(parser "bash" (style gnu) (parameter "c" (authorise)))`
- **AND** rules covering `echo` and `rm`
- **WHEN** evaluating `bash -c "echo hi"`
- **THEN** the inner `echo hi` SHALL be evaluated by `(authorise)`
- **AND** the result SHALL reflect the inner evaluation's decision

#### Scenario: Match flag value against regex

- **GIVEN** `(rule "kubectl" (and (parameter ["n" "namespace"] (regex "^prod-")) (ask "production cluster")))`
- **WHEN** evaluating `kubectl -n prod-foo get pods`
- **THEN** the rule SHALL apply
- **AND** the decision SHALL be `:ask`

#### Scenario: Flag absence yields Nil

- **GIVEN** `(rule "curl" (parameter ["X" "request"] "POST"))`
- **WHEN** evaluating `curl https://example.com`
- **THEN** the rule SHALL NOT apply

#### Scenario: Sibling positional sees consumed flag-value pair removed

- **GIVEN** `(rule "kubectl" (and (parameter ["n" "namespace"] (regex ".*")) (positional "get" "pods")))`
- **WHEN** evaluating `kubectl -n my-ns get pods`
- **THEN** the rule SHALL apply (positional sees `[get, pods]`)

#### Scenario: Legacy `(may-i *)` body fails at load

- **GIVEN** `(parser "bash" (style gnu) (parameter "c" (may-i *)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error suggesting `(authorise)`.

## ADDED Requirements

### Requirement: `(anywhere …)` and `(forbidden …)` honour `--` as flag-stop

The pattern matchers `(anywhere PAT…)` and `(forbidden PAT…)` SHALL stop scanning at the first occurrence of the literal token `--`. Tokens after `--` SHALL be invisible to these matchers.

This SHALL apply universally, regardless of whether the active parser declares `(tail …)`. The `--` token is a universal lexical convention for "no more flags" in GNU-shaped argv; matchers that look for flag-shaped tokens SHALL respect it consistently with `(flag …)` and `(parameter …)`, which already do.

#### Scenario: `(anywhere "--force")` does not match post-`--` token

- **GIVEN** `(rule "git" (and (anywhere "--force") (deny "force flag")))`
- **WHEN** evaluating `git diff -- --force` (where `--force` is a path argument)
- **THEN** `(anywhere "--force")` SHALL NOT match
- **AND** the rule SHALL NOT apply.

#### Scenario: `(forbidden "--force")` succeeds when target is post-`--`

- **GIVEN** `(rule "git" (and (forbidden "--force") (allow "no force flag")))`
- **WHEN** evaluating `git diff -- --force` (where `--force` is a path argument)
- **THEN** `(forbidden "--force")` SHALL succeed (target is post-`--`, not visible)
- **AND** the rule SHALL return `:allow`.

#### Scenario: `(anywhere)` matches pre-`--` token

- **GIVEN** `(rule "git" (and (anywhere "secret") (deny "secret token")))`
- **WHEN** evaluating `git secret commit`
- **THEN** `(anywhere "secret")` SHALL match
- **AND** the rule SHALL return `:deny`.

### Requirement: Argv matchers scope to outer slice when parser declares `(tail …)`

When the resolved parser for the command-under-evaluation declares a `(tail …)`, the matchers `(flag …)`, `(parameter …)`, `(positional …)`, `(exact …)`, `(anywhere …)`, `(forbidden …)` SHALL operate exclusively on the outer slice produced by tokenisation. Tokens in the tail slice SHALL NOT be visible to these matchers.

The tail slice SHALL be addressable only via `(tail (authorise))` (see wrapper-tail spec).

#### Scenario: Flag matcher does not see tail tokens

- **GIVEN** `(parser "sudo" (style gnu) (tail (after :flags)))` and `(rule "sudo" (and (flag "r") (deny "outer flag")))`
- **WHEN** evaluating `sudo rm -rf /tmp/x`
- **THEN** `(flag "r")` SHALL NOT match (the `-r` is in the tail slice).

#### Scenario: Forbidden matcher does not see tail tokens

- **GIVEN** `(parser "sudo" (style gnu) (tail (after :flags)))` and `(rule "sudo" (and (forbidden "secret") (allow)))`
- **WHEN** evaluating `sudo echo secret`
- **THEN** `(forbidden "secret")` SHALL succeed (the `secret` token is in the tail slice, not visible).
