---
audience: user
bucket: parsing
---
# patterns Specification

## Purpose

Defines the Pattern sublanguage used in rule bodies (see `CONTEXT.md` for the *Pattern* term): the flag/parameter/positional Patterns, the `--` flag-stop convention, parser-declared outer-slice scoping, negation, and roundtrip serialisation.

## Requirements

### Requirement: Pattern serialization roundtrips through the parser
A Pattern serialized to its s-expression form SHALL parse back to a structurally equivalent Pattern.

#### Scenario: Arbitrary pattern roundtrip
- **WHEN** a randomly generated Pattern is converted to an s-expression string and parsed back
- **THEN** the result SHALL be structurally equivalent to the original Pattern

### Requirement: `(flag X)` matches flag presence

The pattern `(flag X)` SHALL match when the named flag is present in the
tokenised arg stream, and SHALL NOT match otherwise. `X` SHALL be one of:

- a single string of length 1 — interpreted as a short flag,
- a single string of length greater than 1 — interpreted as a long flag,
- a vector of two strings `[short long]` — matching either form.

The match SHALL recognise all flag forms produced by the active
tokenisation profile, including combined short clusters (`-rf` ⇒ `r` and
`f` are both present under `:gnu`) and `=`-attached values (`--force=true`
⇒ `force` is present).

`(flag X)` SHALL NOT consume tokens; sibling Patterns in the same rule SHALL
see the full token stream.

#### Scenario: Short flag presence in combined cluster

- **GIVEN** `(args-style "rm" :gnu)` (the default)
- **WHEN** evaluating `rm -rf dir`
- **THEN** `(flag "r")` SHALL match
- **AND** `(flag "f")` SHALL match

#### Scenario: Long flag presence with `=`-attached value

- **WHEN** evaluating `git commit --force=true`
- **THEN** `(flag "force")` SHALL match

#### Scenario: Either-form vector matches either spelling

- **WHEN** evaluating `git push -f`
- **THEN** `(flag ["f" "force"])` SHALL match
- **WHEN** evaluating `git push --force`
- **THEN** `(flag ["f" "force"])` SHALL also match

#### Scenario: Absent flag does not match

- **WHEN** evaluating `git push origin`
- **THEN** `(flag "force")` SHALL NOT match
- **AND** `(not (flag "force"))` SHALL match

### Requirement: `(parameter X FORM)` matches flag value

The pattern `(parameter X FORM)` SHALL extract the value of the named flag
from the tokenised arg stream and evaluate `FORM` against that value. If
the flag is absent, the pattern SHALL NOT match. If the flag is present,
the pattern's result SHALL be the result of `FORM` evaluated against the
flag's value.

`(parameter X FORM)` SHALL match the value regardless of whether it was
attached via `=` or supplied as the next argument:

- `-X VAL`
- `-X=VAL`
- `--long VAL`
- `--long=VAL`

`(parameter X FORM)` SHALL consume both the flag token and its value from
the stream visible to sibling Patterns in the same rule.

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
(see `parser-bindings`), `FORM` SHALL operate on the joined-tokens
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

#### Scenario: Flag absence means no match

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

### Requirement: `(anywhere …)` and `(forbidden …)` honour `--` as flag-stop

The Patterns `(anywhere PAT…)` and `(forbidden PAT…)` SHALL stop scanning at the first occurrence of the literal token `--`. Tokens after `--` SHALL be invisible to these Patterns.

This SHALL apply universally, regardless of the parser's `(flags MODE)` or `(rest …)` declaration. The `--` token is a universal lexical convention for "no more flags" in GNU-shaped argv; Patterns that look for flag-shaped tokens SHALL respect it consistently with `(flag …)` and `(parameter …)`, which already do.

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

### Requirement: Argv Patterns scope to the outer slice

The Patterns `(flag …)`, `(parameter …)`, `(positional …)`, `(exact …)`, `(anywhere …)`, `(forbidden …)` SHALL operate exclusively on the outer slice produced by tokenisation. Tokens past the outer slice (claimed by the parser's `(rest …)` binding) SHALL NOT be visible to these Patterns.

The outer/rest split SHALL be determined by the parser's `(flags MODE)`:

- Under `(flags posix)` the outer slice ends at the first non-flag token; everything from that point on is rest.
- Under `(flags (until STR…))` the outer slice ends immediately before the first matching boundary token; the boundary token is consumed and dropped, and the remainder is rest.
- Under `(flags permute)` (the default for undeclared programs) the outer slice is the whole argv and there is no rest unless a positional declaration leaves a residual.

The rest slice SHALL be addressable only via `(authorise #var)` where `#var` is the parser's `(rest …)` binding (typically `#cmd`).

#### Scenario: Flag Pattern does not see rest tokens under posix

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))` and `(rule "sudo" (and (flag "r") (deny "outer flag")))`
- **WHEN** evaluating `sudo rm -rf /tmp/x`
- **THEN** `(flag "r")` SHALL NOT match (the `-r` is in the rest slice).

#### Scenario: Forbidden Pattern does not see rest tokens under posix

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))` and `(rule "sudo" (and (forbidden "secret") (allow)))`
- **WHEN** evaluating `sudo echo secret`
- **THEN** `(forbidden "secret")` SHALL succeed (the `secret` token is in the rest slice, not visible).

#### Scenario: Outer slice ends at boundary token under until

- **GIVEN** `(parser "nix" (style gnu) (flags (until "--command" "-c")) (rest #cmd))` and `(rule "nix" (and (flag "i") (deny "no impure")))`
- **WHEN** evaluating `nix --command bash -i`
- **THEN** `(flag "i")` SHALL NOT match (the `-i` is past the `--command` boundary, in the rest slice).

### Requirement: Negation uses `(not …)`

There SHALL be no separate `(no-flag …)` form. Negation of `(flag …)` and
`(parameter …)` SHALL use the existing `(not …)` Pattern.

#### Scenario: `(not (flag …))` blocks force-style operations

- **GIVEN** `(rule "git" (and (positional "push") (not (flag ["f" "force"])) (allow)))`
- **WHEN** evaluating `git push --force`
- **THEN** the rule SHALL NOT apply
- **AND** the default decision (`:ask`) SHALL stand

### Requirement: `(or …)` matches if any sub-pattern matches
`(or …)` SHALL match if any sub-pattern matches the value. The evaluation SHALL short-circuit on the first matching sub-pattern. Only the facts bound by the first matching sub-pattern SHALL be included in the result. Later alternatives SHALL NOT be evaluated once a match is found.

#### Scenario: First sub-pattern matches
- **WHEN** matching `(or "prod" "staging")` against `"prod"`
- **THEN** it SHALL match

#### Scenario: Later sub-pattern matches
- **WHEN** matching `(or "prod" "staging")` against `"staging"`
- **THEN** it SHALL match

#### Scenario: No sub-pattern matches
- **WHEN** matching `(or "prod" "staging")` against `"dev"`
- **THEN** it SHALL NOT match

#### Scenario: Bound facts from first matching branch only
- **WHEN** matching `(or [:a "prod"] [:b "staging"])` against `"staging"`
- **THEN** bound facts SHALL contain `:b = "staging"` but NOT `:a`

#### Scenario: Short-circuit prevents later binding leakage
- **WHEN** matching `(or [:x *] [:y *])` against `"val"`
- **THEN** bound facts SHALL contain only `:x = "val"`
- **AND** `:y` SHALL NOT be present in bound facts

### Requirement: Fewer args than required patterns returns no match
When the number of available positional args is less than the number of patterns (accounting for quantifiers), positional matching SHALL NOT match.

#### Scenario: Zero args with one required pattern
- **WHEN** matching the positional pattern `"push"` against an empty arg list
- **THEN** it SHALL NOT match

#### Scenario: One arg with two required patterns
- **WHEN** matching the positional patterns `"remote" "add"` against the args `remote`
- **THEN** it SHALL NOT match

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

### Requirement: Bind is valid in positional, exact, and anywhere but not forbidden
A `[:k …]` bind pattern SHALL be accepted by the parser inside `(positional …)`, `(exact …)`, and `(anywhere …)` patterns. The parser SHALL reject a bind inside `(forbidden …)` patterns with a clear error.

#### Scenario: Bind in positional
- **WHEN** parsing `(positional [:ssh/host *])`
- **THEN** it SHALL succeed with a bind pattern

#### Scenario: Bind in exact
- **WHEN** parsing `(exact [:env "prod"])`
- **THEN** it SHALL succeed with a bind pattern

#### Scenario: Bind in anywhere
- **WHEN** parsing `(anywhere [:git/branch (regex "^(main|master)$")])`
- **THEN** it SHALL succeed with a bind pattern

#### Scenario: Bind in forbidden rejected
- **WHEN** parsing `(forbidden [:key *])`
- **THEN** the parser SHALL reject it with an error explaining bind is not valid in forbidden patterns

### Requirement: Command-dispatch position rejects regex patterns

The command-dispatch position of a `(rule …)` SHALL accept only a literal string or an `(or …)` of literal strings — the program name the rule applies to. A `(regex …)` in command-dispatch position SHALL be a parse error.

#### Scenario: Regex in command position is a parse error

- **WHEN** config contains `(rule (regex "^git-.*") (allow))`
- **THEN** the parser reports an error
