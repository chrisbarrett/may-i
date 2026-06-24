---
audience: user
bucket: parsing
---
# patterns Specification

## Purpose

Defines the Pattern sublanguage used in rule bodies (see `CONTEXT.md` for the *Pattern* term): the flag/parameter/positional Patterns, the `--` flag-stop convention, parser-declared outer-slice scoping, negation, and roundtrip serialisation. Also defines the collection quantifiers `(every? #var PRED)` / `(some? #var PRED)`; the binding shapes they require and the load-time checking of those uses are specified in `binding-shapes` (contributor-facing).

## Requirements

### Requirement: Pattern serialization roundtrips through the parser
A Pattern serialized to its s-expression form SHALL parse back to a structurally equivalent Pattern. This SHALL hold for quantifier Patterns carrying a sequence of sub-patterns, including nested groups.

#### Scenario: Arbitrary pattern roundtrip
- **WHEN** a randomly generated Pattern is converted to an s-expression string and parsed back
- **THEN** the result SHALL be structurally equivalent to the original Pattern

#### Scenario: Nested sequence-group roundtrip
- **WHEN** the Pattern `(? "run" (? "--"))` is converted to an s-expression string and parsed back
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

### Requirement: Undeclared long-flag value consumption under gnu Styles is value-shaped

Under gnu-shaped Styles, the Tokenisation SHALL resolve an undeclared long
flag's unknown arity by consuming the next token as its value **only when that
token is a plausible value**, and SHALL otherwise treat the flag as value-less
(boolean), leaving the following token in the positional residual. A gnu-shaped
Style has `--` long-prefix, `-` short-prefix, and `=` among its separators. An
"undeclared" long flag is one that is **neither** declared as a `(parameter …)`
on the active Parser, **nor** implicitly registered by a `(parameter …)` Pattern
in a matching Rule, **nor** declared as a boolean `(flag …)` on the active
Parser. A flag declared as a boolean `(flag …)` has author-asserted value-less
arity and SHALL be treated as value-less — it never consumes the following
token, regardless of that token's shape.

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

#### Scenario: Undeclared boolean before a bare subcommand is still a guess

- **GIVEN** no Parser declaration for `cargo`
- **WHEN** evaluating `cargo --release build`
- **THEN** `--release` SHALL consume `build` as its value — its arity is
  unknown and `build` is a plausible, non-flag value, so the value-shape rule
  consumes it (the same way `--output report.txt` consumes `report.txt`)
- **AND** the positional residual SHALL be empty, so a `(positional "build")`
  guard does **not** match
- **AND** an arity-guess Advisory naming `--release` and `build` SHALL be
  emitted, making the guess observable

> A boolean flag immediately before a bare subcommand cannot be distinguished
> by token shape from a value flag; the value-shape rule consumes the
> following token. To keep such a subcommand visible to a `(positional …)`
> guard, declare the flag (`(flag "release")`) so it is treated as value-less,
> or match the subcommand via `(flag …)` / `(anywhere …)`, which scan raw argv.

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

#### Scenario: A declared boolean flag is value-less

- **GIVEN** `(parser "cargo" (style gnu) (flag "release"))`
- **WHEN** evaluating `cargo --release build`
- **THEN** `--release` SHALL be treated as value-less (author-asserted arity)
- **AND** `build` SHALL remain in the positional residual, so `(positional
  "build")` matches
- **AND** no arity-guess Advisory SHALL be emitted (the arity was declared, not
  guessed)

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
- **WHEN** evaluating `tool --verbose --quiet`
- **THEN** `--verbose` SHALL be value-less (its successor `--quiet` is
  flag-shaped) and `--quiet` SHALL be value-less (it has no successor)
- **AND** no arity-guess Advisory SHALL be emitted for them

#### Scenario: Declared parameter does not emit an arity-guess Advisory

- **GIVEN** `(parser "tool" (style gnu) (parameter "output"))`
- **WHEN** evaluating `tool --output report.txt`
- **THEN** no arity-guess Advisory SHALL be emitted (the arity was declared, not
  guessed)

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

### Requirement: Quantifiers accept a sequence of sub-patterns

A quantifier head (`?`, `+`, `*`) SHALL accept one **or more** sub-patterns.
With a single sub-pattern the meaning is unchanged. With more than one
sub-pattern the sub-patterns form an **implicit sequence**: the quantified
unit is the whole sub-sequence, matched left to right against consecutive
positional args. A sub-pattern MAY itself be a quantifier form, so groups
nest.

`(? A B …)` SHALL match either zero args (the group is skipped) or the
full sub-sequence `A B …` in order. `(+ A B …)` and `(* A B …)` SHALL
repeat the whole sub-sequence (see the one-or-more and zero-or-more
requirements).

#### Scenario: Optional sequence group skipped

- **WHEN** matching the positional patterns `(? "run" (? "--")) *` against the args `state`
- **THEN** matching SHALL succeed with the group consuming zero args.

#### Scenario: Optional sequence group, partial inner

- **WHEN** matching the positional patterns `(? "run" (? "--")) *` against the args `run state`
- **THEN** matching SHALL succeed with the group consuming `run`.

#### Scenario: Optional sequence group, full inner

- **WHEN** matching the positional patterns `(? "run" (? "--")) *` against the args `run -- state`
- **THEN** matching SHALL succeed with the group consuming `run --`.

#### Scenario: Sequence group requires its leading element

- **WHEN** matching the positional patterns `(? "run" (? "--")) *` against the args `-- state`
- **THEN** the group SHALL NOT match `--` (its leading `run` is absent), and the group SHALL consume zero args.

### Requirement: Optional quantifier matches with or without arg

A Pattern wrapped in `(? PAT …)` (the optional quantifier) SHALL match even when the arg at that position is absent. When matched, the sub-sequence `PAT …` MUST match consecutive args in order. A single-sub-pattern `(? PAT)` is the special case of a one-element sequence.

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

A Pattern wrapped in `(+ PAT …)` (the one-or-more quantifier) SHALL require at least one full occurrence of the sub-sequence `PAT …` at the pattern's position, and SHALL match as many consecutive occurrences as possible, backtracking so that following patterns can match. With a single sub-pattern this reduces to the historical "one or more args each matching `PAT`" behaviour.

#### Scenario: One-or-more wildcard with one arg

- **WHEN** matching the positional pattern `(+ *)` against the args `file1`
- **THEN** matching SHALL succeed.

#### Scenario: One-or-more wildcard with multiple args

- **WHEN** matching the positional pattern `(+ *)` against the args `file1 file2 file3`
- **THEN** matching SHALL succeed.

#### Scenario: One-or-more with no args

- **WHEN** matching the positional patterns `"cmd" (+ *)` against the args `cmd`
- **THEN** matching SHALL NOT succeed.

#### Scenario: One-or-more sequence group repeats

- **WHEN** matching the positional pattern `(+ "--opt" *)` against the args `--opt a --opt b`
- **THEN** matching SHALL succeed, consuming two occurrences of the sub-sequence.

### Requirement: Zero-or-more quantifier matches any count

A Pattern wrapped in `(* PAT …)` (the zero-or-more quantifier) SHALL match zero or more consecutive occurrences of the sub-sequence `PAT …` from that position, backtracking so that following patterns can match. With a single sub-pattern this reduces to the historical "zero or more args each matching `PAT`" behaviour.

#### Scenario: Zero-or-more wildcard with no args

- **WHEN** matching the positional patterns `"cmd" (* *)` against the args `cmd`
- **THEN** matching SHALL succeed.

#### Scenario: Zero-or-more wildcard with multiple args

- **WHEN** matching the positional pattern `(* *)` against the args `a b c`
- **THEN** matching SHALL succeed.

#### Scenario: Zero-or-more sequence group repeats

- **WHEN** matching the positional pattern `(* "--opt" *)` against the args `--opt a --opt b`
- **THEN** matching SHALL succeed, consuming two occurrences of the sub-sequence.

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

### Requirement: `(every? #var PRED)` folds a predicate over a collection binding

The rule-body form `(every? #var PRED)` SHALL evaluate `PRED` against
every element of the collection bound to `#var` and SHALL match iff
every element matches. `#var` SHALL be a parser-bound name whose
declared shape is `Collection Token` (see `binding-shapes`). Using
`(every? …)` on any other shape SHALL be a config-load error.

`PRED` SHALL be a single-token Pattern expression: a literal string,
the wildcard `*`, a `(regex …)`, an `(or …)`/`(and …)`/`(not …)` of
such expressions, or a fact-binding `[:k *]`.

The fold SHALL be vacuously true on the empty collection (zero
elements). Fact-binding patterns inside `PRED` SHALL contribute their
captured values to facts as if the matching pattern had been written
without a quantifier — see "Fact-binding capture under quantifiers"
below.

`(every? …)` SHALL be evaluable wherever a Pattern is expected: inside
`(and …)`, `(or …)`, `(not …)`, `(when …)`, `(unless …)`, `(if …)`,
and as a `(cond …)` test arm.

#### Scenario: All positionals match — every? is true

- **GIVEN** `(parser "rm" (style gnu) (flags posix) (positional #paths (regex "^/tmp/") *))` and `(rule "rm" (when (and (flag ["r" "recursive"]) (every? #paths (regex "^/tmp/"))) (allow "tmp paths")))`
- **WHEN** evaluating `rm -rf /tmp/a /tmp/b`
- **THEN** `(every? #paths (regex "^/tmp/"))` SHALL match
- **AND** the rule SHALL return `:allow "tmp paths"`.

#### Scenario: One positional fails — every? is no-match

- **GIVEN** the configuration above
- **WHEN** evaluating `rm -rf /tmp/a /etc/passwd`
- **THEN** `(every? #paths (regex "^/tmp/"))` SHALL NOT match (because
  `/etc/passwd` does not match the regex)
- **AND** the rule SHALL return no decision from this branch.

#### Scenario: Empty collection — every? is vacuously true

- **GIVEN** `(parser "rm" (style gnu) (flags posix) (positional #paths * *))` and `(rule "rm" (when (every? #paths (regex "^/tmp/")) (allow "vacuous")))`
- **WHEN** evaluating `rm` (no positionals)
- **THEN** `#paths` SHALL bind to the empty collection
- **AND** `(every? #paths (regex "^/tmp/"))` SHALL match
- **AND** the rule SHALL return `:allow "vacuous"`.

#### Scenario: Wrong shape fails at load

- **GIVEN** `(parser "xargs" (style gnu) (flags posix) (parameter "n" #procs) (rest #cmd))` and `(rule "xargs" (when (every? #procs (regex "^[0-9]+$")) (allow)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a shape-mismatch diagnostic naming
  `#procs` as `Token` and `(every? …)` as requiring `Collection Token`.

### Requirement: `(some? #var PRED)` matches when any element satisfies the predicate

The rule-body form `(some? #var PRED)` SHALL evaluate `PRED` against
every element of the collection bound to `#var` and SHALL match iff at
least one element matches. The shape requirement, predicate
sublanguage, and composition contexts SHALL be the same as for
`(every? …)`.

The fold SHALL be false on the empty collection (zero elements).

#### Scenario: One positional matches — some? is true

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)) (rest #cmd))` and `(rule "ssh" (when (some? #opts (regex "^ProxyCommand=")) (ask "review ProxyCommand")))`
- **WHEN** evaluating `ssh -o BatchMode=yes -o ProxyCommand="nc host port" target`
- **THEN** `(some? #opts (regex "^ProxyCommand="))` SHALL match
- **AND** the rule SHALL return `:ask "review ProxyCommand"`.

#### Scenario: No positional matches — some? is no-match

- **GIVEN** the configuration above
- **WHEN** evaluating `ssh -o BatchMode=yes target`
- **THEN** `(some? #opts (regex "^ProxyCommand="))` SHALL NOT match.

#### Scenario: Empty collection — some? is false

- **GIVEN** the configuration above
- **WHEN** evaluating `ssh target` (no `-o` flags)
- **THEN** `#opts` SHALL bind to the empty collection
- **AND** `(some? #opts (regex "^ProxyCommand="))` SHALL NOT match.

#### Scenario: Wrong shape fails at load

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" (command #cmd)))` and `(rule "bash" (when (some? #cmd (regex "rm")) (deny)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a shape-mismatch diagnostic naming
  `#cmd` as `Command` and `(some? …)` as requiring `Collection Token`.

### Requirement: Fact-binding capture under quantifiers

Fact-binding patterns inside `(every? …)` and `(some? …)` SHALL
accumulate matched element values into facts in the enclosing rule's
fact environment.

When `PRED` inside `(every? …)` or `(some? …)` contains a fact-binding
`[:k *]`, every element that matches SHALL contribute its value to the
fact named `:k` in iteration order. The fact's accumulated values
SHALL be a set (consistent with existing fact-storage semantics) —
duplicates SHALL deduplicate.

For `(every? …)`, the fact SHALL accumulate exactly when the overall
fold matches (i.e. every element matches); when even one element
fails, no fact contribution SHALL be retained.

For `(some? …)`, the fact SHALL accumulate the values of every element
that matched (potentially more than one), regardless of whether other
elements failed.

#### Scenario: `(every? …)` with fact-binding accumulates all values

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))` and `(rule "ssh" (when (every? #opts [:ssh/opt *]) (allow)))`
- **WHEN** evaluating `ssh -o BatchMode=yes -o ConnectTimeout=10 host`
- **THEN** the rule's fact environment SHALL include `:ssh/opt`
  containing both `"BatchMode=yes"` and `"ConnectTimeout=10"`.

#### Scenario: `(some? …)` with fact-binding accumulates matching values only

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))` and `(rule "ssh" (when (some? #opts (and (regex "^ProxyCommand=") [:ssh/proxy *])) (ask "review proxy")))`
- **WHEN** evaluating `ssh -o BatchMode=yes -o ProxyCommand="nc h p" -o ProxyCommand="other" host`
- **THEN** the fact `:ssh/proxy` SHALL accumulate both ProxyCommand values
- **AND** SHALL NOT accumulate `BatchMode=yes`.
