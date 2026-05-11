## ADDED Requirements

### Requirement: `#var` sigil denotes a parser-bound name

The s-expression reader SHALL recognise atoms of the form `#NAME` (where `NAME` matches the existing atom-name grammar) as a distinct atom kind: a parser-bound name. `#NAME` SHALL be lexically and structurally distinct from literal strings (`"…"`), keyword facts (`:k`), and free atoms.

Parser-bound names SHALL be used in two positions only:

- As a binding declaration in parser-body forms (`(rest #var)`, `(positional #var …)`, `(parameter NAME #var)`, `(parameter NAME (many-till PAT) #var)`).
- As a binding reference in rule-body forms (`(authorise #var)`, `(bound? #var)`, `(matches? #var PAT)`, `(with-facts [[:k #var]] …)`).

A `#NAME` atom appearing elsewhere SHALL be a config-load error naming the offending position.

#### Scenario: Reader accepts `#NAME` atoms

- **GIVEN** the input `(rest #cmd)`
- **WHEN** the s-expression reader parses the form
- **THEN** the second element SHALL be a binding-name atom with name `cmd`.

#### Scenario: `#NAME` outside permitted positions fails at load

- **GIVEN** `(rule "x" (flag #cmd))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error indicating `#cmd` is not permitted in flag matchers.

#### Scenario: Reference to undeclared `#var` fails at load

- **GIVEN** `(parser "x" (style gnu) (flags posix))` and `(rule "x" (authorise #cmd))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error indicating `#cmd` is not bound by the parser.

### Requirement: `(flags MODE)` declares flag-scanning mode in parser body

The parser body SHALL include exactly one `(flags MODE)` declaration. `MODE` SHALL be one of:

- `posix` — outer flag/parameter scanning SHALL stop at the first non-flag token. Tokens after that point SHALL be positionals (or, after positionals are consumed, the bound `(rest …)` value).
- `permute` — outer flag/parameter scanning SHALL proceed through the full argv. Tokens matching declared flag or parameter names SHALL be consumed wherever they occur. Remaining tokens SHALL form the positional residual in source order.
- `(until STR…)` — outer flag/parameter scanning SHALL proceed up to (and not including) the first occurrence of any literal token in `STR…`. The matched boundary token SHALL be consumed and discarded. Tokens after the boundary SHALL form the bound `(rest …)` value.

A parser body missing `(flags …)` SHALL be a config-load error. A parser body declaring `(flags …)` more than once SHALL be a config-load error.

#### Scenario: `(flags posix)` stops at first positional

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))`
- **WHEN** tokenising `sudo -E rm -rf /tmp/x`
- **THEN** outer SHALL be `[-E]` consumed as a flag, and `#cmd` SHALL bind `[rm, -rf, /tmp/x]`.

#### Scenario: `(flags permute)` peels declared flags from anywhere

- **GIVEN** `(parser "git" (style gnu) (flags permute) (parameter "C"))`
- **WHEN** tokenising `git status -C /repo`
- **THEN** the parameter `C` SHALL be consumed with value `/repo`, and the positional residual SHALL be `[status]`.

#### Scenario: `(flags (until "--"))` stops at boundary token

- **GIVEN** `(parser "mise" (style gnu) (flags (until "--")) (rest #cmd))`
- **WHEN** tokenising `mise exec foo -- rm -rf /tmp/x`
- **THEN** outer SHALL be `[exec, foo]` available as positionals, and `#cmd` SHALL bind `[rm, -rf, /tmp/x]`.

#### Scenario: `(flags (until STR…))` accepts a token alias-set

- **GIVEN** `(parser "nix" (style gnu) (flags (until "--command" "-c")) (rest #cmd))`
- **WHEN** tokenising `nix shell pkg -c rm /tmp/x`
- **THEN** outer SHALL be `[shell, pkg]` available as positionals, and `#cmd` SHALL bind `[rm, /tmp/x]`.

#### Scenario: Missing `(flags …)` fails at load

- **GIVEN** `(parser "x" (style gnu))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error requiring `(flags …)`.

#### Scenario: Duplicate `(flags …)` fails at load

- **GIVEN** `(parser "x" (style gnu) (flags posix) (flags permute))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error noting `(flags …)` is declared more than once.

### Requirement: `(rest #var)` declares the unconsumed-tail binding

The parser body MAY include at most one `(rest #var)` declaration. When present, it SHALL bind `#var` to the unconsumed-tail slice of argv — the tokens after all outer flag/parameter scanning and all declared `(positional …)` consumption have completed.

Under `(flags posix)`, the rest SHALL begin after any declared `(positional …)` slots are filled.
Under `(flags permute)`, the rest SHALL be the positional residual after all positional declarations consume their share (typically empty for permute parsers, which usually omit `(rest …)`).
Under `(flags (until STR…))`, the rest SHALL begin at the token immediately after the matched boundary.

The rest value SHALL be a token list. When the tail is empty (no tokens after consumption), `#var` SHALL be bound to the empty list — `(bound? #var)` SHALL still return true, but `(authorise #var)` SHALL be a no-match.

Declaring `(rest …)` more than once SHALL be a config-load error.

#### Scenario: `(rest #cmd)` binds tail under posix mode

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))`
- **WHEN** tokenising `sudo rm -rf /tmp/x`
- **THEN** `#cmd` SHALL bind to the token list `[rm, -rf, /tmp/x]`.

#### Scenario: `(rest #cmd)` binds empty list when no tail present

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))`
- **WHEN** tokenising `sudo`
- **THEN** `#cmd` SHALL bind to the empty token list
- **AND** `(authorise #cmd)` in a rule body SHALL be a no-match.

#### Scenario: Duplicate `(rest …)` fails at load

- **GIVEN** `(parser "x" (style gnu) (flags posix) (rest #a) (rest #b))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error noting `(rest …)` is declared more than once.

### Requirement: `(positional [#var] PAT [QUANT])` declares positional slots in parser body

The parser body MAY include zero or more `(positional …)` declarations. Each declaration SHALL match against the positional stream (tokens not consumed by flags/parameters under the active mode) in source order. Each declaration SHALL accept:

- An optional `#var` binding name as the first argument after `positional`.
- A required match expression `PAT` (any `Expr` shape: literal, regex, wildcard `*`, `(or …)`, `(and …)`, `(not …)`).
- An optional quantifier as the trailing argument: `one` (default), `?`, `*`, or `+`.

When `#var` is present:

- `one` and `?` quantifiers SHALL bind `#var` to a single string (the matched token), or leave `#var` unbound for `?` when no match occurred.
- `*` and `+` quantifiers SHALL bind `#var` to a token list.

Positional declarations SHALL match in source order. Backtracking semantics SHALL be the same as for rule-body `(positional …)` matchers (`match_positional_recursive` shape).

If a `(positional …)` declaration fails to match the required quantity, parser evaluation SHALL emit a tokenisation diagnostic and the rule's decision SHALL floor to `:ask` per the existing invariant.

#### Scenario: Required positional with binding

- **GIVEN** `(parser "timeout" (style gnu) (flags posix) (positional #duration (regex "^[0-9]+[smhd]?$")) (rest #cmd))`
- **WHEN** tokenising `timeout 30s rm -rf /tmp/x`
- **THEN** `#duration` SHALL bind to the string `"30s"`
- **AND** `#cmd` SHALL bind to the token list `[rm, -rf, /tmp/x]`.

#### Scenario: Optional positional with `?` quantifier

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (positional #user ? (regex "^[^@]+@")) (positional #host *) (rest #cmd))`
- **WHEN** tokenising `ssh host rm -rf /tmp/x`
- **THEN** `#user` SHALL be unbound
- **AND** `#host` SHALL bind to `"host"`.

#### Scenario: Positional without `#var` matches but does not bind

- **GIVEN** `(parser "direnv" (style gnu) (flags posix) (positional (or "exec" "edit" "export")) (rest #cmd))`
- **WHEN** tokenising `direnv exec true`
- **THEN** the positional SHALL match `exec`
- **AND** `#cmd` SHALL bind to `[true]`.

#### Scenario: Failed required positional surfaces as diagnostic

- **GIVEN** `(parser "timeout" (style gnu) (flags posix) (positional #d (regex "^[0-9]+$")) (rest #cmd))`
- **WHEN** tokenising `timeout abc rm -rf /tmp/x`
- **THEN** an error-severity tokenisation diagnostic SHALL be emitted
- **AND** the decision SHALL floor to `:ask`.

### Requirement: `(parameter NAME #var)` binds the captured parameter value

The parser-body `(parameter NAME)` declaration SHALL accept an optional trailing `#var` slot. When present, the captured value of the parameter SHALL be bound to `#var` for rule-body reference.

For single-occurrence parameters (default), `#var` SHALL bind to the captured value as a string.

For parameters declared with `(many-till PAT)`, the binding form SHALL be `(parameter NAME (many-till PAT) #var)`; `#var` SHALL bind to the captured token list.

When the parameter is absent from argv, `#var` SHALL be unbound (`(bound? #var)` returns false).

When the parameter appears multiple times in argv and is not declared `(many-till …)`, `#var` SHALL bind to the value of the last occurrence (matching existing single-occurrence semantics).

#### Scenario: Single-value parameter binding

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" #cmd))`
- **WHEN** tokenising `bash -c "echo hi"`
- **THEN** `#cmd` SHALL bind to the string `"echo hi"`.

#### Scenario: `(many-till …)` parameter with binding

- **GIVEN** `(parser "find" (style single-dash-long) (flags permute) (parameter "exec" (many-till (or ";" "+")) #args))`
- **WHEN** tokenising `find . -exec rm -rf / \;`
- **THEN** `#args` SHALL bind to the token list `[rm, -rf, /]`.

#### Scenario: Parameter absent leaves binding unbound

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" #cmd))`
- **WHEN** tokenising `bash script.sh`
- **THEN** `#cmd` SHALL be unbound
- **AND** `(bound? #cmd)` SHALL return false.

#### Scenario: Parameter without `#var` matches but does not bind

- **GIVEN** `(parser "xargs" (style gnu) (flags posix) (parameter "n") (rest #cmd))`
- **WHEN** tokenising `xargs -n 1 rm -rf`
- **THEN** the parameter `n` SHALL be consumed as a tokenisation effect (value `1` discarded for binding purposes)
- **AND** `#cmd` SHALL bind to `[rm, -rf]`.

### Requirement: `(authorise #var)` recurses on a bound name

The rule-body form `(authorise #var)` SHALL recursively authorise the value bound to `#var` as a command line. The semantics SHALL be:

- If `#var` is unbound or bound to an empty value (empty string, empty token list), `(authorise #var)` SHALL be a no-match (the surrounding combinator continues to other branches).
- If `#var` is bound to a single string, the string SHALL be parsed by the shell command parser into an inner command and inner argv.
- If `#var` is bound to a token list, the tokens SHALL be joined by single spaces and parsed as above.
- The inner command SHALL be re-evaluated against the active rule set.
- `:via PROG` (the current command name) SHALL accumulate into the inner facts.
- The result SHALL be the recursed decision.

`(authorise …)` with any argument other than a `#var` reference SHALL be a config-load error. `(authorise)` with no argument SHALL be a config-load error.

#### Scenario: `(authorise #cmd)` recurses on bound rest

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))`, `(rule "sudo" (authorise #cmd))`, and `(rule "rm" (and (flag "r") (deny "no rm -r")))`
- **WHEN** evaluating `sudo rm -rf /tmp/x`
- **THEN** the inner evaluation SHALL see command `rm` with argv `[-rf, /tmp/x]`
- **AND** the rule SHALL return `:deny`.

#### Scenario: `(authorise #cmd)` records `:via`

- **GIVEN** the configuration above
- **WHEN** evaluating `sudo rm -r /tmp/x`
- **THEN** the inner evaluation's facts SHALL include `:via "sudo"`.

#### Scenario: `(authorise #var)` is no-match for unbound name

- **GIVEN** `(parser "nix-shell" (style gnu) (flags posix) (parameter "run" #cmd))` and `(rule "nix-shell" (authorise #cmd))`
- **WHEN** evaluating `nix-shell shell.nix`
- **THEN** `#cmd` SHALL be unbound
- **AND** `(authorise #cmd)` SHALL be a no-match
- **AND** evaluation SHALL continue to subsequent rules.

#### Scenario: `(authorise)` with no argument fails at load

- **GIVEN** `(rule "sudo" (authorise))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error requiring a `#var` argument.

### Requirement: `(bound? #var)` predicate tests binding presence

The rule-body predicate `(bound? #var)` SHALL evaluate to true iff `#var` is bound to a non-empty value in the current binding environment. Empty strings, empty token lists, and unbound names SHALL all yield false.

`(bound? …)` with any argument other than a `#var` reference SHALL be a config-load error.

#### Scenario: `(bound? #cmd)` true when parameter present

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" #cmd))` and `(rule "bash" (when (bound? #cmd) (authorise #cmd)))`
- **WHEN** evaluating `bash -c "echo hi"`
- **THEN** `(bound? #cmd)` SHALL return true
- **AND** the rule SHALL recurse on `echo hi`.

#### Scenario: `(bound? #cmd)` false when parameter absent

- **GIVEN** the configuration above
- **WHEN** evaluating `bash script.sh`
- **THEN** `(bound? #cmd)` SHALL return false
- **AND** the rule body SHALL not fire `(authorise #cmd)`.

### Requirement: `(matches? #var PAT)` matches a bound value against a pattern

The rule-body form `(matches? #var PAT)` SHALL evaluate `PAT` against the value bound to `#var`. `PAT` SHALL be any single-token expression (literal, regex, wildcard, `(or …)`, `(and …)`, `(not …)`, `[:k *]` fact-binding).

For single-string bindings, `PAT` SHALL be applied directly to the value.

For token-list bindings, `PAT` SHALL be applied to the space-joined value as a single string.

When `#var` is unbound, `(matches? #var PAT)` SHALL return false (no-match), regardless of `PAT`.

#### Scenario: `(matches? #duration …)` applies regex

- **GIVEN** `(parser "timeout" (style gnu) (flags posix) (positional #duration *) (rest #cmd))` and `(rule "timeout" (when (matches? #duration (regex "^[0-9]+$")) (authorise #cmd)))`
- **WHEN** evaluating `timeout 30 rm /tmp/x`
- **THEN** `(matches? #duration (regex "^[0-9]+$"))` SHALL return true
- **AND** the rule SHALL recurse on `rm /tmp/x`.

#### Scenario: `(matches? …)` on unbound is false

- **GIVEN** the configuration above
- **WHEN** evaluating `timeout` (argv empty after command)
- **THEN** `#duration` SHALL be unbound
- **AND** `(matches? #duration (regex "^[0-9]+$"))` SHALL return false.

### Requirement: `(with-facts [[:k #var]] BODY)` promotes binding to a fact

The rule-body form `(with-facts BINDINGS BODY)` SHALL accept a vector of `[:k #var]` pairs and evaluate `BODY` with each `:k` fact set to the value of the bound `#var`. The fact lives in inner-recurse facts when `BODY` contains `(authorise …)`.

If `#var` is unbound, the corresponding `:k` SHALL not be added to the fact set (the fact stays at its parent-scope value, or absent).

The existing rule-body `(with-facts …)` form continues to accept literal `[:k VALUE]` pairs alongside `[:k #var]` pairs.

#### Scenario: `(with-facts)` promotes parser binding to fact

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (positional #host *) (rest #cmd))` and `(rule "ssh" (with-facts [[:ssh/host #host]] (authorise #cmd)))` and `(rule "rm" (when (fact? [:ssh/host *]) (ask "rm on remote host")))`
- **WHEN** evaluating `ssh prod.example.com rm /tmp/x`
- **THEN** the inner evaluation's facts SHALL include `:ssh/host "prod.example.com"`
- **AND** the inner rule for `rm` SHALL match the `(fact? …)` check.

#### Scenario: Unbound `#var` skips fact promotion

- **GIVEN** the configuration above
- **WHEN** evaluating `ssh` (argv empty)
- **THEN** `#host` SHALL be unbound
- **AND** the inner evaluation SHALL not gain a `:ssh/host` fact.

### Requirement: Bindings live within parser evaluation and inner recurse

A parser-bound name SHALL be visible in:

- The rule body matched against the current command (read-only access via `(authorise #var)`, `(bound? #var)`, `(matches? #var …)`, `(with-facts [[:k #var]] …)`).
- The inner recurse triggered by `(authorise #var)` — but only if explicitly promoted to a fact via `(with-facts …)`. Parser-bound names SHALL NOT automatically propagate to inner recurses.

Parser-bound names SHALL NOT escape their parser's evaluation scope. A rule body for command A SHALL NOT reference bindings declared by the parser for command B.

#### Scenario: Bindings do not auto-propagate to inner recurse

- **GIVEN** `(parser "timeout" (style gnu) (flags posix) (positional #duration *) (rest #cmd))` and `(rule "timeout" (authorise #cmd))` and `(rule "rm" (when (bound? #duration) (ask "should not match")))`
- **WHEN** evaluating `timeout 30 rm /tmp/x`
- **THEN** the inner rule for `rm` SHALL NOT have `#duration` in scope
- **AND** `(bound? #duration)` in the inner rule SHALL fail at load (binding not declared by `rm`'s parser).

#### Scenario: Promoted fact is visible in inner recurse

- **GIVEN** `(parser "timeout" (style gnu) (flags posix) (positional #duration *) (rest #cmd))` and `(rule "timeout" (with-facts [[:timeout/duration #duration]] (authorise #cmd)))`
- **WHEN** evaluating `timeout 30 rm /tmp/x`
- **THEN** the inner evaluation's facts SHALL include `:timeout/duration "30"`.
