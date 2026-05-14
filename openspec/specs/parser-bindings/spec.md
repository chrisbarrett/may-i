---
audience: user
bucket: parsing
---
# parser-bindings Specification

## Purpose

The full per-program parser-declaration surface: `(style …)`, the required `(flags MODE)` declaration (`posix` | `permute` | `(until …)`) scoping outer flag scanning, parameters (single-occurrence and `(many-till PAT)` multi-token capture), `(positional …)` slots with quantifiers, the `(rest …)` unconsumed-tail binding, the `#var` sigil for parser-bound names referenced from rule bodies (`(authorise …)`, `(bound? …)`, `(matches? …)`, `(with-facts …)`), binding-scope rules, shadowing, and the set of parsers shipped in the prelude for common wrapper tools (sudo, xargs, env, timeout, ssh, mise, nix, find, bash, …). Replaces the prior `(tail …)` form's invisible side-channel with explicit, named bindings.

Also covers the **form-list calling convention** for DSL bodies — `(parser …)`, `(define-arg-style …)`, `(check …)` — and the **canonical surface syntax for decision verbs** (`(allow REASON?)`, `(ask REASON?)`, `(deny REASON?)`) and recursion (`(authorise)`). Legacy PLIST-style bodies and the `(effect …)` form are retired and rejected at config-load time.
## Requirements
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
- If `#var` is bound to a **single string** (e.g. `(parameter "c" #cmd)` capturing one shell argument), the string SHALL be parsed by the shell command parser as a full command line — including compound forms (`&&`, `||`, `;`, `|`, `if`/`for`/`case`, command substitutions) — then decomposed into evaluation units and aggregated strictest-wins.
- If `#var` is bound to a **token list** (e.g. `(rest #cmd)`, `(positional #var *)`, `(positional #var +)`), the recursion SHALL preserve each token's content as one argument: argv[0] SHALL be the inner command name and argv[1..] SHALL be the inner argv. The tokens SHALL NOT be joined with single spaces and re-parsed, because that join discards the boundary information the outer shell already established and exposes shell metacharacters inside a token (e.g. `&&`, `;`, `|`, parens, quotes) as if they were structure at the wrapper's frame.
- For a token-list binding with exactly one element, the single element SHALL be treated as a single string and parsed as a full command line (there is only one outer-shell boundary, so no information is lost by re-parsing).
- For a token-list binding with two or more elements, if `tokens[0]` contains shell metacharacters or is empty, the recursion SHALL return `:ask` with a reason naming the dynamic-or-malformed inner command name.
- For a token-list binding with a well-formed `tokens[0]` (and at least two elements), the recursion SHALL evaluate the inner command directly without further parsing of `tokens[1..]`; each `tokens[i]` SHALL arrive at the inner parser as a single argument. The inner program's own parser then handles any further structure (e.g. `bash -c <string>` captures `<string>` via its own `(parameter "c" #cmd)`).
- `:via PROG` (the current command name) SHALL accumulate into the inner facts for every unit produced by the recursion.
- Each `(authorise …)` recursion SHALL count as one step toward the recursion-depth limit, regardless of how many evaluation units the inner command produces.
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

#### Scenario: `(authorise #cmd)` recurses into a compound inner via string capture

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" #cmd))`, `(rule "bash" (authorise #cmd))`, `(rule "echo" (allow))`, and `(rule "rm" (deny "no rm"))`
- **WHEN** evaluating `bash -c "echo hi && rm -rf /"`
- **THEN** `#cmd` SHALL be bound to the single string `"echo hi && rm -rf /"`
- **AND** the recursion SHALL evaluate `echo hi` and `rm -rf /` as separate units
- **AND** each unit's inner facts SHALL include `:via "bash"`
- **AND** the rule SHALL return `:deny "no rm"` (strictest wins across units).

#### Scenario: `(rest #cmd)` token list preserves quoted argument shape

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))`, `(rule "sudo" (authorise #cmd))`, `(rule "bash" (authorise #cmd))`, `(rule "echo" (allow))`, and `(rule "rm" (deny "no rm"))`
- **WHEN** evaluating `sudo bash -c "echo a && rm -rf /tmp/x"`
- **THEN** sudo's `#cmd` SHALL bind to the token list `[bash, -c, "echo a && rm -rf /tmp/x"]`
- **AND** sudo's `(authorise #cmd)` SHALL recurse with inner command `bash` and inner argv `[-c, "echo a && rm -rf /tmp/x"]` (the third token preserved as a single string)
- **AND** bash's `(parameter "c" #cmd)` SHALL bind to the single string `"echo a && rm -rf /tmp/x"`
- **AND** bash's `(authorise #cmd)` SHALL decompose the string and reach the `rm` unit
- **AND** the rule SHALL return `:deny "no rm"`.

#### Scenario: `(authorise #cmd)` recurses into an `if`/`fi` block via token list

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))`, `(rule "sudo" (authorise #cmd))`, `(rule "sh" (authorise #cmd))`, and `(rule "rm" (deny))`
- **WHEN** evaluating `sudo sh -c "if true; then rm /; fi"`
- **THEN** sudo's `#cmd` SHALL bind to the token list `[sh, -c, "if true; then rm /; fi"]`
- **AND** the recursion SHALL reach the `rm` unit inside the `if`/`fi` body via sh's parameter capture
- **AND** the rule SHALL return `:deny`.

#### Scenario: Token-list `tokens[0]` containing shell metacharacters asks

- **GIVEN** any parser whose `(rest #cmd)` or positional binding could capture an unresolved or malformed first token
- **WHEN** `(authorise #cmd)` recurses with `tokens = ["$X", "arg"]`
- **THEN** the decision SHALL be `:ask`
- **AND** the reason SHALL mention that the inner command name is dynamic or malformed.

#### Scenario: Dynamic inner command name asks (string binding)

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" #cmd))` and `(rule "bash" (authorise #cmd))`
- **WHEN** evaluating `bash -c "$X arg"`
- **THEN** the decision SHALL be `:ask`
- **AND** the reason SHALL mention dynamic command name resolution.

#### Scenario: Recursion depth counts per `(authorise …)`, not per inner unit

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" #cmd))` and `(rule "bash" (authorise #cmd))`
- **WHEN** the bound value is a pipeline of many simple commands
- **THEN** the recursion SHALL consume exactly one depth step, not one per unit.

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

### Requirement: `(many-till PAT)` declares multi-token parameter capture

The parser-side parameter declaration `(parameter NAME (many-till PAT) [#var])` SHALL declare that `NAME` consumes tokens after its occurrence until a token matches `PAT`. The matched terminator token SHALL be consumed and discarded; it SHALL NOT appear in subsequent matchers' view of argv.

`PAT` SHALL be any single-token expression (`"literal"`, `(regex …)`, `(or …)`, `*`, etc.).

The captured value SHALL be the multi-token sequence from immediately after `NAME` up to but not including the terminator token. When the optional `#var` slot is present, `#var` SHALL bind to this token list for rule-body reference via `(authorise #var)`, `(bound? #var)`, `(matches? #var PAT)`, or `(with-facts [[:k #var]] …)`.

If end-of-argv is reached before any token matches `PAT`, tokenisation SHALL emit an error-severity diagnostic. By the existing engine invariant, the rule's decision SHALL floor to `:ask` (`:deny` stays `:deny`).

#### Scenario: `(many-till …)` captures multi-token sequence

- **GIVEN** `(parser "find" (style single-dash-long) (flags permute) (parameter "exec" (many-till (or ";" "+")) #args))`
- **WHEN** tokenising `find . -exec rm -rf / \;`
- **THEN** `#args` SHALL bind to the token list `[rm, -rf, /]`
- **AND** the terminator `;` SHALL be consumed.

#### Scenario: `(many-till …)` reaching end-of-argv emits diagnostic

- **GIVEN** the configuration above
- **WHEN** tokenising `find . -exec rm -rf /` (no terminator)
- **THEN** an error-severity diagnostic SHALL be emitted
- **AND** the rule's decision SHALL floor to `:ask`.

#### Scenario: `(many-till …)` outside parser body fails at load

- **GIVEN** `(rule "find" (parameter "exec" (many-till ";")))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with an error indicating `(many-till …)` is parser-side only.

#### Scenario: `(many-till …)` without binding still consumes tokens

- **GIVEN** `(parser "find" (style single-dash-long) (flags permute) (parameter "exec" (many-till (or ";" "+"))))`
- **WHEN** tokenising `find . -exec rm -rf / \;`
- **THEN** the tokens `[rm, -rf, /]` SHALL be consumed from the argv view
- **AND** no `#var` SHALL be bound for these tokens.

### Requirement: Rules access `(many-till …)`-captured value via the bound `#var`

Rule-side access to a `(many-till …)` capture SHALL go through the parser-declared `#var` binding using one of:

- `(authorise #var)` — join the captured tokens with single spaces and parse the result via the shell command parser as a full command line. Compound forms (`&&`, `||`, `;`, `|`, `if`/`for`/`case`, command substitutions) SHALL be decomposed and each unit evaluated separately, with the strictest decision returned. `:via PROG` SHALL accumulate into the facts seen by every inner unit. _This join-and-parse behaviour is intentional and differs from `(rest …)` / `(positional … *|+)` recursion: a `(many-till …)` capture is a fragment the user **authored** inside their own argument (e.g. `find -exec rm /tmp/x ;` — the tokens `rm /tmp/x` were written by the user with spaces as separators), not an argument the outer shell delivered as a single quoted string. There is no outer-shell quote envelope to preserve; the captured tokens are semantically a command-line fragment, not a structured argument list._
- `(matches? #var PAT)` — match the joined string against `PAT` as a single token.
- `(with-facts [[:k #var]] …)` — promote the joined token list (as a single string) to a fact for the inner recurse.

The rule-body `(parameter NAME (authorise))` form is removed; users SHALL write the parser-side binding `(parameter NAME (many-till PAT) #var)` and the rule-side `(authorise #var)` instead.

#### Scenario: Rule authorises `(many-till …)` capture via binding

- **GIVEN** `(parser "find" (style single-dash-long) (flags permute) (parameter "exec" (many-till (or ";" "+")) #args))` and `(rule "find" (authorise #args))` and `(rule "rm" (and (flag "r") (deny "no rm -r")))`
- **WHEN** evaluating `find . -exec rm -rf / \;`
- **THEN** the rule for `find` SHALL recurse with inner command `rm` and argv `[-rf, /]`
- **AND** the rule for `rm` SHALL match and the result SHALL be `:deny`.

#### Scenario: Rule matches against `(many-till …)` capture

- **GIVEN** `(parser "find" (style single-dash-long) (flags permute) (parameter "exec" (many-till (or ";" "+")) #args))` and `(rule "find" (when (matches? #args (regex "rm")) (ask "review exec")))`
- **WHEN** evaluating `find . -exec rm /tmp/x \;`
- **THEN** `(matches? #args (regex "rm"))` SHALL return true
- **AND** the rule SHALL return `:ask`.

#### Scenario: `(authorise …)` on a compound `(many-till …)` capture

- **GIVEN** `(parser "find" (style single-dash-long) (flags permute) (parameter "exec" (many-till (or ";" "+")) #args))`, `(rule "find" (authorise #args))`, `(rule "echo" (allow))`, and `(rule "rm" (deny "no rm"))`
- **WHEN** evaluating `find . -exec sh -c "echo a && rm /tmp/x" \;`
- **THEN** the joined capture `sh -c "echo a && rm /tmp/x"` SHALL be parsed as a full command line
- **AND** the inner `rm` unit SHALL be reached via nested `(authorise …)` recursion through `sh -c`
- **AND** the overall decision SHALL be `:deny`.

### Requirement: Multi-occurrence parameters fire rule body per occurrence

When the argv contains more than one occurrence of a `(many-till …)`-declared parameter, the `#var` binding SHALL accumulate as a list of token-lists (one per occurrence). Rule-body forms operating on `#var` SHALL be evaluated once per occurrence, in source order. The strictest decision across occurrences SHALL win, consistent with the existing decision combiner (`:allow < :ask < :deny`).

#### Scenario: Multiple `-exec` clauses each authorised

- **GIVEN** `(parser "find" (style single-dash-long) (flags permute) (parameter "exec" (many-till (or ";" "+")) #args))` and `(rule "find" (authorise #args))` and `(rule "rm" (allow))` and `(rule "dd" (deny "no dd"))`
- **WHEN** evaluating `find . -exec rm /tmp/a \; -exec dd if=/dev/zero \;`
- **THEN** the first occurrence SHALL authorise `rm /tmp/a` and return `:allow`
- **AND** the second occurrence SHALL authorise `dd if=/dev/zero` and return `:deny`
- **AND** the rule's overall decision SHALL be `:deny` (strictest).

#### Scenario: Single-occurrence parameter unchanged

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" #cmd))` and `(rule "bash" (authorise #cmd))`
- **WHEN** evaluating `bash -c "echo hi"`
- **THEN** the rule body SHALL fire once for the single `-c` occurrence (existing semantics).

### Requirement: Prelude ships parsers for common wrapper tools

The prelude SHALL define parsers for the following wrapper tools before any user config is loaded. Each declaration SHALL include a `(style …)`, the required `(flags MODE)`, the relevant `(flag …)` and `(parameter …)` declarations, the positional slots needed to carve the recurse target accurately, and a `(rest #cmd)` binding for the recursive payload (where applicable).

The prelude SHALL declare:

- `sudo`     — `(style gnu) (flags posix) (rest #cmd)`
- `xargs`    — `(style gnu) (flags posix) (parameter ["n" "I" "L" "P" "d"]) (flag ["0" "r"]) (rest #cmd)`
- `env`      — `(style gnu) (flags posix) (rest #cmd)`
- `timeout`  — `(style gnu) (flags posix) (parameter ["k" "kill-after"]) (parameter ["s" "signal"]) (positional #duration (regex "^[0-9]+(\\.[0-9]+)?[smhd]?$")) (rest #cmd)`
- `nice`     — `(style gnu) (flags posix) (parameter ["n"]) (rest #cmd)`
- `time`     — `(style gnu) (flags posix) (rest #cmd)`
- `watch`    — `(style gnu) (flags posix) (parameter ["n" "interval"]) (rest #cmd)`
- `su`       — `(style gnu) (flags posix) (rest #cmd)`
- `ionice`   — `(style gnu) (flags posix) (rest #cmd)`
- `chrt`     — `(style gnu) (flags posix) (rest #cmd)`
- `nohup`    — `(style gnu) (flags posix) (rest #cmd)`
- `strace`   — `(style gnu) (flags posix) (parameter ["e" "o" "p"]) (rest #cmd)`
- `mise`     — `(style gnu) (flags (until "--")) (rest #cmd)`
- `direnv`   — `(style gnu) (flags posix) (positional #verb (or "exec" "edit" "export" "hook" "prune" "reload" "status" "stdlib" "version" "log" "allow" "deny" "block")) (rest #cmd)`
- `ssh`      — `(style gnu) (flags posix) (positional #host (regex "^[^-].*")) (rest #cmd)`
- `bash`     — `(style gnu) (flags posix) (parameter "c" #cmd)`
- `nix-shell` — `(style gnu) (flags posix) (parameter "run" #cmd)`
- `nix`      — `(style gnu) (flags (until "--command" "-c")) (rest #cmd)`

The `timeout` parser SHALL bind the DURATION argument to `#duration` so wrapper rules can carve the duration from the recursive payload — closing the silent bypass where `timeout 30 cmd` recursed on `30 cmd` rather than `cmd`.

The `ssh` parser SHALL bind the HOST argument to `#host` so wrapper rules can promote the host to a fact via `(with-facts [[:ssh/host #host]] …)`.

The `direnv` parser SHALL bind the verb to `#verb` so wrapper rules can dispatch on the verb explicitly.

User parsers MAY shadow any prelude parser.

#### Scenario: Prelude sudo parser closes silent bypass

- **GIVEN** prelude parsers loaded and user config `(rule "sudo" (authorise #cmd))` and `(rule "rm" (and (flag "r") (deny "no rm -r")))`
- **WHEN** evaluating `sudo rm -rf /tmp/x`
- **THEN** the inner evaluation SHALL see argv `[-rf, /tmp/x]` for `rm`
- **AND** the rule SHALL return `:deny`.

#### Scenario: Prelude xargs parser handles flagged invocation

- **GIVEN** prelude parsers and `(rule "xargs" (authorise #cmd))` and `(rule "rm" (allow))`
- **WHEN** evaluating `xargs -n 1 rm -rf`
- **THEN** the parameter `n` SHALL be consumed (value `1` discarded)
- **AND** `#cmd` SHALL bind `[rm, -rf]`
- **AND** the inner evaluation SHALL recurse with command `rm` and argv `[-rf]`.

#### Scenario: Prelude timeout parser carves DURATION

- **GIVEN** prelude parsers and `(rule "timeout" (authorise #cmd))` and `(rule "rm" (and (flag "r") (deny "no rm -r")))`
- **WHEN** evaluating `timeout 30 rm -rf /tmp/x`
- **THEN** `#duration` SHALL bind `"30"`
- **AND** `#cmd` SHALL bind `[rm, -rf, /tmp/x]`
- **AND** the inner evaluation SHALL recurse with command `rm` and argv `[-rf, /tmp/x]`
- **AND** the rule SHALL return `:deny`.

#### Scenario: Prelude mise parser uses `--` boundary

- **GIVEN** prelude parsers and `(rule "mise" (authorise #cmd))` and `(rule "rm" (deny "no rm"))`
- **WHEN** evaluating `mise exec -- rm /tmp/x`
- **THEN** `#cmd` SHALL bind `[rm, /tmp/x]`
- **AND** the rule SHALL return `:deny`.

#### Scenario: Prelude bash parser binds -c value

- **GIVEN** prelude parsers and `(rule "bash" (authorise #cmd))` and `(rule "rm" (deny "no rm"))`
- **WHEN** evaluating `bash -c "rm /tmp/x"`
- **THEN** `#cmd` SHALL bind `"rm /tmp/x"`
- **AND** the inner evaluation SHALL recurse with command `rm` and argv `[/tmp/x]`
- **AND** the rule SHALL return `:deny`.

#### Scenario: Chained wrappers compose correctly

- **GIVEN** prelude parsers and `(rule "mise" (authorise #cmd))` and `(rule "timeout" (authorise #cmd))` and `(rule "rm" (and (flag "r") (deny "no rm -r")))`
- **WHEN** evaluating `mise exec -- timeout 30 rm -rf /tmp/x`
- **THEN** mise's `#cmd` SHALL bind `[timeout, 30, rm, -rf, /tmp/x]`
- **AND** the recurse into timeout SHALL bind timeout's `#duration` to `"30"` and `#cmd` to `[rm, -rf, /tmp/x]`
- **AND** the recurse into rm SHALL match the deny rule
- **AND** the overall decision SHALL be `:deny`.

#### Scenario: User parser shadows prelude

- **GIVEN** prelude `sudo` parser and user `(parser "sudo" (style gnu) (flags permute) (flag "E"))` (no rest declared)
- **WHEN** the config is loaded
- **THEN** the user parser SHALL win
- **AND** the resolved parser for `sudo` SHALL NOT bind `#cmd` (no rest declared)
- **AND** rules referencing `#cmd` SHALL fail at load.

### Requirement: Prelude ships `find` parser with `(many-till …)` and named bindings

The prelude SHALL declare a parser for `find`:

```
(parser "find"
  (style single-dash-long)
  (flags permute)
  (parameter "exec"    (many-till (or ";" "+")) #exec)
  (parameter "execdir" (many-till (or ";" "+")) #execdir)
  (parameter "ok"      (many-till (or ";" "+")) #ok)
  (parameter ["name" "iname" "type" "mtime" "size" "regex" "path"]))
```

The `#exec`, `#execdir`, and `#ok` bindings SHALL be accessible from rule bodies via `(authorise …)`, `(matches? …)`, `(bound? …)`, and `(with-facts …)`.

#### Scenario: Prelude find parser captures `-exec`

- **GIVEN** prelude parsers and `(rule "find" (authorise #exec))` and `(rule "rm" (and (flag "r") (deny "no rm -r")))`
- **WHEN** evaluating `find . -exec rm -rf / \;`
- **THEN** `#exec` SHALL bind `[rm, -rf, /]`
- **AND** the rule SHALL return `:deny` after recursion into `rm`.

#### Scenario: Prelude find parser recognises `+` terminator

- **GIVEN** the configuration above
- **WHEN** evaluating `find . -name '*.bak' -exec rm {} +`
- **THEN** `#exec` SHALL bind `[rm, {}]`
- **AND** the recursion SHALL run with command `rm` and argv `[{}]`.

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

