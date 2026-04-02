> [!IMPORTANT]
> The user-facing quick reference is [`REFERENCE.txt`](../../../REFERENCE.txt) in
> the repo root (embedded in the binary via `include_str!`). Keep it in sync with
> this spec when adding or changing syntax.

## ADDED Requirements

### Requirement: Configuration file is a sequence of top-level forms

A configuration file SHALL contain zero or more top-level forms. Each form is an
S-expression. Valid top-level forms are `rule`, `define`, `check`, and
`safe-env-vars`. Forms are evaluated in declaration order.

#### Scenario: Empty config is valid

- **GIVEN** an empty configuration file
- **WHEN** parsed
- **THEN** parsing SHALL succeed with zero rules and zero defines

#### Scenario: Multiple top-level forms

- **GIVEN** a config with a `define`, two `rule` forms, and a `check`
- **WHEN** parsed
- **THEN** all forms SHALL be collected in declaration order

#### Scenario: Unknown top-level form rejected

- **GIVEN** a config containing `(unknown-form)`
- **WHEN** parsed
- **THEN** the parser SHALL reject it with an error

### Requirement: Comments use semicolons

Lines beginning with `;` (after optional whitespace) SHALL be treated as
comments and ignored by the parser. Inline comments (`;` after a form on the
same line) SHALL also be supported.

#### Scenario: Line comment

- **GIVEN** a config containing `; this is a comment`
- **WHEN** parsed
- **THEN** the comment SHALL be ignored

#### Scenario: Inline comment

- **GIVEN** a config containing
  `(rule "git" :effect (effect :allow)) ; allow git`
- **WHEN** parsed
- **THEN** the rule SHALL parse and the comment SHALL be ignored

### Requirement: Strings are double-quoted

String literals SHALL be enclosed in double quotes. Standard escape sequences
(`\\`, `\"`, `\n`, `\r`, `\t`) SHALL be supported within strings.

#### Scenario: Simple string

- **GIVEN** the token `"hello"`
- **WHEN** parsed
- **THEN** it SHALL produce the string value `hello`

#### Scenario: Escaped quotes

- **GIVEN** the token `"say \"hi\""`
- **WHEN** parsed
- **THEN** it SHALL produce the string value `say "hi"`

### Requirement: Keywords start with a colon

Keywords are atoms that begin with `:`. They are used as fact keys (e.g.
`:via/ssh`, `:opencode/agent`) and as decision labels (`:allow`, `:ask`,
`:deny`). A keyword without a leading colon SHALL be rejected.

#### Scenario: Valid keyword

- **GIVEN** the atom `:ssh/host`
- **WHEN** parsed as a keyword
- **THEN** parsing SHALL succeed

#### Scenario: Invalid keyword

- **GIVEN** the atom `ssh/host`
- **WHEN** parsed as a keyword
- **THEN** parsing SHALL fail

---

### Requirement: Rules match commands and produce decisions

`(rule COMMAND EFFECT... [:effect DEFAULT-EFFECT] [CHECK...])` SHALL define an
authorization rule. The first argument is a command selector. Subsequent
arguments are body effects evaluated in order. The optional `:effect` keyword
introduces a default effect used when all body effects return Nil.

#### Scenario: Minimal rule

- **GIVEN** `(rule "cat" :effect (effect :allow))`
- **WHEN** evaluating command `"cat"`
- **THEN** it SHALL return Allow

#### Scenario: Rule with body effects and default

- **GIVEN**
  `(rule "rm" (when (anywhere "-rf") (effect :deny)) :effect (effect :allow))`
- **WHEN** evaluating `"rm" ["-rf", "/"]`
- **THEN** it SHALL return Deny

#### Scenario: Body effect returns Nil, falls through to default

- **GIVEN** the same rule
- **WHEN** evaluating `"rm" ["foo"]`
- **THEN** the `when` returns Nil and the rule SHALL return Allow from the
  default

### Requirement: Command selector restricts which commands a rule matches

The first argument to `rule` SHALL be a command selector. Valid selectors are
string literals, `(regex ...)`, and `(or ...)` combining other selectors. The
selector must match the command name for the rule's body to be evaluated.

#### Scenario: Literal command match

- **GIVEN** `(rule "git" :effect (effect :allow))`
- **WHEN** evaluating command `"git"`
- **THEN** the rule SHALL apply

#### Scenario: Literal command mismatch

- **GIVEN** the same rule
- **WHEN** evaluating command `"cargo"`
- **THEN** the rule SHALL not apply

#### Scenario: Regex command match

- **GIVEN** `(rule (regex "^git") :effect (effect :allow))`
- **WHEN** evaluating command `"git-lfs"`
- **THEN** the rule SHALL apply

#### Scenario: Or command match

- **GIVEN** `(rule (or "git" "gh") :effect (effect :allow))`
- **WHEN** evaluating command `"gh"`
- **THEN** the rule SHALL apply

### Requirement: Rules dispatch as an implicit or

Rules SHALL be tried in declaration order. The first rule to produce a non-Nil
result wins. If no rule matches, the global fallback is Ask.

#### Scenario: First matching rule wins

- **GIVEN** rules for `"git"` (Allow) and `"git"` (Deny) in that order
- **WHEN** evaluating command `"git"`
- **THEN** it SHALL return Allow

#### Scenario: Unmatched command returns Ask

- **GIVEN** rules only for `"git"` and `"cargo"`
- **WHEN** evaluating command `"curl"`
- **THEN** it SHALL return Ask

### Requirement: Inline checks validate rule behaviour

`(check ...)` forms inside a `rule` body define test assertions for that rule.
The syntax `:DECISION "command string"` asserts the expected outcome. Checks are
validated by `may-i check`.

#### Scenario: Inline check passes

- **GIVEN** `(rule "mv" :effect (effect :allow) (check :allow "mv foo bar"))`
- **WHEN** running `may-i check`
- **THEN** the check SHALL pass

#### Scenario: Inline check fails

- **GIVEN** a rule allowing `mv` but a check asserting `:deny "mv foo"`
- **WHEN** running `may-i check`
- **THEN** the check SHALL fail

---

### Requirement: Terminal effects produce decisions

`(effect :allow [REASON])`, `(effect :ask [REASON])`, and
`(effect :deny [REASON])` SHALL produce the corresponding terminal decision. The
optional string reason is informational.

#### Scenario: Allow without reason

- **WHEN** evaluating `(effect :allow)`
- **THEN** it SHALL return Allow with no reason

#### Scenario: Deny with reason

- **WHEN** evaluating `(effect :deny "too dangerous")`
- **THEN** it SHALL return Deny with reason `"too dangerous"`

### Requirement: And combinator short-circuits on Nil

`(and EFFECT...)` SHALL evaluate effects left-to-right. It returns the first Nil
encountered, or the last effect's result if all are non-Nil.

#### Scenario: All succeed

- **WHEN** evaluating `(and (effect :allow) (effect :ask))`
- **THEN** it SHALL return Ask

#### Scenario: Short-circuit on Nil

- **WHEN** evaluating `(and (positional "push") (effect :allow))` against args
  `["status"]`
- **THEN** it SHALL return Nil

### Requirement: Or combinator returns first non-Nil

`(or EFFECT...)` SHALL evaluate effects left-to-right. It returns the first
non-Nil result, or Nil if all return Nil.

#### Scenario: First succeeds

- **WHEN** evaluating `(or (effect :allow) (effect :ask))`
- **THEN** it SHALL return Allow

#### Scenario: Falls through

- **WHEN** evaluating `(or (positional "push") (effect :allow))` against args
  `["status"]`
- **THEN** it SHALL return Allow

### Requirement: Not combinator inverts Allow and Nil

`(not EFFECT)` SHALL return Allow if EFFECT returns Nil, Nil if EFFECT returns
Allow, and pass through Ask/Deny unchanged.

#### Scenario: Not of Nil

- **WHEN** evaluating `(not (positional "push"))` against args `["status"]`
- **THEN** it SHALL return Allow

#### Scenario: Not of Allow

- **WHEN** evaluating `(not (positional "push"))` against args `["push"]`
- **THEN** it SHALL return Nil

### Requirement: When evaluates effect if predicate matches

`(when PREDICATE EFFECT)` SHALL evaluate EFFECT if PREDICATE matches, otherwise
return Nil.

#### Scenario: Predicate matches

- **WHEN** evaluating `(when (fact? :via/ssh) (effect :deny))` with fact
  `:via/ssh` present
- **THEN** it SHALL return Deny

#### Scenario: Predicate does not match

- **WHEN** evaluating the same form without the fact
- **THEN** it SHALL return Nil

### Requirement: Unless evaluates effect if predicate does not match

`(unless PREDICATE EFFECT)` SHALL evaluate EFFECT if PREDICATE does not match,
otherwise return Nil.

#### Scenario: Predicate does not match

- **WHEN** evaluating `(unless (anywhere "--force") (effect :allow))` against
  args `["status"]`
- **THEN** it SHALL return Allow

#### Scenario: Predicate matches

- **WHEN** evaluating the same form against args `["--force"]`
- **THEN** it SHALL return Nil

### Requirement: If chooses branch based on predicate

`(if PREDICATE THEN-EFFECT ELSE-EFFECT)` SHALL evaluate THEN-EFFECT if PREDICATE
matches, otherwise ELSE-EFFECT.

#### Scenario: Predicate matches

- **WHEN** evaluating `(if (anywhere "--force") (effect :ask) (effect :allow))`
  against args `["--force"]`
- **THEN** it SHALL return Ask

#### Scenario: Predicate does not match

- **WHEN** evaluating the same form against args `["status"]`
- **THEN** it SHALL return Allow

### Requirement: Cond evaluates first matching branch

`(cond ((PREDICATE EFFECT)...) [(else EFFECT)])` SHALL evaluate the effect of
the first branch whose predicate matches. If no branch matches and an `else`
clause is present, it evaluates the else effect. If no branch matches and there
is no else, it returns Nil.

#### Scenario: First branch matches

- **WHEN** evaluating
  `(cond ((positional "push") (effect :ask)) ((positional "rm") (effect :deny)) (else (effect :allow)))`
  against args `["push"]`
- **THEN** it SHALL return Ask

#### Scenario: No branch matches, else used

- **WHEN** evaluating the same form against args `["status"]`
- **THEN** it SHALL return Allow

#### Scenario: No branch matches, no else

- **GIVEN** a cond with no else clause
- **WHEN** no branch predicate matches
- **THEN** it SHALL return Nil

---

### Requirement: Positional matches arguments by position, skipping flags

`(positional PATTERN...)` SHALL match command arguments by position, skipping
flags (tokens starting with `-`) and their values. Returns Allow on match, Nil
otherwise.

#### Scenario: Simple positional match

- **WHEN** evaluating `(positional "push")` against args `["push"]`
- **THEN** it SHALL return Allow

#### Scenario: Flags are skipped

- **WHEN** evaluating `(positional "push")` against args `["-v", "push"]`
- **THEN** it SHALL return Allow

#### Scenario: Positional mismatch

- **WHEN** evaluating `(positional "push")` against args `["status"]`
- **THEN** it SHALL return Nil

### Requirement: Exact matches arguments requiring exact count

`(exact PATTERN...)` SHALL match like `positional` but additionally requires
that the number of positional arguments equals the number of patterns. Extra
positional arguments cause the match to fail.

#### Scenario: Exact match

- **WHEN** evaluating `(exact "stash")` against args `["stash"]`
- **THEN** it SHALL return Allow

#### Scenario: Extra positional args fail

- **WHEN** evaluating `(exact "stash")` against args `["stash", "pop"]`
- **THEN** it SHALL return Nil

### Requirement: Anywhere matches token presence in argv

`(anywhere PATTERN...)` SHALL return Allow if any of the patterns match any
token in the argument list. Returns Nil if none match.

#### Scenario: Token found

- **WHEN** evaluating `(anywhere "-r" "--recursive")` against args
  `["-r", "/tmp"]`
- **THEN** it SHALL return Allow

#### Scenario: Token not found

- **WHEN** evaluating the same form against args `["/tmp"]`
- **THEN** it SHALL return Nil

### Requirement: Forbidden is the negation of anywhere

`(forbidden PATTERN...)` SHALL return Allow if none of the patterns match any
token in the argument list. Returns Nil if any match. This is equivalent to
`(not (anywhere PATTERN...))`.

#### Scenario: Forbidden token absent

- **WHEN** evaluating `(forbidden "--force")` against args `["push"]`
- **THEN** it SHALL return Allow

#### Scenario: Forbidden token present

- **WHEN** evaluating `(forbidden "--force")` against args `["--force", "push"]`
- **THEN** it SHALL return Nil

### Requirement: Positional patterns support quantifiers

Individual positional patterns can be wrapped in quantifier forms to control how
many arguments they consume.

- Bare pattern: exactly one argument (`(positional "cmd")`)
- `(? PATTERN)`: zero or one argument
- `(+ PATTERN)`: one or more arguments
- `(* PATTERN)`: zero or more arguments

#### Scenario: Optional quantifier matches zero

- **WHEN** evaluating `(positional (? "verbose") "push")` against args
  `["push"]`
- **THEN** it SHALL return Allow

#### Scenario: Optional quantifier matches one

- **WHEN** evaluating the same form against args `["verbose", "push"]`
- **THEN** it SHALL return Allow

#### Scenario: One-or-more matches multiple

- **WHEN** evaluating `(positional (+ *))` against args `["a", "b", "c"]`
- **THEN** it SHALL return Allow

#### Scenario: One-or-more fails on zero

- **WHEN** evaluating `(positional (+ *))` against args `[]`
- **THEN** it SHALL return Nil

### Requirement: Positional continuation passes remaining args to an effect

`(positional PATTERN... . EFFECT)` SHALL match the patterns and then evaluate
EFFECT with the remaining unconsumed positional arguments. This is used for
recursive evaluation with `(may-i *)`.

#### Scenario: Continuation receives remaining args

- **GIVEN** `(positional "exec" . (may-i *))`
- **WHEN** evaluating against args `["exec", "rm", "-rf", "/"]`
- **THEN** `(may-i *)` SHALL receive `["rm", "-rf", "/"]` as a new command

---

### Requirement: Expression patterns match individual argument tokens

Within positional, exact, and anywhere forms, individual patterns are
expressions (`Expr`) that match a single string.

- `"literal"`: exact string match
- `*`: wildcard, matches any string
- `(regex "PATTERN")`: regex match (anchored by the regex itself, not
  implicitly)
- `(or EXPR...)`: matches if any sub-expression matches
- `(and EXPR...)`: matches if all sub-expressions match
- `(not EXPR)`: inverts the match

#### Scenario: Literal match

- **WHEN** matching `"push"` against `"push"`
- **THEN** it SHALL match

#### Scenario: Wildcard match

- **WHEN** matching `*` against any string
- **THEN** it SHALL match

#### Scenario: Regex match

- **WHEN** matching `(regex "^prod-")` against `"prod-server-01"`
- **THEN** it SHALL match

#### Scenario: Or match

- **WHEN** matching `(or "create" "delete")` against `"delete"`
- **THEN** it SHALL match

#### Scenario: And with Not

- **WHEN** matching `(and (regex "^/") (not "/"))` against `"/tmp"`
- **THEN** it SHALL match

### Requirement: Bind expressions capture matched values as facts

`[:KEY EXPR]` (vector syntax) within a positional pattern SHALL match using EXPR
and, on success, bind the matched value to fact key KEY.

#### Scenario: Bind captures host

- **GIVEN** `(positional [:ssh/host *])`
- **WHEN** evaluating against args `["prod-1"]`
- **THEN** it SHALL match and set fact `:ssh/host` = `"prod-1"`

### Requirement: Expression-level cond branches on token value

Within a positional pattern, `(cond ((EXPR EFFECT)...) [(else EFFECT)])` SHALL
test each branch's expression against the current argument token and evaluate
the effect of the first matching branch.

#### Scenario: Branch matches

- **GIVEN**
  `(positional (cond (("push" (effect :ask)) ("status" (effect :allow)))))`
- **WHEN** evaluating against args `["push"]`
- **THEN** it SHALL return Ask

---

### Requirement: Predicates test conditions for branching

Predicates are used in `when`, `unless`, `if`, and `cond` to decide which branch
to take. They evaluate to Match or NoMatch.

- `(fact? QUERY)`: tests a fact in the runtime context
- `(positional ...)`, `(exact ...)`, `(anywhere ...)`, `(forbidden ...)`:
  argument pattern as predicate (Match if pattern returns Allow)
- `NAME`: reference to a named predicate
- `(and PRED...)`: all must match
- `(or PRED...)`: any must match
- `(not PRED)`: inverts

#### Scenario: Fact presence predicate

- **GIVEN** fact `:via/ssh` is present
- **WHEN** evaluating predicate `(fact? :via/ssh)`
- **THEN** it SHALL return Match

#### Scenario: Arg pattern as predicate

- **WHEN** evaluating predicate `(anywhere "--force")` against args
  `["--force", "push"]`
- **THEN** it SHALL return Match

#### Scenario: Named predicate reference

- **GIVEN** `(define is-ssh (fact? :via/ssh))`
- **WHEN** evaluating predicate `is-ssh` with fact `:via/ssh` present
- **THEN** it SHALL return Match

### Requirement: Fact queries test runtime context

`(fact? QUERY)` SHALL test a fact in the runtime context. Query forms:

- `(fact? :key)`: presence check — matches if key exists
- `(fact? [:key])`: same as `(fact? :key)`
- `(fact? [:key "value"])`: exact value — matches if `"value"` is in the set at
  `:key`
- `(fact? [:key *])`: any value — matches if key exists with a non-empty set
- `(fact? [:key (regex "...")])`: regex — matches if any value in the set
  matches
- `(fact? [:key (or P...)])`, `(fact? [:key (and P...)])`,
  `(fact? [:key (not P)])`: combinators on value patterns

#### Scenario: Presence check

- **GIVEN** fact store contains `:client/claude-code` (empty set)
- **WHEN** evaluating `(fact? :client/claude-code)`
- **THEN** it SHALL return Match

#### Scenario: Value check

- **GIVEN** fact store contains `:opencode/agent` = `{"plan"}`
- **WHEN** evaluating `(fact? [:opencode/agent "plan"])`
- **THEN** it SHALL return Match

#### Scenario: Regex value check

- **GIVEN** fact store contains `:ssh/host` = `{"prod-server-01"}`
- **WHEN** evaluating `(fact? [:ssh/host (regex "^prod-")])`
- **THEN** it SHALL return Match

#### Scenario: Missing key

- **GIVEN** fact store does not contain `:via/ssh`
- **WHEN** evaluating `(fact? :via/ssh)`
- **THEN** it SHALL return NoMatch

---

### Requirement: Define creates named predicates

`(define NAME PREDICATE)` SHALL bind a predicate to a name. The name is a bare
symbol (not a keyword). Named predicates are resolved by inlining their
definitions before evaluation.

#### Scenario: Define and reference

- **GIVEN** `(define is-ssh (fact? :via/ssh))`
- **AND** a rule using `(when is-ssh (effect :deny))`
- **WHEN** evaluating with fact `:via/ssh` present
- **THEN** `is-ssh` SHALL be resolved to `(fact? :via/ssh)` and the when SHALL
  return Deny

#### Scenario: Undefined reference is an error

- **GIVEN** no defines
- **AND** a rule using `(when nonexistent (effect :allow))`
- **WHEN** resolving predicates
- **THEN** it SHALL produce a resolution error

### Requirement: Defines can compose other defines

Named predicates MAY reference other named predicates. References are resolved
transitively.

#### Scenario: Composed define

- **GIVEN** `(define is-ssh (fact? :via/ssh))` and
  `(define is-prod (and is-ssh (fact? [:ssh/host (regex "^prod-")])))`
- **WHEN** resolving `is-prod`
- **THEN** `is-ssh` within `is-prod` SHALL be replaced with its definition

---

### Requirement: Recursive evaluation unwraps wrapper commands

`(may-i *)` within a positional continuation SHALL extract the remaining
arguments as a new command and recursively evaluate it against the full rule
set.

#### Scenario: SSH unwrap

- **GIVEN**
  `(rule "ssh" (positional [:ssh/host *] . (may-i *)) :effect (effect :deny))`
  and `(rule "echo" :effect (effect :allow))`
- **WHEN** evaluating `ssh prod-1 echo hello`
- **THEN** it SHALL recursively evaluate `echo hello`, binding `:ssh/host` =
  `"prod-1"`, and return Allow

#### Scenario: Sudo unwrap

- **GIVEN** `(rule "sudo" (positional . (may-i *)) :effect (effect :deny))`
- **WHEN** evaluating `sudo rm -rf /`
- **THEN** it SHALL recursively evaluate `rm -rf /`

### Requirement: Recursive evaluation inherits and extends facts

When `(may-i *)` triggers recursive evaluation, the inner evaluation SHALL
inherit all facts from the outer context plus any facts bound during the current
rule's pattern matching.

#### Scenario: Bound facts carry into recursion

- **GIVEN** an SSH rule that binds `:ssh/host` and an inner rule that checks
  `(fact? :via/ssh)`
- **WHEN** evaluating `ssh prod-1 journalctl`
- **THEN** the inner evaluation SHALL have both `:ssh/host` = `"prod-1"` and
  `:via/ssh` present

### Requirement: Combined flags are expanded before evaluation

Before evaluation, combined short flags like `-rf` SHALL be expanded to
individual flags `-r`, `-f`. This ensures patterns like `(anywhere "-r")` match
regardless of how the flag was passed.

#### Scenario: Combined flag expansion

- **WHEN** evaluating `rm -rf /` against `(anywhere "-r")`
- **THEN** it SHALL match because `-rf` is expanded to `-r`, `-f`

---

### Requirement: Top-level checks validate the config

`(check ...)` at the top level (outside any rule) SHALL define assertions
against the full rule set. Each entry is `:DECISION "command"`. Checks support
`(with-facts [...] ...)` to simulate runtime context.

#### Scenario: Simple top-level check

- **GIVEN** `(check :allow "ls")`
- **WHEN** running `may-i check`
- **THEN** the check SHALL pass if `ls` evaluates to Allow

#### Scenario: Check with facts

- **GIVEN** `(check (with-facts [[:opencode/agent "build"]] :allow "rm foo"))`
- **WHEN** running `may-i check`
- **THEN** evaluation SHALL include the fact `:opencode/agent` = `"build"`

#### Scenario: Nested with-facts inherit outer facts

- **GIVEN**
  `(check (with-facts [[:client/opencode]] (with-facts [[:opencode/agent "plan"]] :ask "git push")))`
- **WHEN** running the check
- **THEN** evaluation SHALL include both `:client/opencode` and
  `:opencode/agent` = `"plan"`

### Requirement: Safe-env-vars declares safe environment variables

`(safe-env-vars STRING...)` SHALL declare environment variable names that are
safe to resolve during static analysis of shell commands. This allows the parser
to expand `$HOME` etc. before evaluation.

#### Scenario: Declared env var

- **GIVEN** `(safe-env-vars "HOME" "USER")`
- **WHEN** parsing a command containing `$HOME`
- **THEN** the parser MAY resolve it to the actual value

---

### Requirement: Decisions combine by most-restrictive-wins

When multiple effects or rules contribute decisions, the ordering is
`Deny > Ask > Allow`. The most restrictive decision takes precedence.

#### Scenario: Deny overrides Allow

- **GIVEN** an evaluation producing both Allow and Deny
- **THEN** Deny SHALL be the final result

### Requirement: Nil never surfaces to callers

The public evaluation API SHALL always return Allow, Ask, or Deny. Nil is an
internal mechanism for "no match — continue evaluating" and SHALL NOT appear in
results.

#### Scenario: All rules return Nil

- **WHEN** no rule matches a command
- **THEN** the result SHALL be Ask (the global fallback), not Nil
