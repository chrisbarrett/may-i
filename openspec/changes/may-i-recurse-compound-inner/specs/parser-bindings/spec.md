## MODIFIED Requirements

### Requirement: `(authorise #var)` recurses on a bound name

The rule-body form `(authorise #var)` SHALL recursively authorise the value bound to `#var` as a command line. The semantics SHALL be:

- If `#var` is unbound or bound to an empty value (empty string, empty token list), `(authorise #var)` SHALL be a no-match (the surrounding combinator continues to other branches).
- If `#var` is bound to a single string, the string SHALL be parsed by the shell command parser as a full command line — including compound forms (`&&`, `||`, `;`, `|`, `if`/`for`/`case`, command substitutions).
- If `#var` is bound to a token list, the tokens SHALL be joined by single spaces and parsed as above.
- The parsed command SHALL be decomposed into evaluation units, each unit evaluated against the active rule set, and the strictest decision (`Deny > Ask > Allow`) returned. This matches the top-level evaluator's compound-aggregation semantics.
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

#### Scenario: `(authorise #cmd)` recurses into a compound inner

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" #cmd))`, `(rule "bash" (authorise #cmd))`, `(rule "echo" (allow))`, and `(rule "rm" (deny "no rm"))`
- **WHEN** evaluating `bash -c "echo hi && rm -rf /"`
- **THEN** the recursion SHALL evaluate `echo hi` and `rm -rf /` as separate units
- **AND** each unit's inner facts SHALL include `:via "bash"`
- **AND** the rule SHALL return `:deny "no rm"` (strictest wins across units).

#### Scenario: `(authorise #cmd)` recurses into an `if`/`fi` block

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))`, `(rule "sudo" (authorise #cmd))`, and `(rule "rm" (deny))`
- **WHEN** evaluating `sudo sh -c "if true; then rm /; fi"`
- **THEN** the recursion SHALL reach the `rm` unit inside the `if`/`fi` body
- **AND** the rule SHALL return `:deny`.

#### Scenario: Dynamic inner command name asks

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
