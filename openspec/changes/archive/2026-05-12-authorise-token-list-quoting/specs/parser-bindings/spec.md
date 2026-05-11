## MODIFIED Requirements

### Requirement: `(authorise #var)` recurses on a bound name

The rule-body form `(authorise #var)` SHALL recursively authorise the value bound to `#var` as a command line. The semantics SHALL be:

- If `#var` is unbound or bound to an empty value (empty string, empty token list), `(authorise #var)` SHALL be a no-match (the surrounding combinator continues to other branches).
- If `#var` is bound to a **single string** (e.g. `(parameter "c" #cmd)` capturing one shell argument), the string SHALL be parsed by the shell command parser as a full command line — including compound forms (`&&`, `||`, `;`, `|`, `if`/`for`/`case`, command substitutions) — then decomposed into evaluation units and aggregated strictest-wins.
- If `#var` is bound to a **token list** (e.g. `(rest #cmd)`, `(positional #var *)`, `(positional #var +)`), the recursion SHALL preserve each token's content as one argument: argv[0] SHALL be the inner command name and argv[1..] SHALL be the inner argv. The tokens SHALL NOT be joined with single spaces and re-parsed, because that join discards the boundary information the outer shell already established and exposes shell metacharacters inside a token (e.g. `&&`, `;`, `|`, parens, quotes) as if they were structure at the wrapper's frame.
- For a token-list binding, if `tokens` is empty, `(authorise #var)` SHALL be a no-match. If `tokens[0]` contains shell metacharacters or is empty, the recursion SHALL be `:ask` with a reason naming the dynamic-or-malformed inner command name.
- For a token-list binding with a well-formed `tokens[0]`, the recursion SHALL evaluate the inner command directly without further parsing of `tokens[1..]`; each `tokens[i]` SHALL arrive at the inner parser as a single argument. The inner program's own parser then handles any further structure (e.g. `bash -c <string>` captures `<string>` via its own `(parameter "c" #cmd)`).
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

#### Scenario: `(rest #cmd)` token list with compound through `sh -c`

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))`, `(rule "sudo" (authorise #cmd))`, `(rule "sh" (authorise #cmd))`, and `(rule "rm" (deny))`
- **WHEN** evaluating `sudo sh -c "if true; then rm /; fi"`
- **THEN** sudo's `#cmd` SHALL bind to the token list `[sh, -c, "if true; then rm /; fi"]`
- **AND** the recursion SHALL reach the `rm` unit inside the `if`/`fi` body via sh's parameter capture
- **AND** the rule SHALL return `:deny`.

#### Scenario: Token-list `tokens[0]` containing shell metacharacters asks

- **GIVEN** any parser whose `(rest #cmd)` or positional binding could capture an unresolved or malformed first token (e.g. a binding fed by an earlier capture that did not narrow `argv[0]`)
- **WHEN** `(authorise #cmd)` recurses with `tokens[0] = "$X"`
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
