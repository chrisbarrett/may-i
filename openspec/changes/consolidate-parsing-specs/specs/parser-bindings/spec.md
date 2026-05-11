## ADDED Requirements

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

- `(authorise #var)` — join the captured tokens with single spaces and parse the result via the shell command parser as a full command line. Compound forms (`&&`, `||`, `;`, `|`, `if`/`for`/`case`, command substitutions) SHALL be decomposed and each unit evaluated separately, with the strictest decision returned. `:via PROG` SHALL accumulate into the facts seen by every inner unit.
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
