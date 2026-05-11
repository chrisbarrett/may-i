## MODIFIED Requirements

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

- `(authorise #var)` — join the captured tokens with single spaces, parse via the shell command parser, re-evaluate against the active rule set with `:via PROG` accumulated into facts.
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
