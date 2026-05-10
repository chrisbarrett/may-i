## ADDED Requirements

### Requirement: `(many-till PAT)` declares multi-token parameter capture

The parser-side parameter declaration `(parameter NAME (many-till PAT))` SHALL declare that `NAME` consumes tokens after its occurrence until a token matches `PAT`. The matched terminator token SHALL be consumed and discarded; it SHALL NOT appear in subsequent matchers' view of argv.

`PAT` SHALL be any single-token expression (`"literal"`, `(regex …)`, `(or …)`, `*`, etc.).

The captured value SHALL be the multi-token sequence from immediately after `NAME` up to but not including the terminator token.

If end-of-argv is reached before any token matches `PAT`, tokenisation SHALL emit an error-severity diagnostic. By the existing engine invariant, the rule's decision SHALL floor to `:ask` (`:deny` stays `:deny`).

#### Scenario: `(many-till …)` captures multi-token sequence

- **GIVEN** `(parser "find" (style single-dash-long) (parameter "exec" (many-till (or ";" "+"))))`
- **WHEN** tokenising `find . -exec rm -rf / \;`
- **THEN** the captured value for parameter `exec` SHALL be the token sequence `[rm, -rf, /]`.
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

### Requirement: Rules access `(many-till …)`-captured value as a joined string

Rule-side `(parameter NAME (authorise))` against a parameter declared with `(many-till …)` SHALL:

- Join the captured tokens with single spaces.
- Parse the joined string via the shell command parser into an inner command and inner argv.
- Re-evaluate the inner against the active rule set, with `:via PROG` accumulated into facts.

Rule-side `(parameter NAME PATTERN)` against a `(many-till …)` parameter SHALL match the joined string against `PATTERN` (regex, literal, etc.) as a single token.

#### Scenario: Rule authorises `(many-till …)` capture

- **GIVEN** `(parser "find" (style single-dash-long) (parameter "exec" (many-till (or ";" "+"))))` and `(rule "find" (parameter "exec" (authorise)))` and `(rule "rm" (and (flag "r") (deny "no rm -r")))`
- **WHEN** evaluating `find . -exec rm -rf / \;`
- **THEN** the rule for `find` SHALL recurse with inner command `rm` and argv `[-rf, /]`
- **AND** the rule for `rm` SHALL match and the result SHALL be `:deny`.

### Requirement: Multi-occurrence parameters fire rule body per occurrence

When the argv contains more than one occurrence of a `(many-till …)`-declared parameter, the rule body matching that parameter SHALL be evaluated once per occurrence, in source order. The strictest decision across occurrences SHALL win, consistent with the existing decision combiner (`:allow < :ask < :deny`).

#### Scenario: Multiple `-exec` clauses each authorised

- **GIVEN** the configuration above and `(rule "rm" (allow))` and `(rule "dd" (deny "no dd"))`
- **WHEN** evaluating `find . -exec rm /tmp/a \; -exec dd if=/dev/zero \;`
- **THEN** the first occurrence SHALL authorise `rm /tmp/a` and return `:allow`
- **AND** the second occurrence SHALL authorise `dd if=/dev/zero` and return `:deny`
- **AND** the rule's overall decision SHALL be `:deny` (strictest).

#### Scenario: Single-occurrence parameter unchanged

- **GIVEN** `(parser "bash" (style gnu) (parameter "c" (authorise)))`
- **WHEN** evaluating `bash -c "echo hi"`
- **THEN** the rule body SHALL fire once for the single `-c` occurrence (existing semantics).
