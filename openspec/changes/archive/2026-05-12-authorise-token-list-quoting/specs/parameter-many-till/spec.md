## MODIFIED Requirements

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
