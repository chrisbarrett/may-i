## MODIFIED Requirements

### Requirement: Argument match annotations show evidence
When an argument pattern is evaluated, the right-column annotation SHALL show
the tested value, the argument set, and the match verdict. For a multi-element
positional pattern, each element SHALL be annotated against the argument the
matcher tested it with — the value at the match cursor when the element was
evaluated — not against the first positional argument. The cursor advances for
each consumed element and stays put for a skipped optional; an element the match
never reaches (after a required element fails or the arguments run out) SHALL be
left unannotated.

#### Scenario: Anywhere match shows set membership
- **WHEN** `(anywhere "-r")` matches against args `["-r", "-f", "/"]`
- **THEN** the annotation reads `"-r" ∈ {"-r", "-f", "/"} → yes`

#### Scenario: Positional match shows equality test
- **WHEN** `(positional "push")` is tested against positional arg `"pull"`
- **THEN** the annotation reads `"pull" = "push" → no`

#### Scenario: Each consumed element is annotated against its own argument
- **WHEN** `(positional "source-file" (or "a" "b"))` is tested against positional args `["source-file", "b"]`
- **THEN** the `source-file` element annotation reads `"source-file" = "source-file" → yes`
- **AND** the `or` branch annotations read `"b" = "a" → no` and `"b" = "b" → yes` — the second element tests the second positional argument, not the first

#### Scenario: A skipped optional keeps the cursor for the next element
- **WHEN** `(positional (? "affected") (? (or "watch" "run")) (? "--"))` is tested against positional args `["run", "--", "test"]`
- **THEN** `(? "affected")` reads `"run" = "affected" → no` and is skipped
- **AND** `(? (or "watch" "run"))` is tested against the same `"run"` and reads `"run" = "run" → yes`
- **AND** `(? "--")` is tested against `"--"` and reads `"--" = "--" → yes`

#### Scenario: Elements after a failed required element are unannotated
- **WHEN** `(positional "checkout" "--")` is tested against positional args `["status"]`
- **THEN** the `checkout` element reads `"status" = "checkout" → no`
- **AND** the `"--"` element is left unannotated — the match never reached it

#### Scenario: A failed regex element still shows its comparison
- **WHEN** `(positional (regex "^foo"))` is tested against positional args `["bar"]`
- **THEN** the element renders `(regex "^foo")` on the left and `"bar" ~ (regex "^foo") → no` on the right — a failed (or skipped-optional) element is annotated against the value it was tested with, not left blank because it consumed nothing

#### Scenario: A backtracked quantifier annotates the following element against its real argument
- **WHEN** `(positional (* "a") "a")` is tested against positional args `["a"]`
- **THEN** the matcher gives the `"a"` back from `(* "a")` so the required `"a"` matches arg 0
- **AND** the required `"a"` element is annotated `"a" = "a" → yes` — against the argument it matched on the winning path, not left unannotated as a forward greedy walk would
