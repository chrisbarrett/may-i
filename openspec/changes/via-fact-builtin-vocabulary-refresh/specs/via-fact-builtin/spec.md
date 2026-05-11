## MODIFIED Requirements

### Requirement: `(authorise …)` pushes wrapper command name onto :via set

When `(authorise #var)` (or any other `(authorise …)`-shaped recursion entry — `(parameter NAME (authorise))` single-token capture, `(tail (authorise))`) triggers recursive evaluation, the evaluator SHALL automatically push the current command name onto the `:via` fact set before evaluating the inner command. The push SHALL apply to every evaluation unit produced by the recursion (one push per `(authorise …)` call, not per inner unit).

#### Scenario: Single wrapper

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))` and `(rule "sudo" (authorise #cmd))` and `(rule "rm" (deny))`
- **WHEN** evaluating `sudo rm -rf /`
- **THEN** the inner evaluation of `rm -rf /` SHALL have `:via` = `{"sudo"}`.

#### Scenario: Nested wrappers accumulate

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))`, `(parser "ssh" (style gnu) (flags posix) (positional #host (regex "^[^-].*")) (rest #cmd))`, `(rule "sudo" (authorise #cmd))`, and `(rule "ssh" (authorise #cmd))`
- **WHEN** evaluating `sudo ssh prod-1 rm -rf /`
- **THEN** the inner evaluation of `rm` SHALL have `:via` = `{"sudo", "ssh"}`.

#### Scenario: Order does not matter for set membership

- **GIVEN** `:via` = `{"sudo", "ssh"}` from nested unwrapping
- **WHEN** evaluating `(fact? [:via "ssh"])`
- **THEN** it SHALL return Match regardless of unwrapping order.

### Requirement: :via is the only automatically pushed fact

Only the `:via` key SHALL be automatically populated by an `(authorise …)` recursion. All other facts (e.g., `:ssh/host`) require explicit declaration: a parser-side `#var` binding (`(positional #host …)`, `(parameter "k" #v)`, `(rest #cmd)`) combined with a rule-side `(with-facts [[:k #var]] …)` form, or — for set-membership tests only — a direct `(fact? …)` predicate.

#### Scenario: Parser bindings are not automatic facts

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (positional #host (regex "^[^-].*")) (rest #cmd))` and `(rule "ssh" (authorise #cmd))`
- **WHEN** evaluating `ssh prod-1 ls`
- **THEN** the inner evaluation SHALL have `:via` = `{"ssh"}`
- **AND** the inner evaluation SHALL NOT have a `:ssh/host` fact (no `(with-facts …)` lifted `#host` into facts).

#### Scenario: `(with-facts …)` lifts a binding alongside automatic via

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (positional #host (regex "^[^-].*")) (rest #cmd))` and `(rule "ssh" (with-facts [[:ssh/host #host]] (authorise #cmd)))`
- **WHEN** evaluating `ssh prod-1 ls`
- **THEN** the inner evaluation SHALL have `:via` = `{"ssh"}` and `:ssh/host` = `{"prod-1"}`.
