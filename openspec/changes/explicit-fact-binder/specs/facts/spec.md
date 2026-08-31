## ADDED Requirements

### Requirement: Facts are written only by declared writers

A Fact SHALL enter an evaluation only through one of:

- the `--fact` CLI surface,
- the automatic `:via` push performed by `(authorise …)`,
- a rule-body `(let-facts …)` form,
- a Check-block `(with-facts …)` form.

Matching a Pattern SHALL NOT write a Fact. No test SHALL have the side effect of
adding, removing or altering a Fact.

Every write SHALL bind the key for the extent of the writing form's body,
replacing any value the key held in an enclosing scope. `:via` accumulates
because each `(authorise …)` binds it to its previous value together with the
Carrier's name, not because Fact writes merge in general.

#### Scenario: A matching Pattern writes no Fact

- **GIVEN** `(rule "ssh" (when (anywhere "media-server") (authorise #cmd)))` and `(rule "sudo" (if (fact? [:ssh/host *]) (deny "leaked") (allow "clean")))`
- **WHEN** evaluating `ssh media-server sudo -n true`
- **THEN** the evaluation of `sudo` SHALL have no `:ssh/host` Fact
- **AND** the rule for `sudo` SHALL reach its `(allow …)`.

#### Scenario: `:via` accumulates across nested Carriers

- **GIVEN** `(rule "sudo" (authorise #cmd))` and `(rule "ssh" (authorise #cmd))`
- **WHEN** evaluating `sudo ssh prod-1 rm -rf /`
- **THEN** the inner evaluation of `rm` SHALL have `:via` = `{"sudo", "ssh"}`.

#### Scenario: A bound Fact replaces an enclosing value

- **GIVEN** `(rule "ssh" (let-facts [[:ssh/host #host]] (authorise #cmd)))`
- **WHEN** evaluating `ssh jump-host ssh media-server ls`
- **THEN** the evaluation of `ls` SHALL have `:ssh/host` = `{"media-server"}`.

### Requirement: A Fact key queried but never written raises an Advisory

When a configuration loads, a `(fact? …)` query naming a key that no writer in
that configuration can produce SHALL raise an Advisory. The writable set SHALL
comprise `:via`, every key bound by a `(let-facts …)` form, and every key set by
a Check-block `(with-facts …)` form.

The Advisory SHALL name the queried key and its source location. Where a
writable key differs from the queried key only in whether the trailing segment is
a namespace or a value, the Advisory SHALL name that key as a suggestion.

Because the `--fact` CLI surface admits arbitrary keys at runtime, this SHALL be
an Advisory and SHALL NOT prevent the configuration from loading.

#### Scenario: Namespaced key that nothing writes

- **GIVEN** a configuration containing `(rule "touch" (when (fact? :via/sudo) (deny "no sudo")))`
- **WHEN** the configuration loads
- **THEN** an Advisory SHALL report that `:via/sudo` is queried but never written
- **AND** SHALL suggest `[:via "sudo"]`
- **AND** the configuration SHALL load.

#### Scenario: Key written by `(let-facts …)` raises nothing

- **GIVEN** a configuration containing `(rule "ssh" (let-facts [[:ssh/host #host]] (authorise #cmd)))` and `(rule "sudo" (when (fact? [:ssh/host *]) (ask "remote sudo")))`
- **WHEN** the configuration loads
- **THEN** no unwritten-key Advisory SHALL be raised.

### Requirement: :via is the only automatically bound Fact

Only the `:via` key SHALL be automatically populated by an `(authorise …)` recursion. All other Facts (e.g., `:ssh/host`) require explicit declaration: a parser-side `#var` Binding (`(positional #host …)`, `(parameter "k" #v)`, `(rest #cmd)`) combined with a rule-side `(let-facts [[:k #var]] …)` form, or — for set-membership tests only — a direct `(fact? …)` query.

#### Scenario: Parser bindings are not automatic facts

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (positional #host (regex "^[^-].*")) (rest #cmd))` and `(rule "ssh" (authorise #cmd))`
- **WHEN** evaluating `ssh prod-1 ls`
- **THEN** the inner evaluation SHALL have `:via` = `{"ssh"}`
- **AND** the inner evaluation SHALL NOT have a `:ssh/host` fact (no `(let-facts …)` bound `#host` into facts).

#### Scenario: `(let-facts …)` binds a Binding alongside automatic via

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (positional #host (regex "^[^-].*")) (rest #cmd))` and `(rule "ssh" (let-facts [[:ssh/host #host]] (authorise #cmd)))`
- **WHEN** evaluating `ssh prod-1 ls`
- **THEN** the inner evaluation SHALL have `:via` = `{"ssh"}` and `:ssh/host` = `{"prod-1"}`.

## REMOVED Requirements

### Requirement: :via is the only automatically pushed fact

**Reason**: Replaced by ":via is the only automatically bound Fact". The
requirement and its scenarios were written around the rule-body `(with-facts …)`
form, which this change replaces with `(let-facts …)`; the wording "pushed"
also described the union-merge write model that no longer applies.

**Migration**: No behaviour change for `:via` itself. Configurations naming
`(with-facts …)` in a rule body move to `(let-facts …)`.
