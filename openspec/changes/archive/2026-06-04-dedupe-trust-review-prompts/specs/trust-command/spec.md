## ADDED Requirements

### Requirement: Per-rule review deduplicates pending rules by canonical form

The per-rule interactive review SHALL present each unique canonical rule form at most once per session. When two or more pending rules share the same canonical form, the review SHALL prompt the user exactly once for that form, and the decision the user makes SHALL apply to every pending rule sharing the form.

#### Scenario: Rule matching multiple programs prompts once

- **WHEN** `may-i trust` is run interactively against a loaded config containing `(rule (or "git" "gh") (allow))` with no prior approvals
- **THEN** the per-rule review displays one prompt for that rule form, not two
- **AND** the progress label shows `1/1`, not `1/2`
- **AND** pressing `y` approves trust for both `git` and `gh`

#### Scenario: Identical rule text repeated across loaded files prompts once

- **WHEN** two `(load …)`-included files each contain the rule `(rule "echo" (allow))` and the user runs `may-i trust` interactively
- **THEN** the per-rule review displays one prompt for `(rule "echo" (allow))`
- **AND** pressing `y` records approval that covers both occurrences with no further prompt

#### Scenario: One keystroke clears the form from the pending set

- **WHEN** the user approves or blocks a deduplicated rule form
- **THEN** no later prompt in the same session re-shows that rule form
- **AND** a follow-up `may-i trust` invocation reports the rule as already trusted, with no pending entries

#### Scenario: Distinct canonical forms remain distinct

- **WHEN** the loaded config contains `(rule "git" (allow))` and `(rule "cargo" (allow))`
- **THEN** the per-rule review presents two prompts, one per form, in their original order
