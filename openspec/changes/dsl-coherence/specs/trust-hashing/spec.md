## ADDED Requirements

### Requirement: Class A migration rewrites auto-update trust hashes

When the `may-i migrate` command applies a Class A (syntactic, semantics-preserving) rewrite to a trusted rule, the trust store SHALL update the rule's stored hash to reflect the new canonical form, preserving the existing approval. The user SHALL be notified that hashes were updated but SHALL NOT be prompted to re-approve.

This auto-update SHALL apply only when:

- The rewrite is classified Class A by the migration system (see migration-system spec).
- The rule was trusted prior to migration.
- The new canonical form is computable.

If any condition fails, the rule's trust SHALL be invalidated and a manual `may-i trust` SHALL be required.

#### Scenario: Class A rewrite preserves approval, updates hash

- **GIVEN** a trusted loaded rule `(rule "ls" (effect :allow))` with stored hash H1
- **WHEN** `may-i migrate` rewrites to `(rule "ls" (allow))`
- **THEN** the stored hash SHALL update to H2 (matching new canonical form)
- **AND** the rule SHALL remain trusted without prompting.

#### Scenario: Migration notice surfaces the rehash count

- **GIVEN** five trusted rules, all rewritten by Class A passes
- **WHEN** `may-i migrate` completes
- **THEN** the output SHALL note "trust hashes updated for 5 rules" or equivalent.

### Requirement: Class B migration shifts emit a warning, no auto-rehash

When migration introduces a Class B change (semantic shift like the wrapper-boundary fix), trust hashes for affected rules SHALL NOT auto-update beyond what their accompanying Class A syntactic rewrites require. The migration SHALL emit a warning that names the affected commands and recommends re-running `may-i check` cases.

The intent: Class B changes alter what a rule does without changing how it's spelled. Trust covers approval that the rule's text is what the user wrote, not approval that its behaviour is what the user expects. The Class B warning is the user's signal to re-validate.

#### Scenario: Wrapper-boundary fix emits warning

- **GIVEN** a config with rules covering `sudo`
- **WHEN** `may-i migrate` runs with the dsl-coherence rewrites
- **THEN** the output SHALL emit a warning naming `sudo` (and any other affected wrapper commands)
- **AND** the warning SHALL recommend re-running `may-i check`.
