# Trust-Hashing Specification

## Purpose

Defines how `may-i` computes per-program trust hashes over the resolved rule
closure: which rules and defines participate, the canonical order-independent
serialisation, exclusion of non-semantic content, the `safe-env-vars` scope,
and the Class A / Class B migration interaction with stored hashes.

Trust-relevant: yes — see `trust-store`, `trust-command`, `trust-provenance`.

## Requirements

### Requirement: Trust hash is computed per program name

For each program that has any rule or define with `Loaded` provenance, the
system SHALL compute a SHA-256 hash over the resolved rule closure for that
program.

#### Scenario: Program with loaded rule gets a hash

- **WHEN** program `"git"` has one `PrimaryConfig` rule and one `Loaded` rule
- **THEN** the system computes a trust hash for `"git"`

#### Scenario: Program with only PrimaryConfig rules has no hash

- **WHEN** program `"docker"` has only `PrimaryConfig` rules and references no
  `Loaded` defines
- **THEN** no trust hash is computed for `"docker"`

### Requirement: Hash covers the canonical rule and define set

The trust hash for a program SHALL include all rules whose command effect
mentions that program and all defines referenced (directly or transitively)
by those rules. Both `PrimaryConfig` and `Loaded` rules are included.

The hash SHALL be computed over a canonical, *order-independent*
serialisation: each rule and each define is rendered into its canonical
s-expression form, the resulting strings are sorted lexically within each
group (rules and defines), and the two sorted groups are concatenated with
a separator. Source-file order, comments, whitespace, and the way rules
are partitioned across `(load …)` files SHALL NOT influence the hash.

#### Scenario: Reordering rules does not change the hash

- **WHEN** two rules for `"git"` are swapped in source order
- **THEN** the trust hash for `"git"` SHALL be unchanged

#### Scenario: Moving a rule between loaded files does not change the hash

- **GIVEN** rule R for `"git"` lives in `rules/a.lisp`
- **WHEN** R is moved verbatim into `rules/b.lisp`
- **THEN** the trust hash for `"git"` SHALL be unchanged

#### Scenario: Changing a rule's content changes the hash

- **WHEN** a rule's body is edited (e.g. its decision changes from
  `:allow` to `:deny`)
- **THEN** the trust hash for the affected program SHALL change

#### Scenario: Changing a referenced define changes the hash

- **WHEN** a `Loaded` define referenced by a `"git"` rule is modified
- **THEN** the trust hash for `"git"` SHALL change

### Requirement: Programs referencing Loaded defines need trust

If a program's rules reference any define with `Loaded` provenance (directly or
transitively), that program SHALL require trust approval even if all its rules
are `PrimaryConfig`.

#### Scenario: PrimaryConfig rule using Loaded define

- **WHEN** `(rule "kubectl" (when on-vpn (allow)))` is `PrimaryConfig` but
  `(define on-vpn ...)` is `Loaded`
- **THEN** program `"kubectl"` requires trust approval

### Requirement: safe-env-vars has its own trust scope

When any `safe-env-vars` entry comes from a `Loaded` file, the system SHALL
compute a trust hash for the merged `safe-env-vars` set under a separate scope
key.

#### Scenario: Loaded safe-env-vars gets hashed

- **WHEN** a loaded file contains `(safe-env-vars "AWS_SECRET_KEY")`
- **THEN** the system computes a trust hash under the `:safe-env-vars` scope

#### Scenario: PrimaryConfig-only safe-env-vars has no hash

- **WHEN** `safe-env-vars` is only defined in the root config
- **THEN** no trust hash is computed for `:safe-env-vars`

### Requirement: Hash excludes non-semantic content

The trust hash SHALL NOT be affected by comments, whitespace changes,
formatting, `(check ...)` forms, or `(load ...)` directives.

#### Scenario: Adding a comment does not change the hash

- **WHEN** a comment is added to a loaded file
- **THEN** the trust hash for affected programs is unchanged

#### Scenario: Adding a check does not change the hash

- **WHEN** a `(check ...)` form is added to a loaded file
- **THEN** the trust hash for affected programs is unchanged

### Requirement: Hash is computed from canonical serialization

The system SHALL serialize resolved rules to a canonical s-expression form
(deterministic, span-free) before hashing.

#### Scenario: Equivalent configs produce identical hashes

- **WHEN** two configs produce identical resolved rule closures for a program
  but differ in formatting
- **THEN** both produce the same trust hash

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
