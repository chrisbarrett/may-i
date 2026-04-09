## ADDED Requirements

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

### Requirement: Hash covers the full ordered closure

The trust hash for a program SHALL include all rules whose command effect
mentions that program, in config order, with defines fully resolved. Both
`PrimaryConfig` and `Loaded` rules are included.

#### Scenario: Reordering rules changes the hash

- **WHEN** a `Loaded` rule for `"git"` is moved before a `PrimaryConfig` rule
- **THEN** the trust hash for `"git"` changes

#### Scenario: Changing a referenced define changes the hash

- **WHEN** a `Loaded` define referenced by a `"git"` rule is modified
- **THEN** the trust hash for `"git"` changes

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
