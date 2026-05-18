## MODIFIED Requirements

### Requirement: TrustHashes carries per-program metadata

The trust module SHALL produce per-rule metadata joined with trust-store approval state into a single unified view (working name `TrustView`) per rule, carrying hash, canonical form, program, source file (when provenance is `Loaded`), position within the program, and approval state (`Approved`, `Blocked`, or `Pending`). A per-program derived view SHALL be available for listing UIs (program name, hash, canonical rule strings, canonical define strings, source file paths). The join between engine-computed metadata and trust-store state SHALL occur in exactly one place — the CLI's trust module — and CLI handlers SHALL consume the unified view rather than holding per-rule metadata and the trust store separately.

#### Scenario: Per-rule view carries approval state

- **WHEN** the trust module is asked for the unified view of a config whose loaded rule for `git` is approved in the trust store
- **THEN** the returned view for that rule has `state = Approved`
- **AND** the rule's hash, canonical form, program (`git`), and source file path are populated

#### Scenario: Loaded rule absent from store maps to Pending

- **WHEN** a loaded rule for `kubectl` has no entry in the trust store
- **THEN** the unified view for that rule has `state = Pending`
- **AND** the rule's hash, canonical form, program, and source file path are populated

#### Scenario: Blocked entries surface as Blocked state

- **WHEN** a loaded rule's hash is recorded in the trust store with status `Blocked`
- **THEN** the unified view for that rule has `state = Blocked`

#### Scenario: Per-program derived view groups rules

- **WHEN** a program `git` has three loaded rules across two files (`a.lisp`, `b.lisp`), all approved
- **THEN** the per-program derived view for `git` carries the program's combined hash, all three canonical rule strings, transitively-referenced canonical define strings, and the set `{a.lisp, b.lisp}` of source files

#### Scenario: Metadata includes canonical rule forms

- **WHEN** the unified view is computed for a program with loaded rules
- **THEN** each rule's canonical s-expression string is present on its `TrustView` and the per-program derived view's canonical rule list

#### Scenario: Metadata includes source file paths

- **WHEN** a program's rules come from multiple loaded files
- **THEN** the per-program derived view's source-file set contains all contributing file paths

#### Scenario: Primary-only programs excluded

- **WHEN** all rules for a program have `PrimaryConfig` provenance
- **THEN** the program does not appear in the unified view (no `TrustView` is emitted for `PrimaryConfig`-only rules; unchanged behaviour)

#### Scenario: CLI handler signature carries the unified view

- **WHEN** a `cmd_trust` or `interactive` function needs to render or mutate trust state for a rule
- **THEN** the function takes the unified view (or catalog of views) as a parameter
- **AND** the function does NOT take a separate per-rule metadata reference and a separate `TrustStore` reference; the join is performed once before the function is called
