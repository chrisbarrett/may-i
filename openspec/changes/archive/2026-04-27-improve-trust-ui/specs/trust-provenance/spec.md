## ADDED Requirements

### Requirement: Provenance carries source file path
`Provenance::Loaded` SHALL carry the `PathBuf` of the file from which the form was loaded. `Provenance::PrimaryConfig` remains unchanged.

#### Scenario: Rule loaded from a file records its path
- **WHEN** a config contains `(load "rules/git.lisp")` and `rules/git.lisp` contains a rule
- **THEN** the parsed rule's `provenance` is `Provenance::Loaded { path }` where `path` is the canonical path to `rules/git.lisp`

#### Scenario: Define loaded from a file records its path
- **WHEN** a loaded file contains a `(define ...)` form
- **THEN** the parsed define's `provenance` is `Provenance::Loaded { path }` where `path` is the canonical path to that file

#### Scenario: Recursively loaded files carry their own path
- **WHEN** `a.lisp` loads `b.lisp` which loads `c.lisp`
- **THEN** rules from `c.lisp` have provenance with `c.lisp`'s path, not `a.lisp`'s

#### Scenario: Primary config rules are unaffected
- **WHEN** a rule is defined directly in the root config file
- **THEN** its provenance is `Provenance::PrimaryConfig` (unchanged)

### Requirement: TrustHashes carries per-program metadata
`compute_trust_hashes` SHALL return per-program metadata including the hash, canonical rule strings, and set of source file paths.

#### Scenario: Metadata includes canonical rule forms
- **WHEN** trust hashes are computed for a program with loaded rules
- **THEN** the program's metadata includes the canonical s-expression strings used for hashing

#### Scenario: Metadata includes source file paths
- **WHEN** a program's rules come from multiple loaded files
- **THEN** the program's metadata includes all contributing file paths

#### Scenario: Primary-only programs excluded
- **WHEN** all rules for a program have `PrimaryConfig` provenance
- **THEN** the program does not appear in TrustHashes (unchanged behavior)

### Requirement: Trust store persists canonical forms
The trust store SHALL persist canonical rule forms alongside hashes so that diffs can be computed when rules change.

#### Scenario: Approving a program stores its canonical forms
- **WHEN** a user runs `may-i trust "echo"`
- **THEN** the trust store file contains the hash AND the canonical rule strings for `echo`

#### Scenario: Trust store writes v2 format
- **WHEN** the trust store is saved after any modification
- **THEN** the file uses the v2 format with `version`, `programs` map, and canonical forms
- **AND** any pre-existing v1 format file is replaced (old entries re-appear as NEW)

#### Scenario: Old canonical forms available for diff
- **WHEN** a program's rules have changed since last approval
- **THEN** the trust store provides the previously-stored canonical forms for comparison

### Requirement: Trust store verifies integrity of stored canonical forms
The trust store SHALL verify that stored canonical forms are consistent with their stored hash on load. The hash is the source of truth; canonical forms are untrusted display metadata that MUST be cryptographically verified before use.

#### Scenario: Stored forms match their hash
- **WHEN** the trust store is loaded and an entry's canonical forms re-hash to the stored hash
- **THEN** the entry loads normally with canonical forms available for diff display

#### Scenario: Unrecognized store format discarded
- **WHEN** the trust store file is in an unrecognized format (e.g., old v1)
- **THEN** loading returns an empty store (all programs appear as NEW)

#### Scenario: Verification uses same hash algorithm as compute_trust_hashes
- **WHEN** verifying stored canonical forms
- **THEN** the verification joins the stored forms with newline and computes SHA-256 identically to `compute_trust_hashes`

### Requirement: Integrity failures gate trust operations with interactive repair
When the trust store contains entries whose canonical forms fail integrity verification, the system SHALL warn the user and require interactive resolution before any trust operation proceeds. This prevents a tampered trust store from silently poisoning diff output.

#### Scenario: Suspect entries detected — warning displayed
- **WHEN** the trust store is loaded and one or more entries have canonical forms that do NOT re-hash to their stored hash
- **THEN** the system prints a warning naming each suspect program and stating the stored forms may have been modified by another tool

#### Scenario: Interactive repair session before trust operation
- **WHEN** suspect entries exist and the user runs any `may-i trust` subcommand (list, approve, approve-all)
- **THEN** before the requested operation proceeds, the system enters an interactive session presenting each suspect entry
- **AND** for each suspect entry the user sees: the program name, the stored hash, and the stored (unverified) canonical forms
- **AND** the user may choose to **re-approve** (re-hash the stored forms, accepting them as correct) or **drop** (remove the entry from the trust store)

#### Scenario: Re-approve updates hash to match stored forms
- **WHEN** the user chooses to re-approve a suspect entry
- **THEN** the entry's hash is recomputed from its stored canonical forms and saved
- **AND** the entry is now verified and proceeds as trusted

#### Scenario: Drop removes entry from trust store
- **WHEN** the user chooses to drop a suspect entry
- **THEN** the entry is removed from the trust store entirely
- **AND** the program will be treated as NEW on next trust check

#### Scenario: All suspect entries resolved before proceeding
- **WHEN** the interactive session completes (all suspect entries resolved)
- **THEN** the modified trust store is saved to disk
- **AND** the originally requested trust operation proceeds with the cleaned store

#### Scenario: Non-interactive context skips repair, treats forms as unavailable
- **WHEN** suspect entries exist but the context is non-interactive (e.g., hook mode, piped stdin, `--json` flag)
- **THEN** the system does NOT enter interactive repair
- **AND** suspect entries' canonical forms are treated as unavailable (empty) for that invocation
- **AND** a warning is emitted to stderr noting that `may-i trust` should be run interactively to resolve
