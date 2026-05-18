---
audience: contributor
bucket: trust
trust-relevant: true
---
# trust-store Specification

## Purpose

Contributor-only. On-disk persistence layer for trust approvals: the `Provenance` tag (`PrimaryConfig`/`Loaded`) every rule and define carries, the v3 store format keyed by canonical-form hash, per-rule entries, source-file provenance carried on `Provenance::Loaded`, the `TrustHashes` metadata returned by `compute_trust_hashes`, and the integrity-verification + interactive-repair flow for tampered entries. Runtime evaluation semantics (when a mismatch blocks, when the gate bypasses) live in `trust-gate`; hash computation lives in `trust-hashing`; the user-facing CLI surface lives in `trust-command`.

## Requirements

### Requirement: Trust hashes are stored persistently

The system SHALL store trust hashes in a persistent file at a platform-appropriate data directory (e.g. `~/.local/share/may-i/trust.json`).

#### Scenario: Approved hash is persisted

- **WHEN** the user approves trust for program `"git"`
- **THEN** the hash is written to the trust store and survives process restart

### Requirement: Trust is per-rule, not per-program

Each loaded rule SHALL be individually tracked in the trust store by its canonical form hash. Trust decisions (approve, ignore) apply to individual rules, not to programs as a whole.

#### Scenario: Two rules for same program, one approved one ignored
- **GIVEN** config has two loaded rules for `git`: rule A `(rule "git" (allow))` and rule B `(rule "git" (when (dir "/tmp") (deny)))`
- **WHEN** user approves rule A and ignores rule B
- **THEN** only rule A participates in evaluation; rule B is invisible to the eval pipeline

#### Scenario: Pending rules are inactive
- **GIVEN** a freshly loaded config with 3 rules, none yet reviewed
- **WHEN** `may-i eval "git status"` runs
- **THEN** none of the loaded rules participate in evaluation (only primary config rules apply)

#### Scenario: Approving a rule activates it
- **GIVEN** rule A is pending
- **WHEN** user approves rule A via `may-i trust`
- **THEN** rule A participates in subsequent evaluations

#### Scenario: Primary config rules are unaffected
- **GIVEN** rules defined directly in the primary config (not via `(load ...)`)
- **THEN** those rules always participate in evaluation regardless of trust state

### Requirement: Trust store v3 format with per-rule entries

The trust store SHALL use a v3 format keyed by canonical form hash, with each entry recording program name, canonical form, and status (approved/ignored).

#### Scenario: v2 to v3 migration
- **GIVEN** a v2 trust store with per-program entries
- **WHEN** the store is loaded
- **THEN** each program's rules are converted to individual rule entries with status `approved`

#### Scenario: Orphan cleanup
- **GIVEN** the store contains entries for rules no longer present in the current config
- **WHEN** interactive review completes and the store is saved
- **THEN** orphaned entries (hashes not in current config) are removed

### Requirement: Rules are tagged with provenance

Every `Rule` in the parsed config SHALL carry a `Provenance` value: either
`PrimaryConfig` (from the root config file) or `Loaded` (from a file included
via `(load ...)`).

#### Scenario: Root config rules are PrimaryConfig

- **WHEN** a rule is defined in the root config file
- **THEN** the rule's provenance is `PrimaryConfig`

#### Scenario: Loaded file rules are Loaded

- **WHEN** a rule is defined in a file included via `(load "rules.lisp")`
- **THEN** the rule's provenance is `Loaded`

#### Scenario: Recursively loaded rules are Loaded

- **WHEN** `a.lisp` is loaded from the root config, and `a.lisp` loads
  `b.lisp` which contains a rule
- **THEN** the rule from `b.lisp` has provenance `Loaded`

### Requirement: Defines are tagged with provenance

Every `Define` in the parsed config SHALL carry a `Provenance` value, following
the same rules as rule provenance.

#### Scenario: Root config defines are PrimaryConfig

- **WHEN** a define is declared in the root config file
- **THEN** the define's provenance is `PrimaryConfig`

#### Scenario: Loaded file defines are Loaded

- **WHEN** a define is declared in a file included via `(load "defines.lisp")`
- **THEN** the define's provenance is `Loaded`

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

### Requirement: Repo-local discovered files use Loaded provenance

The resolver SHALL parse rules and defines from files discovered via repo-local resolution (per the `repo-local-config` capability) with `Provenance::Loaded { path }`, where `path` is the canonical path to the discovered file. The trust gate SHALL treat these rules identically to rules reached via an explicit `(load …)` directive: filtered until approved, hash-keyed, and surfaced in trust advisories with their source path.

#### Scenario: Repo-local rule appears in trust listing
- **WHEN** `may-i trust` is run from inside a repo containing
  `.may-i.lisp` with rules not yet approved
- **THEN** the listing SHALL include the program(s) covered by those
  rules
- **AND** the source file path SHALL be the path to the repo-local
  `.may-i.lisp`

#### Scenario: Approval persists across reach paths
- **GIVEN** a rule approved when reached via repo-local discovery of
  `/repo/.may-i.lisp`
- **WHEN** the same canonical rule form is later reached via an
  explicit `(load "/repo/.may-i.lisp")` from a different primary
  config
- **THEN** the trust check SHALL return `Approved` (the hash matches)

#### Scenario: Repo-local rules are filtered when un-approved
- **GIVEN** a repo-local file containing a rule with no trust-store
  entry
- **WHEN** the trust gate processes the loaded config
- **THEN** the rule SHALL be removed from the config passed to the
  evaluator
- **AND** the program SHALL appear in the trust advisory naming the
  repo-local file path
