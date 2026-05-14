---
audience: user
bucket: trust
trust-relevant: true
---
# trust-store Specification

## Purpose

Persistent on-disk storage of approved trust hashes — including per-rule granularity (each loaded rule tracked individually by canonical-form hash) and source-file provenance (every Loaded form records the `PathBuf` it came from, enabling per-file grouping in the trust UI and accurate trust-scope assignment). Also defines the evaluation block behaviour when a stored hash does not match the current computed hash, the v3 store format, integrity verification of stored canonical forms, and the interactive-repair flow for tampered entries. See `trust-hashing` for hash computation, `trust-command` for the approval UI, `trust-gate` for the runtime check.

## Requirements

### Requirement: Trust hashes are stored persistently

The system SHALL store trust hashes in a persistent file at a platform-appropriate data directory (e.g. `~/.local/share/may-i/trust.json`).

#### Scenario: Approved hash is persisted

- **WHEN** the user approves trust for program `"git"`
- **THEN** the hash is written to the trust store and survives process restart

### Requirement: Evaluation blocks on trust mismatch

When a program's computed trust hash does not match the stored hash, the system SHALL block evaluation for that program, returning `ask` with a reason indicating trust approval is needed.

#### Scenario: Hash mismatch blocks evaluation

- **WHEN** evaluating `"git commit"` and the trust hash for `"git"` has changed since last approved
- **THEN** the system returns decision `ask` with a reason mentioning trust approval

#### Scenario: Hash match allows evaluation

- **WHEN** evaluating `"git commit"` and the trust hash for `"git"` matches the stored value
- **THEN** evaluation proceeds normally

### Requirement: First load of a program requires approval

When a program has `Loaded` content and no entry exists in the trust store, the system SHALL treat it as a trust mismatch (no TOFU).

#### Scenario: New loaded program blocks until approved

- **WHEN** a loaded file introduces rules for `"kubectl"` and no trust entry exists
- **THEN** evaluation for `"kubectl"` blocks with a trust approval message

### Requirement: Programs without loaded content bypass trust

Programs whose rules and referenced defines are all `PrimaryConfig` SHALL bypass trust checking entirely — no hash computed, no store lookup.

#### Scenario: PrimaryConfig-only program evaluates freely

- **WHEN** program `"ls"` has only `PrimaryConfig` rules
- **THEN** evaluation proceeds without any trust check

### Requirement: Hook mode uses exit code 2 for trust blocks

In Claude Code hook mode, a trust block SHALL produce exit code 2 (blocking error), consistent with other blocking errors.

#### Scenario: Trust block in hook mode

- **WHEN** a trust mismatch occurs during hook-mode evaluation
- **THEN** the process exits with code 2 and the error message is fed back to the harness

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

### Requirement: Interactive review uses `git add -p` style keybindings
When run interactively, `may-i trust` SHALL present each pending rule one at a time with single-key actions.

#### Scenario: Keybindings
- **WHEN** a pending rule is displayed
- **THEN** the prompt offers: `[y] approve  [n] ignore  [s] skip  [q] quit`
- **AND** `y` approves the rule (stores as approved)
- **AND** `n` ignores the rule (stores as ignored, excluded from eval)
- **AND** `s` skips the rule (leaves it pending, no store change)
- **AND** `q` quits review (remaining rules keep their current state)

#### Scenario: New rule display
- **WHEN** a rule has never been reviewed
- **THEN** it is displayed with a `NEW` badge, the canonical form, and source file path

#### Scenario: Changed rule display with diff
- **WHEN** a rule's canonical form has changed since last review (detected by position within program)
- **THEN** it is displayed with a `CHANGED` badge and a line-level diff of old vs new canonical form

#### Scenario: Review summary
- **WHEN** interactive review completes (all rules processed or user quits)
- **THEN** a summary line is shown: `Approved: N  Ignored: N  Skipped: N`

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

### Requirement: Eval pipeline filters rules by trust status
The evaluation pipeline SHALL exclude loaded rules that are not approved in the trust store.

#### Scenario: Ignored rule excluded from eval
- **GIVEN** rule B is marked `ignored` in the trust store
- **WHEN** `may-i eval` runs a command that would match rule B
- **THEN** rule B does not affect the evaluation result

#### Scenario: Pending rule excluded from eval
- **GIVEN** rule C has never been reviewed (not in trust store)
- **WHEN** `may-i eval` runs a command that would match rule C
- **THEN** rule C does not affect the evaluation result

#### Scenario: Approved rule included in eval
- **GIVEN** rule A is marked `approved` in the trust store
- **WHEN** `may-i eval` runs a command that would match rule A
- **THEN** rule A participates in evaluation normally

### Requirement: Non-interactive batch mode
When stdin is not a TTY or `--json` is set, `may-i trust --all` SHALL approve all pending rules without prompting.

#### Scenario: Batch approve all
- **GIVEN** 5 pending rules and stdin is piped
- **WHEN** `may-i trust --all` runs
- **THEN** all 5 rules are approved without prompting

### Requirement: Trust listing reflects per-rule status
`may-i trust` listing SHALL show per-rule status, not per-program.

#### Scenario: Mixed rule statuses within a program
- **GIVEN** program `git` has 3 rules: 1 approved, 1 ignored, 1 pending
- **WHEN** `may-i trust` lists status
- **THEN** each rule is shown individually with its status (approved/ignored/pending)

#### Scenario: JSON output per-rule
- **WHEN** `may-i trust --json` runs
- **THEN** JSON output contains an array of per-rule entries, each with `program`, `hash`, `form`, `status`, and `file`

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
