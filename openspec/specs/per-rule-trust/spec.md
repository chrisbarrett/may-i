# Per-Rule-Trust Specification

## Purpose

Per-rule trust granularity: each loaded rule is tracked individually in the
trust store by its canonical-form hash, and approve / ignore decisions apply
to single rules rather than to whole programs.

Trust-relevant: yes — see `trust-store`, `trust-hashing`.

## Requirements

### Requirement: Trust is per-rule, not per-program
Each loaded rule SHALL be individually tracked in the trust store by its canonical form hash. Trust decisions (approve, ignore) apply to individual rules, not to programs as a whole.

#### Scenario: Two rules for same program, one approved one ignored
- **GIVEN** config has two loaded rules for `git`: rule A `(rule "git" (effect :allow))` and rule B `(rule "git" (when (dir "/tmp") (effect :deny)))`
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
