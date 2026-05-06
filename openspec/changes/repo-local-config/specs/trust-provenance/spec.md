## ADDED Requirements

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
