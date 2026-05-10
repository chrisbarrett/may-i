## ADDED Requirements

### Requirement: `may-i migrate` walks the `(load …)` graph transitively

The user-invoked migration command `may-i migrate` SHALL discover and rewrite every config file reachable from the primary config via `(load …)` directives, including glob expansions.

The walker SHALL:

- Resolve `(load …)` paths relative to each loading file (consistent with the load-time resolver).
- Expand globs (e.g. `(load "rules/*.lisp")`) at migration time.
- Dedupe visited files to avoid infinite loops on cycles.
- Skip files that exist but are not writable, emitting a clear "skipped, not writable" message naming each file.
- Apply the configured rewrite chain to each visited file.

The passive auto-migration on load (per existing behaviour) SHALL continue to apply only to the primary config; the transitive walk is exclusive to the explicit `may-i migrate` command.

#### Scenario: Migration walks loaded files

- **GIVEN** primary config `(load "rules/git.lisp") (load "rules/docker.lisp")`
- **WHEN** the user runs `may-i migrate`
- **THEN** the rewrite chain SHALL be applied to the primary config and to both loaded files.

#### Scenario: Migration walks transitively

- **GIVEN** primary config `(load "rules/index.lisp")` and `rules/index.lisp` contains `(load "groups/git.lisp")`
- **WHEN** the user runs `may-i migrate`
- **THEN** all three files SHALL be rewritten.

#### Scenario: Migration expands globs

- **GIVEN** primary config `(load "rules/*.lisp")` matching `git.lisp` and `docker.lisp`
- **WHEN** the user runs `may-i migrate`
- **THEN** both matched files SHALL be rewritten.

#### Scenario: Read-only file produces a clear notice

- **GIVEN** a loaded file under read-only filesystem
- **WHEN** the user runs `may-i migrate`
- **THEN** the file SHALL be skipped
- **AND** a "skipped, not writable" message SHALL name the file.

### Requirement: `may-i migrate --dry-run` previews planned rewrites

`may-i migrate` SHALL accept a `--dry-run` flag. When set, the migration SHALL list every file it would rewrite with a summary of rewrite counts per file, and SHALL NOT modify any file or trust state.

#### Scenario: Dry-run prints planned changes

- **GIVEN** a config tree with five files needing rewrites
- **WHEN** the user runs `may-i migrate --dry-run`
- **THEN** the output SHALL list each file with its rewrite count
- **AND** no file SHALL be modified.

### Requirement: Migration distinguishes Class A and Class B rewrites

The migration SHALL classify each rewrite into one of two classes:

- **Class A — syntactic, semantics-preserving**: rewrites that change the surface form of a rule without changing the decision the rule produces for any command. Examples: `(effect :allow)` → `(allow)`, `:style S` → `(style S)`, `(may-i *)` → `(authorise)`, `(positional X . CONT)` → `(positional X)` `(tail CONT)`, `define-arg-style` PLIST → form-list, `check` PLIST → form-list.

- **Class B — semantic shift**: changes that alter evaluation behaviour for some commands without textual rule changes. The dsl-coherence wrapper-boundary fix is the canonical Class B case: rules over wrapper commands (sudo, xargs, env, …) now correctly see flags after the inner cmd attributed to the inner cmd, where they previously were absorbed by the outer parser.

Class A rewrites SHALL silently update trust hashes (see trust-hashing spec). Class B SHALL emit a prominent warning naming the affected commands and SHALL NOT auto-update any state beyond the syntactic rewrites that accompany it.

#### Scenario: Class A rewrite leaves trust intact

- **GIVEN** a trusted rule `(rule "ls" (effect :allow))` rewritten by migration to `(rule "ls" (allow))`
- **WHEN** the user runs `may-i migrate`
- **THEN** the rule's trust SHALL carry over without prompting
- **AND** the trust hash SHALL update to reflect the new canonical form.

#### Scenario: Class B emits a warning

- **GIVEN** any config with rules covering wrapper tools
- **WHEN** the user runs `may-i migrate`
- **THEN** the migration SHALL emit a warning naming the wrapper commands
- **AND** the warning SHALL recommend re-running `may-i check` cases.

### Requirement: dsl-coherence rewrite chain

The migration SHALL include rewrite passes for every Class A transformation introduced by dsl-coherence. The passes SHALL be composable in the existing migration pipeline.

The required Class A rewrites SHALL be:

- `(rule PROG ... (effect :DECISION REASON?))` → `(rule PROG ... (DECISION REASON?))` for `:allow`/`:ask`/`:deny`.
- `(parser PROG :style STYLE BODY...)` → `(parser PROG (style STYLE) BODY...)`.
- `(define-arg-style NAME (:k v :k v))` → `(define-arg-style NAME (k v) (k v))` with PLIST-key forms mapped to form-name forms.
- `(check :DECISION CMD :DECISION CMD)` → `(check (DECISION CMD) (DECISION CMD))`.
- `(may-i *)` → `(authorise)` everywhere — both as parameter body and as positional-tail continuation.
- `(positional ITEMS... . (may-i *))` → `(positional ITEMS...)` plus a sibling `(tail (authorise))` form, composed in the rule body via `(and ...)`.
- `(positional "exec" "--" . (may-i *))`-shaped rules over commands that are now declared `(tail (after "--"))` in the prelude SHALL rewrite to `(positional "exec")` plus `(tail (authorise))`, relying on the prelude parser to set the boundary.

#### Scenario: Effect rewrite

- **GIVEN** `(rule "ls" (effect :allow))`
- **WHEN** migration runs
- **THEN** the output SHALL be `(rule "ls" (allow))`.

#### Scenario: Parser style rewrite

- **GIVEN** `(parser "find" :style single-dash-long)`
- **WHEN** migration runs
- **THEN** the output SHALL be `(parser "find" (style single-dash-long))`.

#### Scenario: May-i rewrite in parameter

- **GIVEN** `(parser "bash" :style gnu (parameter "c" (may-i *)))`
- **WHEN** migration runs
- **THEN** the output SHALL be `(parser "bash" (style gnu) (parameter "c" (authorise)))`.

#### Scenario: May-i rewrite in positional tail

- **GIVEN** `(rule "sudo" (positional . (may-i *)))`
- **WHEN** migration runs
- **THEN** the output SHALL be `(rule "sudo" (and (positional) (tail (authorise))))` or `(rule "sudo" (tail (authorise)))` if the prelude declares `(parser "sudo" (tail (after :flags)))`.

#### Scenario: Mise-shape rewrite uses prelude parser

- **GIVEN** `(rule "mise" (positional "exec" "--" . (may-i *)))` and prelude declaring `(parser "mise" (style gnu) (tail (after "--")))`
- **WHEN** migration runs
- **THEN** the output SHALL be `(rule "mise" (and (positional "exec") (tail (authorise))))` (the literal `"--"` is dropped because the parser-declared boundary handles it).

#### Scenario: Define-arg-style rewrite

- **GIVEN** `(define-arg-style java (:overrides gnu :separators (" " "=" ":")))`
- **WHEN** migration runs
- **THEN** the output SHALL be `(define-arg-style java (overrides gnu) (separators " " "=" ":"))`.

#### Scenario: Check rewrite

- **GIVEN** `(check :allow "ls -la" :deny "rm -rf /")`
- **WHEN** migration runs
- **THEN** the output SHALL be `(check (allow "ls -la") (deny "rm -rf /"))`.
