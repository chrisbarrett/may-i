---
audience: user
bucket: migration
trust-relevant: true
---
# migration-system Specification

## Purpose

Defines the DSL migration pipeline: sexpr-level rewrite passes that transform older configuration syntax into the current canonical form before AST parsing, with comment/trivia preservation, transitive `(load …)` walking, and Class A/B classification controlling trust hash behaviour. Migration test policy — property-test generators for compound v1 forms, real-world wrapper patterns, and round-trip evaluation invariants — is documented here alongside the rewrite rules it verifies. Diff-display behaviour for `may-i migrate` (HOME-rewritten file-path header, three lines of context, `NO_COLOR`-respecting unified diff, interactive `[y/N]` confirm defaulting to cancel, `--yes` required for non-interactive) is also documented here.

## Requirements

### Requirement: Migration operates on sexprs before AST parsing
The migration system SHALL transform configuration files by applying rewrite passes to the sexpr tree, before the AST parser processes them.

#### Scenario: Rewrite pass transforms v1 syntax
- **GIVEN** a config file containing v1 syntax `(rule (command git) (effect :allow))`
- **WHEN** the migration system runs
- **THEN** the sexpr rewrite pass SHALL transform it to v2 syntax before AST parsing

### Requirement: Each version bump adds a rewrite pass
Each DSL version transition SHALL be implemented as a discrete sexpr rewrite pass. Passes SHALL be composable so a config from any version runs through the full chain.

#### Scenario: Config from earliest version migrates to current
- **GIVEN** a config written in the earliest supported DSL version
- **WHEN** running migration
- **THEN** all rewrite passes SHALL execute in sequence
- **AND** the output SHALL be valid current-version syntax

#### Scenario: Already-current config is unchanged
- **GIVEN** a config already in the current DSL version
- **WHEN** running migration
- **THEN** no rewrite passes SHALL modify the config

### Requirement: CST roundtrip preserves comments and formatting
Sexpr rewrite passes SHALL use the CST representation to preserve comments, whitespace, and formatting in the output file.

#### Scenario: Comments survive migration
- **GIVEN** a config with inline comments between forms
- **WHEN** running migration
- **THEN** comments SHALL appear in the output file at their original locations

#### Scenario: Formatting is preserved for unchanged forms
- **GIVEN** a config with custom indentation and line breaks
- **WHEN** running migration
- **THEN** forms that are not rewritten SHALL retain their original formatting

### Requirement: Comment and trivia preservation through migration
The migration pipeline SHALL preserve comments and trivia from the original v1 config in the migrated output.

#### Scenario: Comments between top-level forms
- **WHEN** a v1 config has comments between defcontext/rule forms
- **THEN** the migrated output SHALL retain those comments in their relative positions

#### Scenario: Inline comments inside forms
- **WHEN** a v1 wrapper form contains inline comments
- **THEN** the migrated rule SHALL retain the comments

#### Scenario: Multi-line comment blocks above rules
- **WHEN** a multi-line comment block precedes a v1 rule
- **THEN** the comment block SHALL appear before the migrated rule

### Requirement: Trace displays original V1 s-expression structure

When a V1 config has been transparently migrated, the trace output SHALL display
the original V1 s-expression structure (as written in the source file), not the
rewritten V2 AST structure.

#### Scenario: Command wrapper preserved
- **WHEN** the V1 source contains `(rule (command "git") (effect :allow))`
- **THEN** the trace displays `(rule (command "git") (effect :allow))`
- **AND NOT** the V2 form `(rule "git" :effect :allow)`

#### Scenario: Args and effect as siblings
- **WHEN** the V1 source contains `(rule (command "rm") (args (and ...)) (effect :deny "reason"))`
- **THEN** the trace displays `(args ...)` and `(effect ...)` as sibling children of the rule

### Requirement: Line numbers reference original V1 source

The line numbers shown in the trace SHALL correspond to the line in the original
V1 source file, not to any migrated or rewritten representation.

#### Scenario: Trace line numbers map to V1 source
- **WHEN** a trace is rendered for a transparently migrated V1 config
- **THEN** every line number references the corresponding line in the original V1 source file, not the rewritten V2 representation

### Requirement: Eval annotations overlay onto V1 structure

Annotations in the right column SHALL be placed on the correct lines of the V1
source display, even though they are produced by evaluating the V2 AST.

#### Scenario: V2 evaluation annotations align with V1 lines
- **WHEN** the trace evaluates a V2 AST derived from a V1 source
- **THEN** annotations in the right column appear on the V1 source lines that produced the corresponding V2 AST nodes

### Requirement: Source recovery uses pre-migration CST

The source recovery mechanism SHALL use pre-migration CstNodes stored on the
Config during transparent migration. Each rule is matched to its pre-migration
CstNode by span overlap, and the CstNode is converted to a Doc for display.

#### Scenario: Pre-migration CST stored during migration
- **WHEN** a config is loaded via transparent migration
- **THEN** `config.pre_migration_cst` contains the CstNodes from before
  rewrite rules were applied

#### Scenario: Native canonical config has no pre-migration CST
- **WHEN** a config parses directly as canonical syntax (no migration)
- **THEN** `config.pre_migration_cst` is `None`
- **AND** rendering uses the standard V2 AST Doc

### Requirement: Pretty-serialized CST roundtrips
Pretty_serialize at any column width SHALL produce output that re-parses to a structurally equivalent CST.

#### Scenario: Pretty roundtrip at various widths
- **WHEN** a CST is pretty-serialized at width W (20..120) and re-parsed
- **THEN** the atom and list structure SHALL be preserved

### Requirement: `strip_redundant_boundary` strips literals matching any prelude tail token

The `strip_redundant_boundary` migration pass SHALL inspect the prelude's `(tail (after STR…))` token set for the rule's program and strip any positional literal in the rule body that matches any token in that set. Programs whose prelude tail is `(after :flags)`, or whose prelude has no parser declaration, SHALL be unaffected.

#### Scenario: Single-token prelude tail strips matching literal
- **GIVEN** a prelude declaring `(parser "p" (style gnu) (tail (after "TOK")))`
- **AND** a migrated rule `(rule "p" (when (positional "X" "TOK") (tail (authorise))))`
- **WHEN** the migration pipeline applies `strip_redundant_boundary`
- **THEN** the rule SHALL become `(rule "p" (when (positional "X") (tail (authorise))))`

#### Scenario: Multi-token prelude tail strips any matching literal
- **GIVEN** a prelude declaring `(parser "nix" (style gnu) (tail (after ["--command" "-c"])))`
- **AND** a migrated rule `(rule "nix" (when (positional (or "shell" "develop") "--command") (tail (authorise))))`
- **WHEN** the migration pipeline applies `strip_redundant_boundary`
- **THEN** the rule SHALL become `(rule "nix" (when (positional (or "shell" "develop")) (tail (authorise))))`

#### Scenario: Migration of v1 nix wrapper produces correct rule
- **GIVEN** a v1 wrapper form `(wrapper "nix" (positional (or "shell" "develop")) (flag "--command" :command+args))`
- **WHEN** the full migration pipeline runs
- **THEN** the output SHALL be `(rule "nix" (when (positional (or "shell" "develop")) (tail (authorise))))`
- **AND** the migrated rule SHALL correctly route `nix shell pkg --command mkfs /dev/sda` through `(tail (authorise))` for recursive evaluation

#### Scenario: No-op for `:after-flags` prelude tail
- **GIVEN** a prelude declaring `(parser "sudo" (style gnu) (tail (after :flags)))`
- **AND** a migrated rule `(rule "sudo" (when (positional "literal") (tail (authorise))))`
- **WHEN** the migration pipeline applies `strip_redundant_boundary`
- **THEN** the rule SHALL be unchanged (no boundary literal to strip)

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

### Requirement: Migration rule `and_trailing_effect_to_when`

The migration rule SHALL extract a trailing low-complexity `(effect ...)` from
an `(and ...)` predicate, rewriting to a `(when ...)` form.

**Trigger:** `(and e1 … en)` where `en` is `(effect ...)` with structural
complexity ≤ 3.

**Complexity scoring:**
- Atoms: 1
- `(regex "r")`: 1 (special-cased as a leaf)
- Any other `(tag e1 … en)`: `1 + max(complexity(e1), …, complexity(en))`
- `[e1 … en]` (vector): `1 + max(complexity(e1), …, complexity(en))`

#### Scenario: Low-complexity trailing effect rewrites to `when`
- **GIVEN** `(and (positional "X") (effect :allow))` where the trailing `(effect …)` has structural complexity ≤ 3
- **WHEN** the migration rule `and_trailing_effect_to_when` runs
- **THEN** the form rewrites to `(when (positional "X") (effect :allow))`

#### Scenario: High-complexity trailing effect is left alone
- **GIVEN** `(and pred (effect …))` where the `(effect …)` has structural complexity > 3
- **WHEN** the migration rule `and_trailing_effect_to_when` runs
- **THEN** the form is left unchanged

### Requirement: Property test generators for compound v1 forms
The migration property test suite SHALL include generators for compound v1 configurations that exercise multiple rewrite rules simultaneously.

#### Scenario: Compound rule generator
- **WHEN** the any_v1_compound_rule generator produces a v1 config
- **THEN** it SHALL include (command ...), (context ...), and (args ...) in a single rule

#### Scenario: Wrapper generator
- **WHEN** the any_v1_wrapper generator produces a wrapper form
- **THEN** it SHALL include random positional patterns, flag patterns, and capture markers

#### Scenario: Full config generator
- **WHEN** the any_v1_config generator produces a config
- **THEN** it SHALL mix rules, wrappers, defcontexts, and defines

### Requirement: Compound v1 forms preserve evaluation semantics
Migration of v1 configs that trigger multiple rewrite rules simultaneously SHALL produce v2 configs that evaluate identically for all input commands, arguments, and facts.

#### Scenario: Command + context + args combined
- **WHEN** a v1 rule has (command ...), (context ...), and (args ...) forms
- **THEN** the migrated v2 rule SHALL produce the same allow/deny/ask decision for any input

#### Scenario: Named predicate references
- **WHEN** a v1 config uses (defcontext NAME ...) referenced in (context NAME)
- **THEN** the migrated config with (define NAME ...) SHALL evaluate identically

#### Scenario: Compound context with nested has key-value
- **WHEN** a v1 context uses (and (has :key) (has [:key value]))
- **THEN** the migrated fact? expressions SHALL match the same inputs

### Requirement: Real-world wrapper patterns migrate correctly
All wrapper form patterns used in production configs SHALL be tested through migration.

#### Scenario: Wrapper with positional + flag + capture
- **WHEN** a wrapper like (wrapper "mise" (positional "exec") (flag "--" :command+args)) is migrated
- **THEN** the resulting rule SHALL evaluate identically for wrapped commands

### Requirement: has with complex value patterns migrates correctly
The rename_has_to_fact rewrite SHALL preserve semantics for all legal value patterns.

#### Scenario: has with regex value
- **WHEN** (has [:key (regex "pattern")]) is migrated
- **THEN** (fact? [:key (regex "pattern")]) SHALL match the same inputs

#### Scenario: has with or value
- **WHEN** (has [:key (or "a" "b")]) is migrated
- **THEN** (fact? [:key (or "a" "b")]) SHALL match the same inputs

### Requirement: Mixed v1/v2 configs migrate correctly
Files containing both v1 and v2 syntax SHALL only migrate the v1 forms, leaving v2 forms unchanged.

#### Scenario: v2 forms pass through untouched
- **WHEN** a config mixes a v1 `(wrapper …)` form with a v2 `(rule …)` form
- **THEN** migration SHALL rewrite the v1 form and leave the v2 form byte-identical

### Requirement: Proptest generators cover compound v1 forms
Property tests SHALL generate compound v1 configs and verify evaluation equivalence after migration.

#### Scenario: Generated compound config round-trips
- **WHEN** the proptest harness produces a compound v1 config and migrates it
- **THEN** the migrated v2 config SHALL evaluate identically to the v1 original for every sampled input

### Requirement: Migration diff shows file path header

The migration command SHALL display the config file path as a header before the diff, with the HOME directory prefix rewritten as `~`.

#### Scenario: Standard config path

- **WHEN** migrating a config at `/home/user/.config/may-i/config.lisp`
- **THEN** the diff SHALL start with `~/.config/may-i/config.lisp:`

#### Scenario: Config outside HOME

- **WHEN** migrating a config at `/etc/may-i/config.lisp`
- **THEN** the diff SHALL show the absolute path `/etc/may-i/config.lisp:`

### Requirement: Diff shows changed lines with context

The migration diff SHALL display removed lines prefixed with `-`, added lines prefixed with `+`, and unchanged context lines without prefix. It SHALL show three lines of context around each change.

#### Scenario: Changes surrounded by context

- **WHEN** a migration changes one form in a file
- **THEN** the diff includes three lines before and after the change as unchanged context

### Requirement: Diff respects NO_COLOR

The diff output SHALL use colours (red for `-`, green for `+`) when stdout is a TTY and the `NO_COLOR` environment variable is unset. With `NO_COLOR` set, colours SHALL be omitted; line prefixes still distinguish add vs remove.

#### Scenario: NO_COLOR suppresses ANSI

- **WHEN** `NO_COLOR` is set in the environment
- **THEN** the diff output contains no ANSI escape sequences

### Requirement: Migration shows diff before applying changes

The migration command SHALL display the diff before applying changes when running interactively, then prompt for confirmation with `[y/N]`.

#### Scenario: Interactive migration with changes

- **WHEN** the user runs `may-i migrate` on a config with v1 syntax in an interactive terminal and there are changes to apply
- **THEN** the command SHALL display a unified diff with file-path header and context lines
- **AND** prompt for confirmation with `[y/N]`

#### Scenario: Non-interactive with changes

- **WHEN** the user runs `may-i migrate` in a non-interactive environment with changes to apply and without `--yes`
- **THEN** the command SHALL fail with the error `Config file would be modified. Use --yes to confirm non-interactive execution.`
- **AND** not display a diff

#### Scenario: No changes needed

- **WHEN** the user runs `may-i migrate` on an already-migrated config
- **THEN** the command SHALL indicate no changes are needed
- **AND** not display a diff
- **AND** not prompt for confirmation

### Requirement: Interactive prompt defaults to No

When prompting for confirmation, the migration command SHALL default to cancelling (No) if the user presses Enter without input.

#### Scenario: User presses Enter at prompt

- **WHEN** the prompt shows `[y/N]` and the user presses Enter
- **THEN** the migration SHALL be cancelled

#### Scenario: User types 'y' at prompt

- **WHEN** the prompt shows `[y/N]` and the user types `y` or `Y`
- **THEN** the migration SHALL proceed
