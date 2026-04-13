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

### Requirement: Eval annotations overlay onto V1 structure

Annotations in the right column SHALL be placed on the correct lines of the V1
source display, even though they are produced by evaluating the V2 AST.

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
