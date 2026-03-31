## ADDED Requirements

### Requirement: Trace displays original V1 s-expression structure

When a V1 config has been transparently migrated, the trace output SHALL display
the original V1 s-expression structure (as written in the source file), not the
rewritten V2 AST structure. This applies to all structural elements: `(command
...)` wrappers, `(args ...)` / `(effect ...)` as siblings, `(defcontext ...)`
references, and unexpanded patterns.

#### Scenario: Command wrapper preserved
- **WHEN** the V1 source contains `(rule (command "git") (effect :allow))`
- **THEN** the trace displays `(rule (command "git") (effect :allow))`
- **AND NOT** the V2 form `(rule "git" :effect :allow)`

#### Scenario: Args and effect as siblings
- **WHEN** the V1 source contains `(rule (command "rm") (args (and ...)) (effect :deny "reason"))`
- **THEN** the trace displays `(args ...)` and `(effect ...)` as sibling
  children of the rule
- **AND NOT** the V2 form where effect is nested inside args

#### Scenario: Pattern not expanded by migration
- **WHEN** the V1 source contains `(anywhere "-r")`
- **AND** migration would expand this to `(anywhere "-r" "--recursive")`
- **THEN** the trace displays `(anywhere "-r")` as written in source

#### Scenario: Context references use original names
- **WHEN** the V1 source uses `(defcontext build-mode ...)` and `(context build-mode)`
- **THEN** the trace displays `(context ...)` with the original form
- **AND NOT** the V2 renamed `(define ...)` or inlined predicate

### Requirement: Line numbers reference original V1 source

The line numbers shown in the trace (e.g. `43:`) SHALL correspond to the line in
the original V1 source file, not to any migrated or rewritten representation.

#### Scenario: Line number matches source file
- **WHEN** a rule starts at line 43 in the V1 config file
- **THEN** the trace prefix shows `43:`

### Requirement: Eval annotations overlay onto V1 structure

Annotations in the right column (match results, decision arrows, set membership)
SHALL be placed on the correct lines of the V1 source display, even though they
are produced by evaluating the V2 AST.

#### Scenario: Positional comparison annotation
- **WHEN** evaluating `"git status"` against a rule with `(positional "reset")`
- **THEN** the annotation `"status" = "reset" → no` appears on the line
  containing `"reset"` in the V1 source display

#### Scenario: Anywhere set membership annotation
- **WHEN** evaluating `"rm -rf /"` against a rule with `(anywhere "-r")`
- **THEN** the annotation `"-r" ∈ {"-r", "-f", "/"} → yes` appears on the line
  containing `(anywhere "-r")` in the V1 source display

#### Scenario: Effect decision annotation
- **WHEN** a rule matches and produces `:deny "Recursive deletion from root"`
- **THEN** the annotation `→ :deny "Recursive deletion from root"` appears on
  the `(effect` line in the V1 source display

### Requirement: Source recovery uses pre-migration CST

The source recovery mechanism SHALL use pre-migration CstNodes stored on the
Config during transparent migration. Each rule is matched to its pre-migration
CstNode by span overlap, and the CstNode is converted to a Doc for display.

#### Scenario: Pre-migration CST stored during migration
- **WHEN** a config is loaded via `try_migrate_and_parse`
- **THEN** `config.pre_migration_cst` contains the CstNodes from before
  rewrite rules were applied

#### Scenario: Rule matched to pre-migration CstNode
- **WHEN** `rule.span` overlaps a pre-migration CstNode's span
- **THEN** that CstNode is used for display instead of the V2 AST Doc

#### Scenario: Native canonical config has no pre-migration CST
- **WHEN** a config parses directly as canonical syntax (no migration)
- **THEN** `config.pre_migration_cst` is `None`
- **AND** rendering uses the standard V2 AST Doc
