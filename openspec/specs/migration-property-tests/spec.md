## Requirements

### Requirement: Canonical configs are a fixed point of migration
For any valid canonical config source text, migrating the CST and converting back to Sexpr SHALL produce a structurally identical Sexpr (ignoring spans) to parsing the original source directly.

#### Scenario: Simple rule is unchanged
- **WHEN** a canonical config `(rule "git" (effect :allow))` is parsed as CST and migrated
- **THEN** the migrated Sexpr equals the directly-parsed Sexpr

#### Scenario: Rule with when-conditional is unchanged
- **WHEN** a canonical config `(rule "git" (when (fact? :key) (effect :allow)))` is parsed as CST and migrated
- **THEN** the migrated Sexpr equals the directly-parsed Sexpr

#### Scenario: Property — random canonical configs are unchanged
- **WHEN** a randomly-generated canonical config string is parsed as CST and migrated
- **THEN** each migrated form's Sexpr equals the directly-parsed form's Sexpr

### Requirement: Migration is idempotent
For any CST input, applying migration twice SHALL produce the same serialized output as applying it once.

#### Scenario: Property — migrate(migrate(e)) equals migrate(e)
- **WHEN** a config string is parsed as CST, migrated, serialized, re-parsed as CST, and migrated again
- **THEN** the second migration's serialized output is identical to the first

### Requirement: Migration output is parseable
For any valid v1 config source, the migrated output SHALL parse successfully with the canonical config parser.

#### Scenario: Property — migrated v1 configs parse as canonical
- **WHEN** a randomly-generated v1 config string is parsed as CST, migrated, and serialized
- **THEN** `parse_config` on the serialized output returns `Ok`

### Requirement: Migration preserves evaluation semantics
For any v1 config and any evaluation context (command, args, facts), evaluating the config before and after migration SHALL produce the same decision.

#### Scenario: command-wrapper simplification preserves eval
- **WHEN** a v1 config `(rule (command "X") (effect :allow))` is migrated to `(rule "X" (effect :allow))`
- **THEN** evaluating both with command "X" produces the same decision

#### Scenario: defcontext-to-define preserves eval
- **WHEN** a v1 config `(defcontext name (has :key))` is migrated to `(define name (fact? :key))`
- **THEN** both configs resolve the name predicate identically

#### Scenario: Property — random v1 configs evaluate identically after migration
- **WHEN** a randomly-generated v1 config and its expected canonical equivalent are both parsed
- **AND** both are evaluated with the same random (command, args, facts)
- **THEN** the evaluation decisions are equal

### Requirement: Migration converges
For any valid s-expression input, the migration rewrite loop SHALL terminate.

#### Scenario: Property — migration terminates for random inputs
- **WHEN** a randomly-generated s-expression string is parsed as CST and migration is applied
- **THEN** migration completes without hanging (within bounded time)
