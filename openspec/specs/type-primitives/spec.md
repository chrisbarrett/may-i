## MODIFIED Requirements

### Requirement: Core types available in primitives module
The primitives module SHALL provide `Decision` enum (Allow, Ask, Deny), `ToDoc` trait, and `Keyword` struct. (CHANGED: `ContextValue` is no longer a primitive type — facts are stored as sets directly in `ContextFacts`)

#### Scenario: Decision enum has three variants
- **WHEN** matching on `Decision`
- **THEN** the variants SHALL be `Allow`, `Ask`, and `Deny`

#### Scenario: Keyword validates colon prefix
- **WHEN** creating a `Keyword` with `":ssh/host"`
- **THEN** construction SHALL succeed

#### Scenario: Keyword rejects missing colon
- **WHEN** creating a `Keyword` with `"ssh/host"`
- **THEN** construction SHALL fail

## REMOVED Requirements

### Requirement: ContextValue enum in primitives
**Reason**: Replaced by set-based fact model where all facts are `Map<Keyword, Set<String>>`
**Migration**: Use `ContextFacts` methods directly instead of matching on `ContextValue::Present`/`ContextValue::Scalar`
