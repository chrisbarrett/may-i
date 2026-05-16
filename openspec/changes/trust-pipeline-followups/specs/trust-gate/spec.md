## ADDED Requirements

### Requirement: Migration-driven rehash routes through the trust module

The trust module SHALL expose `rehash_after_migration() -> miette::Result<usize>` that loads the trust store, recomputes the canonical form for each entry, and saves the store. `cmd_migrate` SHALL call this function after applying migrations rather than calling `TrustStore::load` directly. The return value reports the number of entries whose hash changed.

The carve-out for `cmd_trust` calling `TrustStore::load` directly (see `Trust store loading is internal to the gate`) remains; `cmd_migrate` is not added to that carve-out — it routes through the new entry point instead.

#### Scenario: cmd_migrate does not load the trust store directly

- **WHEN** scanning `src/cmd_migrate.rs` for `TrustStore::load` references
- **THEN** zero references appear
- **AND** the post-migration rehash is implemented by a call to `crate::trust::rehash_after_migration`

#### Scenario: Rehash preserves approval status

- **WHEN** the trust store has an approved entry whose canonical form is recomputed identically (no change) during migration
- **THEN** `rehash_after_migration` leaves the entry untouched and does not count it as rehashed

#### Scenario: Rehash updates entries whose canonical form changed

- **WHEN** a migration changes the canonical form of an approved rule (so its old hash no longer matches the recomputed form)
- **THEN** `rehash_after_migration` replaces the entry's hash with the recomputed hash, preserves the approval status, and increments the rehashed-count return value
