## Why

Config-dependent commands (eval, check) currently fail on legacy v1 configs that haven't been migrated. Users must manually run `may-i migrate` before using these commands. By transparently migrating configs at load time, we maintain backward compatibility while encouraging users to migrate permanently. Error diagnostics must remain accurate—spans in error messages must point to the original source locations, not the migrated text.

## What Changes

- Modify `config::load()` to transparently migrate legacy configs when normal parsing fails
- Extract `parse_config_from_sexprs()` from `parse_config()` to enable parsing from migrated Sexpr forms
- Log a warning to stderr when auto-migration is applied: "Config auto-migrated from legacy format. Run `may-i migrate` to update permanently."
- Preserve source spans through migration chain: CST → migrate → Sexpr → AST
- If migration also fails, return the original parse error (not the migration error)

## Capabilities

### New Capabilities
- `transparent-config-migration`: Automatic fallback migration for all config-dependent commands with accurate source location reporting

### Modified Capabilities
None—this is purely an implementation enhancement that preserves existing behavior and requirements.

## Impact

- **crates/config/src/io.rs**: `load()` function modified to support transparent migration
- **crates/config/src/config.rs**: New `parse_config_from_sexprs()` function extracted
- **All config-dependent commands**: eval, check, and future commands automatically benefit
- **No API changes**: Public interface remains unchanged; behavior is additive
- **Performance**: Negligible—only activates on parse failure (legacy configs)
