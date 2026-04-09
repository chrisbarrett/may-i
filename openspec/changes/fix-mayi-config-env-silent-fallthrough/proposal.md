## Why

When `MAYI_CONFIG` env var points to a nonexistent path, the tool silently falls through to the default/starter config. A typo in `MAYI_CONFIG` goes undetected, leading to unexpected "allow" decisions from the starter config instead of the user's rules.

## What Changes

- Error when `MAYI_CONFIG` is set but the referenced file doesn't exist, matching the `--config` CLI flag behavior
- Add integration test covering this case

## Capabilities

### New Capabilities

### Modified Capabilities

## Impact

- `crates/config/src/io.rs` — `env_or_default_path()` function (lines 104-113)
- Integration tests in `tests/`
