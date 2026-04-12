## Context

`resolve_path(None)` delegates to `env_or_default_path()` which checks `MAYI_CONFIG` but silently ignores it when the path doesn't exist. Meanwhile `resolve_path(Some(p))` correctly errors on missing files. The two code paths should behave consistently.

## Goals / Non-Goals

**Goals:** Error when `MAYI_CONFIG` is set but the file doesn't exist.

**Non-Goals:** Changing behavior when `MAYI_CONFIG` is unset.

## Decisions

### Return an error from `env_or_default_path` instead of `Option`
Change the return type to `Result<Option<PathBuf>>` so it can distinguish "not set" (`Ok(None)`) from "set but missing" (`Err(...)`). The caller in `resolve_path` propagates the error.

Alternative: keep `Option` and add a separate validation step. Rejected because it splits the logic.

## Risks / Trade-offs

- Users who intentionally set `MAYI_CONFIG` to a not-yet-created path will now get an error. This is the correct behavior — explicit is better than silent fallthrough.
