# Tasks: Migration Form-Wise Diff

## Implementation Tasks

- [x] Add `--yes` flag to CLI (src/main.rs)
- [x] Create migration diff types (crates/config/src/v2/migrate.rs)
- [x] Implement trivia extraction (crates/config/src/v2/migrate.rs)
- [x] Implement form change detection (crates/config/src/v2/migrate.rs)
- [x] Create PromptHandler trait (src/cmd_migrate.rs)
- [x] Implement diff rendering (src/cmd_migrate.rs)
- [x] Implement interactive prompt flow (src/cmd_migrate.rs)
- [x] Implement error span display (src/cmd_migrate.rs)
- [x] Fix false positives in unhandled case detection (crates/config/src/v2/migrate.rs)
- [x] Add integration tests (tests/migration_diff.rs)
- [x] Update documentation (README.md or docs/)
- [x] Run lint and type check

## Notes

See design.md for detailed specifications of each task.

### Dependencies
- No new external dependencies
- Reuse existing: `terminal_size`, `colored`, `may_i_pp`, `may_i_output`

### Estimated Effort
- Tasks 1-3: 2 hours
- Tasks 4-6: 4 hours
- Tasks 7-8: 3 hours
- Tasks 9-12: 3 hours
- **Total**: ~12 hours
