## 1. Check subcommand tests

- [x] 1.1 Create tests/check_integration.rs
- [x] 1.2 Write test: check with valid config exits 0
- [x] 1.3 Write test: check with failing checks exits non-zero
- [x] 1.4 Write test: check --verbose shows additional output

## 2. Parse subcommand tests

- [x] 2.1 Create tests/parse_integration.rs
- [x] 2.2 Write test: parse with valid shell command exits 0 and shows structure
- [x] 2.3 Write test: parse with --file flag reads from file

## 3. Migrate subcommand tests

- [x] 3.1 Create tests/migrate_integration.rs
- [x] 3.2 Write test: migrate v1 config as subprocess produces valid v2 output
- [x] 3.3 Write test: migrate already-v2 config reports no changes

## 4. Eval and hook additional coverage

- [x] 4.1 Add test to tests/eval_stdin.rs: eval with --fact flags uses provided facts
- [x] 4.2 Add test to tests/hook_integration.rs: hook with --json flag produces valid JSON
- [x] 4.3 Add test: MAYI_CONFIG pointing to nonexistent file produces descriptive error
