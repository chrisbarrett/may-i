## 1. Fix env_or_default_path

- [ ] 1.1 Change `env_or_default_path` return type to `Result<Option<PathBuf>>` and error when `MAYI_CONFIG` is set but file doesn't exist
- [ ] 1.2 Update `resolve_path` caller to propagate the new error
- [ ] 1.3 Update existing unit tests in `io.rs` for the new error behavior

## 2. Integration test

- [ ] 2.1 Add integration test: `MAYI_CONFIG` env var pointing to nonexistent path exits 2 with descriptive error
