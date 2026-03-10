## 1. Parser and data model

- [ ] 1.1 Update check parsing to remove inline `(facts ...)` support and add `(with-facts FACTS ...BODY...)` forms within `(check ...)`.
- [ ] 1.2 Add parsing and validation for uniform fact-entry vectors, including presence entries, scalar entries, and duplicate-key detection within one fact literal.
- [ ] 1.3 Implement nested `with-facts` scope handling so inner scopes override outer fact bindings while preserving plain check assertions.

## 2. Diagnostics and evaluation

- [ ] 2.1 Emit warnings for empty fact vectors and empty `with-facts` bodies with clear source locations and guidance.
- [ ] 2.2 Preserve existing check evaluation behavior by resolving each assertion to an effective command plus context fact set after scope expansion.
- [ ] 2.3 Reject legacy inline `(facts ...)` check syntax with a migration-oriented error message pointing users to `with-facts`.

## 3. Docs and coverage

- [ ] 3.1 Update README and configuration docs to show `with-facts` examples, nested scopes, and uniform vector fact literals.
- [ ] 3.2 Add parser and engine tests covering scoped facts, nested overrides, duplicate-key errors, multiple `:via/*` facts, and warning cases.
- [ ] 3.3 Migrate existing built-in or sample check fixtures from inline `(facts ...)` syntax to `with-facts` and verify `may-i check` expectations still read clearly.
