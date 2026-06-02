# Tasks

## 1. Apply parser-bindings delta

- [x] 1.1 Apply the MODIFIED Requirement "Parser body is a form-list of declarations" from `specs/parser-bindings/spec.md` to `openspec/specs/parser-bindings/spec.md`: remove the `(tail …)` bullet from the recognised kinds list (line 595), add the legacy-form retirement paragraph, and add the "Legacy `(tail (after …))` parser-body fails at load" scenario.
- [x] 1.2 Apply the MODIFIED Requirement "`(authorise)` is the sole recursion verb" from `specs/parser-bindings/spec.md` to `openspec/specs/parser-bindings/spec.md`: rewrite the "Authorise inside tail" scenario's `GIVEN` (line 707) to use `(parser "sudo" (style gnu) (flags posix) (rest #cmd))`; clarify the bullet at line 694 to note the rest slice is scoped by `(flags MODE)`.

## 2. Verify and archive

- [x] 2.1 `openspec validate retire-tail-form-from-specs --strict` — expect clean.
- [x] 2.2 Run `scripts/validate-spec-frontmatter.sh` to confirm no frontmatter regressions.
- [x] 2.3 `rg "\(tail \(after" openspec/specs/parser-bindings/spec.md` hits only the retirement paragraph and the "Legacy `(tail (after …))` parser-body fails at load" scenario — no occurrences in the recognised-kinds list or the "Authorise inside tail" scenario.
- [x] 2.4 `cargo test` to confirm no scenarios that were previously documented as passing now describe behaviour the loader rejects (sanity check; no code changes expected).
- [ ] 2.5 Run `/opsx:archive retire-tail-form-from-specs` once tasks land.
