## REMOVED Requirements

The `config-load-surface` capability is removed in full. Its requirements document a one-shot internal refactor (removing a `LoadResult` wrapper struct) that has already landed. The Purpose was `TBD - created by archiving change deepen-loaded-config. Update Purpose after archive.` See design.md for rationale.

### Requirement: CLI consumes LoadResult directly
**Reason:** Describes code shape, not behaviour. The refactor has landed; if the wrapper pattern returns, the right response is a targeted `code-quality` requirement, not a resurrected capability spec.

### Requirement: User-facing behaviour preserved
**Reason:** Tautological — every refactor must preserve user-visible behaviour; this is not a per-capability requirement. Removed as boilerplate.
