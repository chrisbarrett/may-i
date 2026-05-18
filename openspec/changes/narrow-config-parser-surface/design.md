## Context

`crates/config/src/lib.rs` exports a parsing kit: one fn per surface form (`parse_rule`, `parse_define`, `parse_parser_form`, `parse_style_definition`, `parse_command_pattern`, `parse_rule_body`) plus the whole-config entries (`parse_config`, `parse_config_from_sexprs`, `parse_config_from_tagged_sexprs`), loader helpers, canonicalisation, and a few discovery helpers. The lib.rs comment for `parse_rule_body` reads:

> This is the **only** public entry point for rule-body parsing; the sub-parsers it dispatches to … are crate-internal and produce contributor-vocabulary types (`Effect`, `Predicate`, `ArgPattern`) that intentionally do not leak past the config crate's API seam.

The intent is sound. The execution is partial: `parse_define` returns `Spanned<Define>`, `parse_parser_form` returns `Parser`, `parse_style_definition` returns `Spanned<Style>` — all contributor types — and each is publicly callable even though no one calls them.

Workspace grep across `src/`, `crates/` (excluding `crates/config/`), and `tests/`:

| Export                  | External callers                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------ |
| `parse_rule`            | `src/trust/rehash.rs`                                                                            |
| `parse_config*`         | tests + `crates/engine/src/trust.rs` + `src/output/mod.rs`                                       |
| `parse_define`          | none                                                                                             |
| `parse_parser_form`     | none                                                                                             |
| `parse_style_definition`| none                                                                                             |
| `parse_command_pattern` | none                                                                                             |
| `parse_rule_body`       | none                                                                                             |
| `canonicalise_forms`    | `src/cmd_fmt.rs`                                                                                 |
| `canonicalise_node`     | none                                                                                             |
| `LoadResult`            | `src/{pipeline,annotation,cmd_eval,cmd_check}.rs`, `src/trust/mod.rs`, `tests/`                  |
| `ConfigError`           | `src/cmd_migrate.rs`                                                                             |
| `load*`, `walk_load_graph`, `discover_repo_*`, `resolve_path` | `src/{cmd_fmt,cmd_migrate}.rs` and integration tests             |

## Goals / Non-Goals

**Goals:**
- Reduce the config crate's public seam to items with at least one external caller.
- Stop leaking contributor types (`Define`, `Parser`, `Style`, `CommandPattern`, `Effect` via `parse_rule_body`) through the seam.
- Encode the narrowed surface in the `code-quality` spec so re-widening is a deliberate choice.

**Non-Goals:**
- Restructuring the parsers themselves. This is a visibility-only change.
- Touching `parse_rule` — there is a legitimate external caller (`src/trust/rehash.rs` re-parses single rules during rehash).
- Folding `parse_config_from_sexprs` and `parse_config_from_tagged_sexprs` into one entry point. They cover distinct provenance flows; consolidation is a separate refactor.
- Replacing the `parse_*` shape with a builder/typed-form API. Useful future direction but not in scope for the visibility narrowing.

## Decisions

### Per-export demotion

Each unused export gets `pub use` → `pub(crate) use` (or the underlying `pub fn` → `pub(crate) fn`). Alternative: delete `parse_rule_body` entirely, since it merely wraps `parse_effect`. Rejected because the wrapper is small and the narrowed-seam framing in its doc comment is still load-bearing for contributors browsing the crate.

### Keep the loader/discovery surface public

`discover_repo_root` and friends have callers in `cmd_fmt` and `cmd_migrate`. A future refactor could route them through `load_and_resolve` so they become internal, but the layering doesn't fit today — `cmd_fmt` needs the discovery output *without* loading or resolving. Keeping them public is the honest call.

### Anchor in `code-quality`

Same rationale as the engine-surface change: one contributor-internals spec collects crate-surface invariants. The two changes can be applied in either order; their delta files touch different requirements.

## Risks / Trade-offs

- **Risk**: An unnoticed external caller exists. → **Mitigation**: `cargo check --workspace`. Reversible per-item.
- **Trade-off**: A future contributor wanting to drive a single-form parser from outside the crate must either add a `pub(crate)` carve-out (with spec backing) or extend the supported config entry. This is the intended deepening — ad-hoc reach-through becomes a deliberate seam change.
