## 1. Bug Fix

- [ ] 1.1 Delete `match_command_pattern` in `crates/engine/src/eval/effects.rs` and replace call sites with `CommandPattern::is_match`
- [ ] 1.2 Add test for nested Or pattern matching (e.g. `Or(vec![Or(vec![Literal("git"), Literal("hg")]), Literal("svn")])`)

## 2. Type Refinement — Core AST

- [ ] 2.1 Replace `Effect::Allow/Ask/Deny` with `Effect::Terminal { decision: Decision, reason: Option<String> }` in `crates/core/src/ast.rs`
- [ ] 2.2 Update all match sites across engine, config, annotation, and output modules to use `Effect::Terminal`
- [ ] 2.3 Merge `ArgPattern::Positional` and `ArgPattern::Exact` into `ArgPattern::Ordered { mode: MatchMode, patterns, continuation }` in `crates/core/src/pattern.rs`
- [ ] 2.4 Update config parsers and engine eval to use `ArgPattern::Ordered`
- [ ] 2.5 Remove `vector_syntax` from `FactQuery::Presence` in `crates/core/src/predicates.rs`; handle syntax choice in config parser layer only
- [ ] 2.6 Remove `source_text` and `pre_migration_forms` from `Config` in `crates/core/src/ast.rs`; create `LoadedConfig` wrapper in `src/`

## 3. Type Refinement — Engine Fold

- [ ] 3.1 Create `PositionalMatchKind` enum (Bind, ExprMatch, Cond, Wildcard) in `crates/engine/src/fold.rs`
- [ ] 3.2 Replace covarying `Option` fields in `PositionalElementDetail` with `kind: PositionalMatchKind`
- [ ] 3.3 Change `BindDetail.key` from `String` to `Keyword`
- [ ] 3.4 Update all fold consumers (annotation.rs, test generators) for new detail types

## 4. Deduplication — Engine

- [ ] 4.1 Delete `word_to_string` in `crates/engine/src/check.rs`; replace with `Word::to_str()`
- [ ] 4.2 Create shared `parse_simple_command(input: &str) -> Option<(String, Vec<String>)>` in shell-parser or engine; update `cmd_eval::parse_command_args` and `check::parse_check_command` to use it
- [ ] 4.3 Unify Positional/Exact eval branches in `crates/engine/src/eval/effects.rs` into single code path parameterised by `MatchMode`
- [ ] 4.4 Add `ArgMatchDetail::new(args, matched, elements)` constructor with default empty `search_tokens`

## 5. Deduplication — Core & Sexpr

- [ ] 5.1 Implement `FactPattern::to_source()` and `FactQuery::to_source()` via `to_doc()` + serialisation in `crates/core/src/predicates.rs`
- [ ] 5.2 Implement `CstNode::to_doc()` as `to_doc_with_trivia().map(|_| ())` in `crates/sexpr/src/cst.rs`

## 6. Deduplication — Config

- [ ] 6.1 Replace duplicate `Span` in `crates/config/src/migrate/mod.rs` with `may_i_core::Span`
- [ ] 6.2 Extract `tagged_list` and `rebuild_list` helpers in migrate module; refactor rewrite rules to use them
- [ ] 6.3 Extract `check_refs_defined` function in `crates/config/src/resolve.rs` to deduplicate undefined-ref error construction
- [ ] 6.4 Extract shared `parse_decision` function in `crates/config/src/config.rs` to deduplicate `:allow/:deny/:ask` parsing

## 7. Deduplication — Binary & Tests

- [ ] 7.1 Add `TracingFold::from_loaded_config(&LoadedConfig)` constructor; replace chained `.with_source_text().with_pre_migration_forms()` calls
- [ ] 7.2 Add `parse_json(output: &std::process::Output) -> serde_json::Value` helper in `tests/common/mod.rs`; update integration tests to use it

## 8. API Hygiene

- [ ] 8.1 Change `&String` → `&str` through the engine positional arg chain: `positional_args`, `match_positional_patterns`, `match_positional_recursive`, `match_expr_against_arg`, `match_args_contain`
- [ ] 8.2 Change `Effect::reason()` return type from `Option<&String>` to `Option<&str>`
- [ ] 8.3 Remove redundant `#[must_use]` attributes on `parse_config`, `parse_config_from_sexprs`, `evaluate` (all return Result)
- [ ] 8.4 Simplify `.prop_map(|children| list(children))` to `.prop_map(list)` in `src/output/render_rule.rs`
- [ ] 8.5 Remove stale "Task 2.10" comment in `crates/config/src/config.rs`
- [ ] 8.6 Tighten `pub` → `pub(crate)` on config submodules (`command`, `config`, `effect`, `pattern`, `predicate`, `rule`, `errors`)
- [ ] 8.7 Tighten `pub` → `pub(crate)` on engine internals where re-exports suffice
- [ ] 8.8 Remove unused `_pattern` parameter from `extract_inner_command` in `crates/engine/src/eval/effects.rs`
- [ ] 8.9 Clarify `insert_scalar`/`push` on `ContextFacts`: merge into single method or differentiate semantics
- [ ] 8.10 Replace `clone` + `clear` with `std::mem::take` in layout line accumulation (`crates/layout/src/lib.rs`)

## 9. Property Tests — High Priority

- [ ] 9.1 Add proptest: `parser::parse(arbitrary_string)` never panics (shell-parser crate)
- [ ] 9.2 Add proptests: config parsers (effect, predicate, command, rule) don't panic on generated CST
- [ ] 9.3 Add proptest: migration preserves eval semantics for configs with defines (extend `any_config()` generator)
- [ ] 9.4 Add proptest: `validate_and_resolve` never panics on arbitrary (rules, defines)
- [ ] 9.5 Add proptests: `Doc::map` identity and composition laws (create `any_doc()` generator)

## 10. Property Tests — Medium Priority

- [ ] 10.1 Add proptest: pretty-printer idempotency (`pretty(parse(pretty(doc, w)), w) == pretty(doc, w)`)
- [ ] 10.2 Add proptest: pretty-printer width monotonicity (narrower → more lines)
- [ ] 10.3 Add proptest: shell segment concatenation reproduces original input
- [ ] 10.4 Add proptest: `write_layout` never panics on arbitrary Layout + terminal width (create `any_layout()` generator)
- [ ] 10.5 Add proptests: `truncate_matched_anywhere` and `dim_unevaluated` idempotency
- [ ] 10.6 Add proptest: `ContextFacts::merge` commutativity
- [ ] 10.7 Add proptest: after successful `validate_and_resolve`, no `Named` predicates remain
- [ ] 10.8 Add proptest: `expand_combined_flags` output subset property
