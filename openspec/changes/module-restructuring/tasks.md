## 1. Core crate (`crates/core/`)

- [ ] 1.1 Create `ast/` directory; split `ast.rs` into `ast/mod.rs` (re-exports), `ast/spanned.rs`, `ast/effect.rs`, `ast/predicate.rs`, `ast/config.rs`
- [ ] 1.2 Move tests from `ast.rs` into their respective new files as inline `#[cfg(test)]` modules
- [ ] 1.3 Update `lib.rs` re-exports to use `ast::` paths; run `cargo check` on full workspace

## 2. Sexpr crate (`crates/sexpr/`)

- [ ] 2.1 Rename `span.rs` → `error.rs`; update `lib.rs` module declaration
- [ ] 2.2 Create `cst/` directory; split `cst.rs` into `cst/mod.rs` (types + methods + re-exports), `cst/parser.rs`, `cst/pretty.rs`, `cst/rewrite.rs`
- [ ] 2.3 Distribute tests from `cst.rs` into their respective new files
- [ ] 2.4 Update `lib.rs` re-exports; run `cargo check` on full workspace

## 3. PP crate (`crates/pp/`)

- [ ] 3.1 Create `format.rs` (Format, detect_column_width, snap_to_preset, line_prefix_width)
- [ ] 3.2 Create `color.rs` (SPECIAL_FORMS, is_* predicates, colorize_atom)
- [ ] 3.3 Create `output.rs` (PrettyOutput, OutputEvent, StringBuilder, EventBuffer, AnnotatedLine, AnnotatedLineBuilder)
- [ ] 3.4 Create `render.rs` (render engine, pretty, pretty_into, visible_len)
- [ ] 3.5 Move tests into `tests/` directory (helpers, render_tests, width_tests, prop_tests, annotated_line_tests)
- [ ] 3.6 Reduce `lib.rs` to re-exports only; run `cargo check` on full workspace

## 4. Shell-parser crate (`crates/shell-parser/`)

- [ ] 4.1 Create `ast/` directory; split `ast.rs` into `ast/mod.rs` (types), `ast/word.rs` (Word methods), `ast/helpers.rs` (abbreviate, format_param_op, try_fold_static_cat)
- [ ] 4.2 Create `lexer/` directory; split `lexer.rs` into `lexer/mod.rs` (Token, Lexer, tokenize), `lexer/word_parts.rs`, `lexer/param_expansion.rs`, `lexer/string_readers.rs`
- [ ] 4.3 Un-gate `glob.rs` and `resolve.rs` from `#[cfg(test)]`; make their public items `pub(crate)`
- [ ] 4.4 Dissolve `tests.rs` (3973 lines) into per-topic files under `tests/` (parse, word, redirect, expansion, glob, resolve, helpers)
- [ ] 4.5 Update `lib.rs`; clean up test-only helpers; run `cargo check` on full workspace

## 5. Config crate (`crates/config/`)

- [ ] 5.1 Create `parser/` directory; move `config.rs`, `rule.rs`, `effect.rs`, `predicate.rs`, `pattern.rs`, `command.rs` under it with `parser/mod.rs` re-exports
- [ ] 5.2 Tighten visibility: `parse_expr` → `pub(super)`, individual parse functions → `pub(crate)` within `parser/`
- [ ] 5.3 Create `resolve/` directory; split `resolve.rs` into `resolve/mod.rs`, `resolve/error.rs`, `resolve/define_map.rs`, `resolve/passes.rs`
- [ ] 5.4 Create `migrate/` directory; split `migrate.rs` into `migrate/mod.rs`, `migrate/rules.rs`, `migrate/driver.rs`, `migrate/analysis.rs`
- [ ] 5.5 Extract `keywords.rs` (centralise `is_reserved_keyword` + `is_reserved_define_name`)
- [ ] 5.6 Narrow `lib.rs` public API to 5 entry points; run `cargo check` on full workspace

## 6. Engine crate (`crates/engine/`)

- [ ] 6.1 Create `eval/` directory; split `eval.rs` into `eval/mod.rs`, `eval/context.rs`, `eval/evaluator.rs`, `eval/effects.rs`, `eval/positional.rs`, `eval/args.rs`, `eval/details.rs`
- [ ] 6.2 Move `build_fact_detail` from `fold.rs` into `eval/details.rs`
- [ ] 6.3 Extract test suites from `test_generators.rs` into `tests/` directory (predicate_props, effect_props, check_props, edge_cases, additional_props, fold_props, integration); leave only generators in `test_generators.rs`
- [ ] 6.4 Move unit tests from `eval.rs` into `tests/eval_unit.rs`
- [ ] 6.5 Update `lib.rs` re-exports; run `cargo check` on full workspace

## 7. Binary crate (`src/`)

- [ ] 7.1 Create `trace/` directory; split `annotation.rs` into `trace/mod.rs`, `trace/types.rs`, `trace/doc_builders.rs`, `trace/fold.rs`
- [ ] 7.2 Mark `trace/doc_builders.rs` functions as `pub(super)`
- [ ] 7.3 Split `output/transform.rs` into `output/reduce.rs` (truncate, dim) and `output/distribute.rs` (annotation redistribution)
- [ ] 7.4 Update all `crate::annotation` imports to `crate::trace`; update `output/` internal imports
- [ ] 7.5 Run `cargo check`, `cargo test`, and `cargo tarpaulin` on full workspace to verify no regressions
