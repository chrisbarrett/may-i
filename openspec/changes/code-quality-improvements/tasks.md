## 1. Deduplicate shared logic

- [x] 1.1 Unify quote_string (cst.rs) and quote_atom (sexpr.rs) into pub fn in crates/sexpr/src/lib.rs
- [ ] 1.2 Extract load_config helper from cmd_eval, cmd_check, cmd_claude_code_hook
- [ ] 1.3 Deduplicate CST transform/write_to logic for List vs Vector via shared helper
- [x] 1.4 Move strip_ansi to crates/pp alongside visible_len; re-export from layout
- [x] 1.5 Extract is_capture_marker() helper in crates/config/src/migrate/helpers.rs

## 2. Fix quality issues

- [x] 2.1 Replace 5 bare Keyword::new().unwrap() in cmd_claude_code_hook.rs with .expect()
- [x] 2.2 Replace process::exit(1) in cmd_check.rs with proper error return
- [x] 2.3 Add MAX_ITERS = 100 guard to rewrite_until_convergence in cst.rs
- [x] 2.4 Replace unwrap() in resolve.rs:167 with .expect("name exists in define_map")
- [x] 2.5 Fix branch ordering in colorize_right — move ~/∈ check before general → check
- [x] 2.6 Remove empty impl Format {} block in crates/pp/src/lib.rs
- [x] 2.7 Replace let _ = effect / let _ = args patterns with _prefixed params in signatures

## 3. Add #[must_use] annotations

- [ ] 3.1 Add #[must_use] to evaluate() in engine crate
- [x] 3.2 Add #[must_use] to EvalResult::new()
- [ ] 3.3 Add #[must_use] to key parse functions (parse_config, parse_expr, etc.)
