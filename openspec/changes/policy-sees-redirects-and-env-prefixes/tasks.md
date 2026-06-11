## 1. Surface redirects and env prefixes to evaluation (engine)

- [x] 1.1 Write failing eval scenarios: `echo x > /home/u/.ssh/authorized_keys` under `(rule "echo" (allow))` floors to at least `:ask` naming the target; `echo x > /dev/null` and `echo x 2>&1` stay `:allow`; `echo x > /tmp/$NAME` floors; heredoc/herestring redirections do not floor on their own.
- [x] 1.2 Floor on a redirect to a non-standard file target in command evaluation, reusing the raise-to-ask combinator with a reason naming the operator and target.

## 2. Env-assignment prefixes gate the decision (engine + config)

- [x] 2.1 Write failing eval scenarios: `LD_PRELOAD=/evil.so git status` under `(rule "git" (allow))` floors naming `LD_PRELOAD`; `GIT_PAGER=cat git status` with `(safe-env-vars "GIT_PAGER")` in the primary config stays `:allow`; mixed prefixes floor if any name is not allowlisted; with no `(safe-env-vars …)` form, every prefix floors.
- [x] 2.2 Compute the effective safe-env-vars set at evaluation: primary-config entries always; loaded-file entries only when the `:safe-env-vars` trust scope is approved (inert otherwise).
- [x] 2.3 Write failing trust scenario: a `(load …)`-included `(safe-env-vars "FOO")` without trust approval leaves `FOO=bar cmd` flooring to `:ask`.
- [x] 2.4 Floor on a non-allowlisted prefix name, reusing the raise-to-ask combinator with a reason naming the variable.

## 3. Properties

- [x] 3.1 Proptest: a command with any file-target redirect (target ≠ `/dev/null`, not an fd dup) never evaluates to `:allow`.
- [x] 3.2 Proptest: a command with any env prefix whose name is outside the effective set never evaluates to `:allow`; floors only raise strictness (`:deny` unchanged).

## 4. Verify

- [x] 4.1 `cargo fmt`; `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] 4.2 `cargo test --workspace` green; check in any new `proptest-regressions/`.
- [x] 4.3 Re-run the confirmed bypasses against the built binary: the redirect and `LD_PRELOAD` cases now `:ask`.
- [ ] 4.4 `cargo tarpaulin`; inspect `lcov.info` for uncovered branches in the new floors.
