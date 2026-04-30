## 1. Core types

- [x] 1.1 Add `Profile` enum (`Gnu | SingleDashLong | LegacyBundle |
      KeyValue`) and `Convention { profile, flags_with_values }` to
      `crates/core/src/ast.rs`.
- [x] 1.2 Add `ArgsStyle { program: String, convention: Convention }` as a
      new top-level config item.
- [x] 1.3 Extend `Config` with `Vec<ArgsStyle>` field; getter
      `convention_for(command_name)` returning the resolved `Convention`
      (last declaration wins; `:gnu` fallback).

## 2. Config parsing

- [x] 2.1 Add `(args-style PROGRAM :PROFILE [:flags-with-values (...)])`
      parser in `crates/config/src/...`.
- [x] 2.2 Reject unknown profile keywords with a clear error.
- [x] 2.3 Warn (not error) on duplicate declarations for the same program.
- [x] 2.4 Round-trip tests via existing pretty-printer.

## 3. Failing tests first

- [x] 3.1 Integration test: `find . -name foo` with `(args-style "find"
      :single-dash-long)` and `(rule "find" (anywhere "-n"))` ⇒ no false
      match (no longer fires due to over-eager split).
- [x] 3.2 Integration test: `kubectl -n foo get pods` with `(args-style
      "kubectl" :gnu :flags-with-values ("-n"))` and `(rule "kubectl"
      (positional "get" "pods"))` ⇒ allow.
- [x] 3.3 Integration test: `tar xvzf archive.tgz` with `(args-style "tar"
      :legacy-bundle)` ⇒ first token recognised as a flag bundle.
- [x] 3.4 Integration test: `dd if=foo of=bar bs=1M` with `(args-style "dd"
      :key-value)` ⇒ tokens recognised as `key=value` flags.
- [x] 3.5 Integration test: command without `args-style` keeps `:gnu`
      behaviour byte-for-byte (regression baseline).

## 4. Tokeniser refactor

- [x] 4.1 Change `expand_combined_flags(args)` to
      `expand_combined_flags(args, convention)`. Implement profile
      branches.
- [x] 4.2 Change `positional_args(args)` to `positional_args(args,
      convention)`. Implement profile branches and apply
      `flags_with_values`.
- [x] 4.3 Update `evaluate_with_fold` to look up the convention from
      `Config` for the current command before tokenising.
- [x] 4.4 Update `Effect::MayI` recursion path to look up the inner
      command's convention (not the wrapper's).
- [x] 4.5 Update `predicates.rs` and `effects.rs` call sites to pass
      conventions through.

## 5. Property tests

- [x] 5.1 Property: `:gnu` profile + empty `flags_with_values` produces
      identical output to today's behaviour for arbitrary argv.
- [x] 5.2 Property: tokenisation is deterministic — same argv and
      convention always produce the same annotated stream.
- [x] 5.3 Property: `expand_combined_flags` under `:single-dash-long`
      never increases the token count (no splitting).

## 6. Trace and reference

- [x] 6.1 Trace renderer surfaces the resolved profile per evaluation
      (e.g. one-line "convention: :single-dash-long" header).
- [x] 6.2 Update `may-i reference` output with a Tokenisation section
      describing `args-style` and the four profiles.

## 7. Baseline shipped declarations

- [x] 7.1 Decide: ship baseline as built-in default (overridable) or as a
      separate `(load …)` file users opt into. Default: built-in.
- [x] 7.2 Add baseline declarations for `find`, `go`, `terraform`, `tar`,
      `dd` (and any others the team thinks are unambiguous).
- [x] 7.3 Documentation note in reference output that user declarations
      override the baseline.

## 8. Cleanup

- [x] 8.1 `cargo fmt`.
- [x] 8.2 `cargo tarpaulin`; inspect `lcov.info` for new uncovered branches
      and add targeted tests.
- [x] 8.3 Run user oracle: verify each failing case in §3 actually passes.
      (Oracle binary on PATH is the published `may-i 0.1.0`, which predates
      this change and rejects `args-style` as an unknown form. The §3
      cases are verified instead by `tests/arg_tokenisation.rs` against
      this branch's `may-i-engine`.)
- [x] 8.4 Update sample / docs configs in `examples/` if any reference
      single-dash-long tools without `args-style`. (No examples needed
      changes — `examples/ssh-sudo-prod-demo.lisp` does not reference
      `find`, `tar`, `go`, `terraform`, or `dd`.)
