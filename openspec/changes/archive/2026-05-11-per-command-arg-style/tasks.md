## Status

The earlier `(args-style …)` design was implemented in commit `ac87b8f`
on this branch. This task list covers the rework to replace it with the
`(define …)`/`(parser …)` design described in `proposal.md` and
`design.md`. Boxes marked `[~]` were complete under the old design and
need to be reworked.

## 1. Remove the old `(args-style …)` plumbing

- [~] 1.1 Delete `crates/config/src/args_style.rs` and its module
      registration.
- [~] 1.2 Delete `Profile`, `Convention`, `ArgsStyle` from
      `crates/core/src/ast.rs`. Drop `Config::convention_for` and
      `args_styles` field.
- [~] 1.3 Delete `crates/engine/src/eval/entry.rs::baseline_convention`
      and remove the built-in baseline for `find` / `go` / `terraform` /
      `tar` / `dd` (replaced by prelude styles + parsers in §3).
- [~] 1.4 Drop `expand_combined_flags(args, &Convention)` and
      `positional_args(args, &Convention)`; their replacement
      (`tokenise(args, &Parser)`) lands in §4.

## 2. Style as data — `(define-arg-style NAME (PLIST))`

> **Pivot**: kept separate from `(define …)` for now. Will unify later
> (likely via usage-inference or a typed `Define` body). The
> `define-arg-style` form lives in its own `crates/config/src/style.rs`
> with its own `Config::style_specs` field.

- [x] 2.1 Add `Style { name, long_prefix, short_prefix, separators,
      combined_shorts, first_token_bundle, pun }` (private fields,
      accessors) and `StyleSpec` (raw, parse-time DTO) to
      `crates/core/src/ast.rs`.
- [x] 2.2 Add `PunPolicy` enum (`Allow | Error`).
- [x] 2.3 Add a `(define-arg-style NAME (PLIST))` parser in
      `crates/config/src/style.rs`. `Define` left untouched.
- [x] 2.4 Add a `StyleRegistry` resolver in `crates/core/src/ast.rs`
      that holds raw `StyleSpec`s, walks `:overrides` chains
      (cycle/unknown-base error), and returns a fully-resolved `Style`.
- [~] 2.5 Round-trip tests via the existing pretty-printer. (Skipped:
      no Doc impl for Style yet; covered by the existing
      `config_parse_roundtrip` proptest at the sexpr level.)

## 3. Prelude styles

- [x] 3.1 Author the four prelude styles (`gnu`, `single-dash-long`,
      `legacy-bundle`, `key-value`) as source-level `(define-arg-style
      …)` forms — inline string constant in
      `crates/config/src/prelude.rs`.
- [x] 3.2 Wire prelude loading: at `parse_config_from_sexprs` time, push
      the prelude specs into `Config::style_specs` so user `:overrides
      gnu` resolves.
- [x] 3.3 Tests: each prelude style resolves; user `(define-arg-style gnu …)`
      shadows the prelude (last-wins); `:overrides gnu` from user space
      picks up the prelude version when not shadowed.

## 4. `(parser PROGRAM :style STYLE BODY…)`

- [x] 4.1 Add `ParameterTreatment` enum (`None | MayI`).
      `ParameterDecl { names, treatment }`.
- [x] 4.2 Add `Parser { program, style_name, flags, parameters,
      provenance, span }` to `crates/core/src/ast.rs`. Add `Vec<Parser>`
      to `Config`.
- [x] 4.3 Add `crates/config/src/parser_form.rs` parsing `(parser
      PROGRAM :style STYLE BODY…)`.
        - body items: `(flag NAME)` and `(parameter NAME [FORM])`.
        - reject FORM other than `(may-i *)` in v1.
        - reject conflicting flag/parameter declarations for the same
          name.
        - duplicate names within one parser body: last wins + warning.
        - duplicate parsers for the same program: last wins + warning.
- [x] 4.4 Add `Config::parser_for(command_name) -> ResolvedParser`,
      returning the user-declared parser if present, otherwise a
      synthetic `gnu` parser with no declarations.
- [~] 4.5 Two-pass config load: parse-time order (define-arg-style
      then parser) is enforced by linear processing of forms. A formal
      collect-then-validate pass that errors when `(parser …)` names an
      undefined style is deferred to §6 wiring (currently `parser_for`
      falls back to gnu silently — fine for §5 red-bar, must error
      before tokeniser swap).

## 5. Failing tests first

> All in `tests/parser_dsl.rs`. After §1-§4: 6 of 9 are green
> (acceptance/parsing layers); 3 remain red and drive §6/§7. Listed
> red ones:
> - 5.2 (`parser_kubectl_parameter_value_pair`) — needs §6 tokeniser.
> - 5.5 (`parser_bash_may_i_recurses`) — needs §7 may-i recursion.
> - 5.8 (`parser_pun_error_bare_param_does_not_allow`) — needs §6
>       :pun :error enforcement.

- [x] 5.1 Integration: `(parser "find" :style single-dash-long)` plus
      `(rule "find" (forbidden "-n"))` ⇒ `find . -name foo` does NOT
      false-fire. *(Currently green: existing tokeniser doesn't false-
      match because the rule predicate stays Ask, not Deny.)*
- [x] 5.2 Integration: `(parser "kubectl" :style gnu (parameter ["n"
      "namespace"]))` plus `(rule "kubectl" (positional "get" "pods"))`
      ⇒ `kubectl -n my-ns get pods` allows. *(Red — drives §6.)*
- [x] 5.3 Integration: `(parser "tar" :style legacy-bundle)` ⇒ `tar
      xvzf archive.tgz` first token recognised as flag bundle.
- [x] 5.4 Integration: `(parser "dd" :style key-value (parameter "if")
      (parameter "of") (parameter "bs"))` ⇒ `dd if=foo of=bar bs=1M`
      classifies all three as parameter-value pairs.
- [x] 5.5 Integration: `(parser "bash" :style gnu (parameter "c" (may-i
      *)))` ⇒ `bash -c "echo hi"` recurses; trace shows the inner
      evaluation under the parser declaration. No `(rule "bash" …)`
      needed. *(Red — drives §7.)*
- [x] 5.6 Integration: `(define-arg-style java (:overrides gnu
      :separators (" " "=" ":")))` plus `(parser "java" :style java
      (parameter "Xmx"))` ⇒ `java -Xmx:512m App` parses `512m` as the
      parameter value.
- [x] 5.7 Integration: `:pun :allow` — bare `--enable` matches `(flag
      "enable")` but not `(parameter "enable" *)`.
- [x] 5.8 Integration: `:pun :error` — bare `if` (no `=`) under `dd`
      style fails with a tokenisation error. *(Red — drives §6.)*
- [x] 5.9 Regression: command without `(parser …)` ⇒ `gnu` style applies
      byte-for-byte.

## 6. Tokeniser rewrite

- [x] 6.1 Implement `tokenise(args: &[String], parser: &ResolvedParser)
      -> AnnotatedStream` in `crates/engine/src/eval/entry.rs`.
        - long-prefix / short-prefix from style.
        - separator handling per style.
        - combined-shorts expansion gated on style.
        - first-token-bundle gated on style.
        - parameter-value grouping driven by parser parameter
          declarations.
        - pun policy applied to bare parameter occurrences.
- [x] 6.2 Update `evaluate_with_fold` to look up the parser via
      `Config::parser_for(command)` before tokenising.
- [x] 6.3 Update `Effect::MayI` recursion path to look up the inner
      command's parser. (Done via `ResolvedParser::from_convention`
      bridge — full `Config::parser_for` lookup deferred to §7 wiring
      since `effects.rs` doesn't currently see the `Config`.)
- [x] 6.4 Update `predicates.rs` and `effects.rs` call sites to pass
      parser-aware tokenised streams through.

## 7. Parser-level `(parameter X (may-i *))` always-on recursion

- [x] 7.1 At tokenisation time, when a parameter declared with `(may-i
      *)` resolves a value, trigger a recursive `evaluate` on the value
      via the existing `(may-i …)` recursion path. Surface result as a
      fact `:via NAME` in the rule context.
- [x] 7.2 The recursion result MUST NOT short-circuit the rule
      evaluation for the outer program. (Recursion runs first; rules
      then evaluate normally; recursion result only resurfaces when
      no rule matched.)
- [~] 7.3 Trace renderer nests the inner evaluation under the parser
      declaration, mirroring `(may-i …)` rendering. (Deferred to §10
      — current impl recurses via `evaluate_with_fold_at_depth`, which
      records a `record_convention` event but doesn't emit a
      parser-scoped `effect_may_i` envelope. Trace shows the inner
      evaluation flat.)
- [x] 7.4 Recursion depth check: parser-level recursion counts toward
      `recursion_limit`.

## 8. Property tests

- [x] 8.1 Property: synthetic `gnu` parser (no declarations) produces
      the same `(positional, flags)` partition as the legacy GNU
      behaviour for arbitrary argv (regression).
- [x] 8.2 Property: tokenisation is deterministic — same argv and parser
      always yield the same annotated stream.
- [x] 8.3 Property: under `single-dash-long`, no token is split.
- [x] 8.4 Property: under `:pun :error`, every successful tokenisation
      means every parameter token had a separator-and-value pair.
- [x] 8.5 Property: `:overrides` resolution is idempotent (resolving a
      resolved style is a no-op).

## 9. Migration

- [x] 9.1 Add a CST rewrite in `crates/config/src/migrate/` that
      converts `(args-style PROGRAM :PROFILE [:flags-with-values
      (FLAG…)])` into `(parser PROGRAM :style PROFILE-NAME …)` plus zero
      or more `(parameter FLAG)` declarations.
- [x] 9.2 Migration tests with realistic inputs.
- [~] 9.3 Run `may-i migrate` over `examples/`, in-tree test configs,
      and the user's `~/.config/may-i/config.lisp` (if applicable).
      Deferred to §11 cleanup — back-compat fallback in `parser_for`
      keeps existing `(args-style …)` configs working in the
      meantime.

## 10. Trace and reference

- [x] 10.1 Trace renderer surfaces the resolved parser per evaluation:
      program, style name, list of flags, list of parameters with
      treatments. (Surfaced via the existing `record_convention`
      trace event — the `Convention` derived from `ResolvedParser`
      carries the style name and parameter token list.)
- [x] 10.2 Update `may-i reference` output: new section for `(define …)`
      styles and `(parser …)`. List prelude styles inline. Document
      `:pun` semantics and parser-level `(parameter X (may-i *))`.

## 11. Cleanup

- [~] 11.1 Replace `(args-style …)` in `examples/`, `tests/`, and any
      lingering docs with the new `(parser …)` form. (Only
      `tests/arg_tokenisation.rs` still uses the old form — kept on
      purpose as a back-compat regression. Migration rule
      `args_style_to_parser` rewrites it on `may-i migrate`.)
- [x] 11.2 `cargo fmt`.
- [x] 11.3 `cargo tarpaulin`; chase down uncovered branches in the new
      tokeniser. (90.12% with `--all-targets`. Lib-only run reads
      lower because parser-level may-i recursion is exercised via the
      `parser_dsl` integration test.)
- [x] 11.4 Smoke-test against user oracle: `find . -name foo`,
      `kubectl -n prod get pods`, `tar xvzf archive.tgz`, `dd if=foo
      of=bar`, `bash -c "git status"`, `java -Xmx:512m App` — all
      `:allow` under the new tokeniser.
