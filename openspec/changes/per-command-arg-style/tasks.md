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

## 2. Style as data — `(define NAME (PLIST))`

- [ ] 2.1 Add `Style { name, long_prefix, short_prefix, separators,
      combined_shorts, first_token_bundle, pun, overrides }` to
      `crates/core/src/ast.rs`. Provenance / span fields per existing
      conventions.
- [ ] 2.2 Add `PunPolicy` enum (`Allow | Error`).
- [ ] 2.3 Extend the existing `define` parser in
      `crates/config/src/define.rs` (or wherever `Define` lives) so its
      body can be a style PLIST. Keep fact-binding `define` working
      unchanged.
- [ ] 2.4 Add a `StyleRegistry` resolver in `crates/core/src/...` (or a
      new `style.rs`) that:
        - validates each style as it is added (unknown keys → error,
          unknown `:overrides` reference → error),
        - resolves `:overrides` chains (cycle detection → error),
        - returns a fully-resolved `ResolvedStyle` for a given name.
- [ ] 2.5 Round-trip tests via the existing pretty-printer.

## 3. Prelude styles

- [ ] 3.1 Author the four prelude styles (`gnu`, `single-dash-long`,
      `legacy-bundle`, `key-value`) as source-level `(define …)` forms
      in a new `crates/config/src/prelude/styles.lisp` (or inline as a
      string constant if file embedding is preferred).
- [ ] 3.2 Wire prelude loading: at `Config::new` time, parse the prelude
      source into the same `StyleRegistry` so user `:overrides gnu`
      resolves.
- [ ] 3.3 Tests: each prelude style resolves; user `(define gnu …)` shadows
      the prelude with a warning; `:overrides gnu` from user space picks
      up the prelude version when not shadowed.

## 4. `(parser PROGRAM :style STYLE BODY…)`

- [ ] 4.1 Add `ParameterTreatment` enum (`None | MayI`).
      `ParameterDecl { names, treatment }`.
- [ ] 4.2 Add `Parser { program, style_name, flags, parameters,
      provenance, span }` to `crates/core/src/ast.rs`. Add `Vec<Parser>`
      to `Config`.
- [ ] 4.3 Add `crates/config/src/parser_form.rs` parsing `(parser
      PROGRAM :style STYLE BODY…)`.
        - body items: `(flag NAME)` and `(parameter NAME [FORM])`.
        - reject FORM other than `(may-i *)` in v1.
        - reject conflicting flag/parameter declarations for the same
          name.
        - duplicate names within one parser body: last wins + warning.
        - duplicate parsers for the same program: last wins + warning.
- [ ] 4.4 Add `Config::parser_for(command_name) -> ResolvedParser`,
      returning the user-declared parser if present, otherwise a
      synthetic `gnu` parser with no declarations.
- [ ] 4.5 Two-pass config load: collect all `(define …)` styles and
      `(parser …)` declarations first, then validate rules. Surface a
      clear error if a `(parser …)` references an undefined style.

## 5. Failing tests first

- [ ] 5.1 Integration: `(parser "find" :style single-dash-long)` plus
      `(rule "find" (forbidden "-n"))` ⇒ `find . -name foo` does NOT
      false-fire.
- [ ] 5.2 Integration: `(parser "kubectl" :style gnu (parameter ["n"
      "namespace"]))` plus `(rule "kubectl" (positional "get" "pods"))`
      ⇒ `kubectl -n my-ns get pods` allows.
- [ ] 5.3 Integration: `(parser "tar" :style legacy-bundle)` ⇒ `tar
      xvzf archive.tgz` first token recognised as flag bundle.
- [ ] 5.4 Integration: `(parser "dd" :style key-value (parameter "if")
      (parameter "of") (parameter "bs"))` ⇒ `dd if=foo of=bar bs=1M`
      classifies all three as parameter-value pairs.
- [ ] 5.5 Integration: `(parser "bash" :style gnu (parameter "c" (may-i
      *)))` ⇒ `bash -c "echo hi"` recurses; trace shows the inner
      evaluation under the parser declaration. No `(rule "bash" …)`
      needed.
- [ ] 5.6 Integration: `(define java (:overrides gnu :separators (" "
      "=" ":")))` plus `(parser "java" :style java (parameter "Xmx"))`
      ⇒ `java -Xmx:512m App` parses `512m` as the parameter value.
- [ ] 5.7 Integration: `:pun :allow` — bare `--enable` matches `(flag
      "enable")` but not `(parameter "enable" *)`.
- [ ] 5.8 Integration: `:pun :error` — bare `if` (no `=`) under `dd`
      style fails with a tokenisation error.
- [ ] 5.9 Regression: command without `(parser …)` ⇒ `gnu` style applies
      byte-for-byte.

## 6. Tokeniser rewrite

- [ ] 6.1 Implement `tokenise(args: &[String], parser: &ResolvedParser)
      -> AnnotatedStream` in `crates/engine/src/eval/entry.rs`.
        - long-prefix / short-prefix from style.
        - separator handling per style.
        - combined-shorts expansion gated on style.
        - first-token-bundle gated on style.
        - parameter-value grouping driven by parser parameter
          declarations.
        - pun policy applied to bare parameter occurrences.
- [ ] 6.2 Update `evaluate_with_fold` to look up the parser via
      `Config::parser_for(command)` before tokenising.
- [ ] 6.3 Update `Effect::MayI` recursion path to look up the inner
      command's parser.
- [ ] 6.4 Update `predicates.rs` and `effects.rs` call sites to pass
      parser-aware tokenised streams through.

## 7. Parser-level `(parameter X (may-i *))` always-on recursion

- [ ] 7.1 At tokenisation time, when a parameter declared with `(may-i
      *)` resolves a value, trigger a recursive `evaluate` on the value
      via the existing `(may-i …)` recursion path. Surface result as a
      fact `:via NAME` in the rule context.
- [ ] 7.2 The recursion result MUST NOT short-circuit the rule
      evaluation for the outer program.
- [ ] 7.3 Trace renderer nests the inner evaluation under the parser
      declaration, mirroring `(may-i …)` rendering.
- [ ] 7.4 Recursion depth check: parser-level recursion counts toward
      `recursion_limit`.

## 8. Property tests

- [ ] 8.1 Property: synthetic `gnu` parser (no declarations) produces
      the same `(positional, flags)` partition as the legacy GNU
      behaviour for arbitrary argv (regression).
- [ ] 8.2 Property: tokenisation is deterministic — same argv and parser
      always yield the same annotated stream.
- [ ] 8.3 Property: under `single-dash-long`, no token is split.
- [ ] 8.4 Property: under `:pun :error`, every successful tokenisation
      means every parameter token had a separator-and-value pair.
- [ ] 8.5 Property: `:overrides` resolution is idempotent (resolving a
      resolved style is a no-op).

## 9. Migration

- [ ] 9.1 Add a CST rewrite in `crates/config/src/migrate/` that
      converts `(args-style PROGRAM :PROFILE [:flags-with-values
      (FLAG…)])` into `(parser PROGRAM :style PROFILE-NAME …)` plus zero
      or more `(parameter FLAG)` declarations.
- [ ] 9.2 Migration tests with realistic inputs.
- [ ] 9.3 Run `may-i migrate` over `examples/`, in-tree test configs,
      and the user's `~/.config/may-i/config.lisp` (if applicable).

## 10. Trace and reference

- [ ] 10.1 Trace renderer surfaces the resolved parser per evaluation:
      program, style name, list of flags, list of parameters with
      treatments.
- [ ] 10.2 Update `may-i reference` output: new section for `(define …)`
      styles and `(parser …)`. List prelude styles inline. Document
      `:pun` semantics and parser-level `(parameter X (may-i *))`.

## 11. Cleanup

- [ ] 11.1 Replace `(args-style …)` in `examples/`, `tests/`, and any
      lingering docs with the new `(parser …)` form.
- [ ] 11.2 `cargo fmt`.
- [ ] 11.3 `cargo tarpaulin`; chase down uncovered branches in the new
      tokeniser.
- [ ] 11.4 Smoke-test against user oracle: `find . -name foo`,
      `kubectl -n prod get pods`, `tar xvzf archive.tgz`, `dd if=foo
      of=bar`, `bash -c "git status"`, `java -Xmx:512m App`.
