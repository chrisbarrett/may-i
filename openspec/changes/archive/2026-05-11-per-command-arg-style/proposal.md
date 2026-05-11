## Why

A single hard-coded GNU-ish convention (`expand_combined_flags` +
`positional_args` in `crates/engine/src/eval/entry.rs`) governs how every
command's argv is split into flags, flag values, and positional arguments.
This default is wrong for several large families of CLI tools:

- **Single-dash-long** tools (`find`, `go`, `java`, `terraform`) — the
  parser splits `-name` into `-n -a -m -e`. A rule like `(forbidden "-n")`
  then fires falsely against any `-name X` argument.
- **GNU tools with value-bearing short flags** (`kubectl -n NS`, `bash -c
  CMD`) — `positional_args` strips `-n`/`-c` but leaves the value
  `NS`/`CMD` floating in the positional stream. Rules expecting
  `(positional "get" "pods")` silently fail when the user types `kubectl -n
  foo get pods`.
- **Legacy bundled** tools (`tar xvzf archive.tgz`, `ps aux`) — first-token
  flag clusters without a leading dash are treated as positional verbs.
- **Key=value** tools (`dd if=foo of=bar bs=1M`) — every token is
  positional; no flag/positional split happens at all.
- **Overloaded parameters** (`--enable`, `--enable=true`, `--enable true`)
  — no way to express "this option has an optional value, separated by
  whitespace, `:`, or `=`".

The earlier in-flight design used `(args-style PROGRAM :PROFILE …)` with a
fixed set of profile keywords. That conflated two concerns — *how flags
are spelled* and *which options on this program take values* — and gave no
hook for per-program semantic facts like "the value of `bash -c` should
always be re-authorised".

This change replaces it with two cooperating forms:

- `(define NAME (PLIST))` — declare a named parsing **style** as data.
  The prelude ships common styles (`gnu`, `single-dash-long`,
  `legacy-bundle`, `key-value`); users can derive their own via
  `:overrides`.
- `(parser PROGRAM :style STYLE BODY…)` — declare how a program's argv is
  parsed. `BODY` is a sequence of parser-scoped `(flag …)` and
  `(parameter …)` declarations describing per-option treatment, including
  auto-recursion into `(may-i *)` for command-bearing options.

This separates the **parsing DSL** (here) from the **authorisation DSL**
(rules). Rules then talk about *what the user is trying to do* without
also having to teach the tokeniser how to read the command line.

## What Changes

- **New top-level form** `(define NAME (PLIST))` — declares a named style
  as a property list. Styles are first-class data: bind once, reference by
  name from any number of `(parser …)` declarations.
- **Prelude-shipped styles**:
  - `gnu` — `--long`, short combine, `--long=val` / `--long val`,
    `:pun :allow` (bare `--enable` is value-less presence).
  - `single-dash-long` — every `-foo` is a long flag; no combining; value
    via `-foo val` or `-foo=val`; `:pun :allow`.
  - `legacy-bundle` — `:overrides gnu :first-token-bundle t`.
  - `key-value` — only `key=value` tokens are flag-equivalent; `:pun
    :error` (bare key is invalid).
- **Style PLIST keys** (initial set):
  - `:long-prefix` / `:short-prefix` — string prefix for long/short flags
    (default `"--"` / `"-"`).
  - `:separators` — list of separator strings allowed between a parameter
    and its value (e.g. `(" " "=")` for GNU; `(" " "=" ":")` for
    Java-style).
  - `:combined-shorts` — boolean; whether `-rf` expands to `-r -f`.
  - `:first-token-bundle` — boolean; whether the first non-dashed alpha
    cluster is treated as a flag bundle (`tar xvzf`).
  - `:pun` — `:allow` | `:error`. Decides what a bare parameter
    occurrence (no value, no separator) means: `:allow` ⇒ present-as-flag
    with no value (matches `(flag X)` only); `:error` ⇒ tokenisation
    error.
  - `:overrides STYLE-NAME` — derive from `STYLE-NAME`, replacing keys
    listed in this PLIST. List-valued keys *replace*, not merge.
- **New top-level form** `(parser PROGRAM :style STYLE-NAME BODY…)` —
  declares the parsing rules for `PROGRAM`. `BODY` is a sequence of:
  - `(flag NAME)` — declare `NAME` as a pure boolean flag (never takes a
    value).
  - `(parameter NAME [FORM])` — declare `NAME` as a value-bearing
    parameter. `NAME` may be a string or a `[short long]` vector. The
    optional `FORM` is the *parser-level* treatment of the value:
    - omitted ⇒ the parser merely registers `NAME` as value-bearing, so
      the tokeniser groups `-N VAL` correctly.
    - `(may-i *)` ⇒ every occurrence of this parameter has its value
      parsed as a command line and re-authorised. No corresponding rule
      needed — this is parser-level always-on behaviour.
    - any other expression ⇒ reserved for future expansion (e.g.
      type-checked values).
- **Removed**: `(args-style PROGRAM :PROFILE [:flags-with-values …])`.
  Replaced wholesale by `(parser …)` and the prelude styles.
- **Default fallback** — programs without a `(parser …)` declaration use
  the `gnu` style with no parameter declarations.
- **Recursion via `(may-i …)`** — the inner command's parser applies to
  the inner argv (lookup is by `ctx.command`, which already swaps on
  recursion).

## Capabilities

### New Capabilities

- `command-parser-declarations`: per-program parsing DSL covering style
  selection, parser-scoped option declarations, and parser-level
  always-on behaviour (auto-recurse).

### Removed Capabilities

- `arg-tokenisation` (proposed by the earlier draft of this change) is
  withdrawn in favour of `command-parser-declarations`. No spec was
  archived to `openspec/specs/`, so nothing to deprecate publicly.

### Modified Capabilities

- `pattern-expressions` continues to operate on the (now parser-aware)
  annotated stream. The rule-level `(parameter X FORM)` form keeps its
  value-matching semantics and is unchanged. The implicit value-bearing
  flag registration done from rule-level `(parameter …)` can be retired
  in favour of explicit parser-level declarations (separate change if
  desired).

## Impact

- `crates/core/src/ast.rs` — replace `ArgsStyle` / `Profile` /
  `Convention` with `Style { name, plist }` and `Parser { program,
  style_name, declarations }`. Add a style-registry resolver.
- `crates/config/src/...` — replace `args_style.rs` with `parser.rs` and
  `style.rs`; reuse the existing `define` parser for the new style form.
- `crates/config/src/prelude/...` — ship the four built-in styles as
  source-level definitions loaded automatically.
- `crates/engine/src/eval/entry.rs` — tokeniser consults the resolved
  parser (style + parameter declarations) for the current command.
  Replace `expand_combined_flags(args, &Convention)` and
  `positional_args(args, &Convention)` with a unified `tokenise(args,
  &Parser)`. Implement `:pun`, `:separators`, `:combined-shorts`,
  `:first-token-bundle`, `:long-prefix` / `:short-prefix`.
- `crates/engine/src/eval/effects.rs` — for `(parameter X (may-i *))` at
  parser level, automatically re-authorise the value at tokenisation
  time, before rule evaluation. Surface as a virtual fold event so traces
  show the recursion.
- `crates/config/src/migrate/` — drop the `(args-style …)` parser; add a
  one-shot migration that rewrites any in-repo configs still using the
  old form.
- `tests/` — rewrite `arg_tokenisation.rs` against the new DSL; add tests
  for `:pun`, custom `(define …)` styles, parser-level `(parameter X
  (may-i *))`.
- `openspec/specs/command-parser-declarations/spec.md` — created by this
  change.
- `openspec/specs/pattern-expressions/spec.md` — minor edit noting that
  parser-level declarations can subsume the rule-level implicit
  value-bearing registration.

## Dependencies

- Supersedes the in-flight `(args-style …)` implementation already
  committed on this branch (commit `ac87b8f`). That code is removed and
  replaced as part of this change's task list.
- Independent of `flag-and-parameter-patterns` for design, but that
  change's rule-level `(flag X)` and `(parameter X FORM)` forms are still
  required: they are how rules consume the parser-annotated stream.
