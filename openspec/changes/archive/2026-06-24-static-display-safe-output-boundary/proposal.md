## Why

Reasons were just hardened with a `DisplaySafe` newtype, but every other
terminal surface — traces, check failures, eval results, advisories, and the
miette error path — still interpolates input-derived text (command names, argv,
regex actuals, captured values, `(load)`ed config) into raw `String`s that reach
the TTY. Those strings legitimately carry our own ANSI/SGR (that is why
`strip_ansi`/`visible_len` exist), so the type system cannot distinguish our
declarative styling from an injected `\x1b` an adversary smuggled in via a
command name. The goal is to make user-controlled ANSI/SGR reaching a stream
**unrepresentable by construction**, not merely escaped at scattered call sites.

## What Changes

- **New escape choke points in `core`**: `SafeText` (control-escaping, expanding;
  generalises today's `engine::DisplaySafe`) and `SafeSource` (length-preserving
  control→placeholder scrub, for offset-addressed miette source). Single
  implementations both `engine` and `may-i-output` depend on. `DisplaySafe`
  becomes a re-export/alias.
- **Color-as-data rendering DSL**: `Layout` leaves hold `SafeText` content plus a
  closed semantic-role `Style` enum (e.g. `Keyword`, `StringLit`, `FormHead`,
  `Dimmed`, `Heading`, `MatchHit`, `MatchMiss`). The renderer is the **sole**
  emitter of `\x1b`, mapping roles to SGR at one site. **BREAKING** (internal):
  explicit `width`/`visible_width` fields on `ColItem`/`NoteHeading`/`HRuleLabel`
  are deleted — the renderer computes visible width from escape-free content.
  `strip_ansi`/`visible_len` become dead and are removed.
- **Single output sink**: one module owns every `stdout()/stderr()` handle and
  accepts only `Layout` (structured) or a `SafeText` line (simple diagnostics).
  The scattered `println!`/`eprintln!`/`stdout()` sites in `cmd_*` and `config`
  are routed through it.
- **miette input sanitisation**: the one spanned source (`shape_diag`) is wrapped
  in `SafeSource` (offset-preserving so spans stay aligned); flat `miette!`
  message interpolations go through `SafeText`. miette's own SGR is then trusted
  because its input is escape-free.
- **The gate (closing step)**: remove the `colored` dependency from the bin and
  `config` so an inline `.red()` outside the renderer is a *compile error*; deny
  `clippy::print_stdout`/`print_stderr`/`dbg_macro` workspace-wide with the sink
  module as the sole allow site; add a prek grep banning stream-handle
  acquisition (`io::stdout`/`stderr`, `console::Term::std*`, raw fd) outside the
  sink.
- **Falsifiable proof**: a color-off proptest drives adversarial input through
  every render surface and asserts zero control characters reach the sink; a
  color-on variant asserts every `\x1b` is a well-formed SGR from the role
  palette.

`may-i fmt`/`migrate`'s `pp` colorizer (`colorize_atom → String`) is the last
inline-ANSI island; it is folded onto roles in the same change after the
adversary-eval path is sealed, removing `colored` from `pp` last.

## Capabilities

### New Capabilities
- `display-safe-output`: the type-enforced terminal-output boundary —
  `SafeText`/`SafeSource` choke points, color-as-data `Style` roles as the sole
  ANSI source, the single sink owning all stream handles, miette input
  sanitisation, and the workspace gate (compile-error `colored` boundary + lint +
  prek grep) with the color-off proptest as its falsifiable companion. Bucket:
  `tracing-and-output`. Contributor-facing.

### Modified Capabilities
- `output-rendering`: `Layout` primitives become color-as-data (`SafeText`
  content + `Style` roles; width fields removed). The module's renderer-protocol
  surface drops `strip_ansi`/`visible_len`; the per-subcommand builders feed the
  single sink rather than raw writers.
- `code-quality`: add the output-boundary tooling invariants — `colored` is
  absent from every workspace crate (the renderer emits SGR directly);
  `clippy::print_stdout`/`print_stderr` denied with one allow site;
  stream-handle acquisition banned outside the sink.

## Impact

- **Crates**: `core` (new `SafeText`/`SafeSource`), `may-i-output` (color-as-data
  rewrite, raw-SGR renderer, single sink), `engine` (`DisplaySafe`→alias),
  `pp` (`Style` roles + span collector, `colored` removed), bin (`colored`
  removed, all `cmd_*` output through the sink, miette sanitisation).
- **Dependencies**: `colored` removed from every Cargo manifest — the renderer
  writes SGR directly, so no crate (including `may-i-output`) depends on it.
- **Tooling**: workspace `Cargo.toml` lints, prek hook (ast-grep structural
  scan), `ast-grep` added to the dev shell.
- **Tests**: new color-off / color-on proptests over the render surfaces;
  existing snapshot tests re-baseline (escaping now applied on trace surfaces).
- **No user-facing config syntax change** — no migration-system entry. Rendered
  output is unchanged except that control characters in input-derived text are
  now escaped.
