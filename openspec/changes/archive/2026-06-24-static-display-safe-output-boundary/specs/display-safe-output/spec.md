## ADDED Requirements

### Requirement: Display text has a single escaping choke point

A type `SafeText` SHALL be the only representation of input-derived text that
reaches a terminal-output surface. `SafeText` SHALL have a private field and a
single constructor that control-escapes its input (every `char::is_control()`
byte is rewritten to a non-control escape, e.g. via `char::escape_default`), so
no value of the type can carry a raw control character. The constructor SHALL be
idempotent — escaping already-escaped text is a no-op. `SafeText` SHALL live in
`may-i-core` so both `may-i-engine` (Reason text) and `may-i-output` (Layout
content) depend on one implementation; `engine`'s existing `DisplaySafe` SHALL
become a re-export or alias of `SafeText`, not a second implementation. The type
SHALL NOT provide a `From`/`Into` conversion that bypasses escaping.

#### Scenario: Constructor escapes every control character

- **WHEN** `SafeText::new(s)` is called for any string `s`
- **THEN** the resulting value contains no `char` for which `is_control()` holds

#### Scenario: Escaping is idempotent

- **WHEN** a `SafeText` is constructed and its escaped string is passed to `SafeText::new` again
- **THEN** the second result is byte-equal to the first

#### Scenario: No bypassing constructor

- **WHEN** the workspace is scanned for `impl From<` or `impl Into<` targeting `SafeText`, and for public constructors other than the single escaping one
- **THEN** zero matches are found, and the only field of `SafeText` is private

### Requirement: Spanned-source sanitisation preserves byte offsets

A type `SafeSource` SHALL sanitise source text that is addressed by byte-offset
spans (the snippet rendered by miette diagnostics). Its constructor SHALL replace
each *dangerous* control character with a printable placeholder of equal UTF-8
byte length so that the byte length of the source is unchanged and every span
offset into the original source remains valid against the sanitised source. Line
feed (`\n`) and tab (`\t`) SHALL be preserved, because in a multi-line
offset-addressed snippet they are structural: the renderer derives a span's
line/column from them, and scrubbing them would collapse the snippet and
misplace every caret. They are not injection vectors (unlike `\x1b`). Every
other control character SHALL be scrubbed. `SafeSource` SHALL live in
`may-i-core` alongside `SafeText`, and SHALL be distinct from `SafeText` because
`SafeText`'s expanding escape would shift offsets.

#### Scenario: Sanitised source has no dangerous control characters

- **WHEN** `SafeSource::new(src)` is called for any string `src`
- **THEN** the result contains no `char` for which `is_control()` holds other than `\n` and `\t`, and in particular contains no `\x1b`

#### Scenario: Byte length is preserved

- **WHEN** `SafeSource::new(src)` is called
- **THEN** the byte length of the result equals the byte length of `src`, so a `SourceSpan` valid against `src` remains in-bounds and correctly aligned against the result

### Requirement: Styling is color-as-data with roles as the only ANSI source

Terminal styling SHALL be represented as data: every `Layout` leaf that carries
styled text SHALL hold `SafeText` content together with a value of a closed
`Style` enum of semantic roles (e.g. keyword, string-literal, form-head, dimmed,
heading, match-hit, match-miss). ANSI/SGR escape sequences SHALL NOT be embedded
in any `Layout` content value. The mapping from a `Style` role to an SGR sequence
SHALL exist at exactly one site inside the renderer, where colour enablement
(`NO_COLOR` / `--color`) is also decided.

#### Scenario: No pre-coloured strings in Layout content

- **WHEN** the `Layout` ADT and its leaf types are inspected
- **THEN** no content field has a type that admits embedded ANSI; styled leaves carry `SafeText` plus a `Style` role, and the role→SGR table is the only place an `\x1b` byte is produced

#### Scenario: Colour disable produces no SGR

- **WHEN** a `Layout` is rendered with colour disabled
- **THEN** the emitted bytes contain no `\x1b` byte at all

### Requirement: The renderer computes visible width from escape-free content

The renderer SHALL compute the visible width of styled text from its escape-free
`SafeText` content, since a `Style` role adds zero visible width. The explicit
width companion fields on layout leaves (`ColItem`'s width, `NoteHeading`'s
`visible_width`, `HRuleLabel`'s `visible_width`) SHALL be removed. The
ANSI-stripping helpers `strip_ansi` and `visible_len` SHALL be removed, as no
layout value carries embedded ANSI for them to strip.

#### Scenario: Width companion fields are gone

- **WHEN** `ColItem`, `NoteHeading`, and `HRuleLabel` are inspected
- **THEN** none declares an explicit `width` or `visible_width` field; width is derived by the renderer from content

#### Scenario: strip_ansi and visible_len are removed

- **WHEN** the workspace is scanned for `strip_ansi` and `visible_len`
- **THEN** zero definitions and zero call sites remain

### Requirement: A single sink owns every process output stream

Exactly one module (the sink) SHALL acquire and write the process `stdout` and
`stderr` streams. The sink SHALL accept only escape-safe input: a `Layout`
(rendered with a `Terminal`), a `SafeText` line for simple diagnostics, or a
serialisable value for JSON responses (whose control characters are escaped by
serialisation). No other module SHALL name `std::io::stdout`/`stderr`,
`console::Term::stdout`/`stderr`, a raw terminal file descriptor, or invoke a
`print*!` macro.

#### Scenario: Sink is the only stream owner

- **WHEN** the workspace (excluding tests) is scanned for `io::stdout`, `io::stderr`, `stdout()`, `stderr()`, `console::Term::std`, and the `println!`/`print!`/`eprintln!`/`eprint!` macros
- **THEN** the only matches are inside the sink module

#### Scenario: Sink rejects unsafe input by type

- **WHEN** the sink's public methods are inspected
- **THEN** every text entry point takes `Layout` or `SafeText`, and no entry point takes a bare `String`/`&str` that is written without escaping

### Requirement: miette diagnostics render only sanitised input

Error diagnostics rendered through miette SHALL receive only sanitised input, so
miette's own SGR output is trusted. The single spanned source surface
(`shape_diag`) SHALL wrap its source in `SafeSource` before attaching it to the
diagnostic. Input-derived interpolations in flat `miette!` messages SHALL be
wrapped in `SafeText`. A rendered `miette::Report` SHALL reach a stream only
through the sink.

#### Scenario: Spanned source is SafeSource

- **WHEN** `shape_diag` constructs a diagnostic with a `NamedSource`/`SourceSpan`
- **THEN** the source text attached is a `SafeSource`, and the spans remain aligned because `SafeSource` preserves byte offsets

#### Scenario: Report reaches the stream via the sink

- **WHEN** the workspace is scanned for rendering a `miette::Report` to `stderr` (e.g. `writeln!(stderr(), "{:?}", report)`)
- **THEN** the only such site is inside the sink module

### Requirement: No user-controlled control character reaches a stream

The render surfaces SHALL NOT deliver a raw control character to the sink for any
input. Adversarial input includes raw `\x1b`, ANSI-C `$'\n'` forms, and arbitrary
control bytes embedded in command names, argv, regex actuals, captured values,
and `(load)`ed config. This SHALL be proven by a colour-disabled property test:
with colour off the renderer emits no SGR, so any control character in the sink
bytes is an injection and MUST fail the test. A colour-enabled companion test
SHALL assert every `\x1b` in the output belongs to a well-formed SGR sequence
drawn from the `Style` role palette and that no other control byte appears.

#### Scenario: Colour-off render is control-free

- **WHEN** adversarial input is driven through `render_eval`, `render_check`, the trace renderers, and the advisory renderers with colour disabled
- **THEN** the bytes delivered to the sink contain no `char` for which `is_control()` holds

#### Scenario: Colour-on render emits only palette SGR

- **WHEN** the same surfaces are rendered with colour enabled
- **THEN** every `\x1b` introduces a well-formed SGR sequence from the role palette, and no other control character appears in the output
