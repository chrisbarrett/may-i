## ADDED Requirements

### Requirement: output.rs is decomposed into focused submodules
The monolithic `src/output.rs` SHALL be decomposed into a `src/output/` module
directory with submodules, each responsible for a single concern. The public API
surface (functions and re-exports used by `cmd_eval.rs`, `cmd_check.rs`, and
other callers) SHALL remain unchanged.

#### Scenario: Module directory structure
- **WHEN** inspecting `src/output/`
- **THEN** the following submodules exist: `mod.rs`, `transform.rs`,
  `annotate.rs`, `render_rule.rs`, `colorize.rs`, `json.rs`

#### Scenario: Public API preserved
- **WHEN** `cmd_eval.rs` imports from `crate::output`
- **THEN** all previously available public functions and re-exports
  (`write_trace`, `print_trace`, `trace_to_json`, `colorize_decision_keyword`,
  `print_separator`, `render_elements`, `shorten_home`, and `may_i_layout`
  re-exports) are accessible without changes to import paths

#### Scenario: Tests co-located with modules
- **WHEN** inspecting each submodule
- **THEN** tests for that module's functions are in a `#[cfg(test)] mod tests`
  block within the same file

### Requirement: Doc tree transforms are isolated in transform module
The `transform` submodule SHALL contain all Doc tree transformations that prepare
annotated docs for rendering: truncation, dimming, and related helpers.

#### Scenario: Transform functions are self-contained
- **WHEN** `truncate_matched_anywhere`, `truncate_unevaluated`, and
  `dim_unevaluated` are called
- **THEN** they operate as pure `Doc<Option<Ann>> -> Doc<Option<Ann>>`
  functions with no dependency on rendering or colorization code

### Requirement: Annotation collection is isolated in annotate module
The `annotate` submodule SHALL contain annotation extraction logic that walks
Doc trees to produce structured annotation data.

#### Scenario: Annotation functions have no rendering dependency
- **WHEN** `collect_annotations` is called
- **THEN** it produces annotation data without calling pretty-printing or
  colorization functions

### Requirement: Right-column colorization is isolated in colorize module
The `colorize` submodule SHALL contain all ANSI colorization logic for
right-column annotation text and decision keywords.

#### Scenario: Colorize functions are pure string transformations
- **WHEN** `colorize_right` and `colorize_decision_keyword` are called
- **THEN** they accept plain strings and return ANSI-colored strings with no
  dependency on Doc types or tree traversal
