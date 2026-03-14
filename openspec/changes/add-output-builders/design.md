## Context

The `cmd_check` and `cmd_eval` commands currently mix data extraction, decision-making about what to display, and actual formatting/rendering in a single pass. For example, `cmd_check.rs` iterates through results once for verbose output, then again to collect failures, then renders each failure block inline. This makes the code harder to unit test and obscures the document structure.

Current pain points:
- `cmd_check.rs:58-156` interleaves multiple concerns in ~100 lines
- Text and JSON output branches share little code despite producing equivalent information
- The document structure (warnings, results, summary) is implicit in control flow
- No way to test output structure without running the full command

## Goals / Non-Goals

**Goals:**
- Separate data extraction from rendering in `cmd_check` and `cmd_eval`
- Make output structure explicit and testable
- Preserve existing text output appearance exactly
- Preserve existing JSON structure (with `context`→`facts` rename)
- Support local reasoning: each builder type is complete for its command

**Non-Goals:**
- Create a global output framework shared across all commands
- Change `cmd_parse` or `cmd_hook` (too simple to benefit)
- Add new output formats beyond text/JSON
- Change the underlying `output.rs` primitives (`Element`, `Row`, `render_elements`)

## Decisions

### Decision: Local builders, not global framework

Each command gets its own builder tailored to its needs:

```rust
// cmd_check.rs
struct CheckReport {
    warnings: Vec<WarningDisplay>,
    results: Vec<CheckResultDisplay>,
    summary: Summary,
}

impl CheckReport {
    fn from_engine_results(results: &[CheckResult], config: &Config) -> Self;
    fn render_text(&self, verbose: bool) -> String;
    fn to_json(&self) -> serde_json::Value;
    fn exit_code(&self) -> i32; // 0 or 1
}
```

**Rationale:** `cmd_check` and `cmd_eval` have different output structures. A global abstraction would either be too generic (forcing boilerplate at use sites) or too specific (leaking command concerns into shared code). Local builders can evolve independently.

**Alternative considered:** Global `OutputDocument` with command-specific sections. Rejected: adds indirection without benefit at this scale.

### Decision: Builders produce final strings/values, not intermediate representation

The builders render directly to `String` (text) or `serde_json::Value` (JSON), not to an intermediate document tree.

**Rationale:** The existing `output.rs` primitives (`Element`, `Row`) already provide the intermediate layer for text formatting. Adding another layer would be redundant. For JSON, `serde_json::Value` *is* the intermediate representation.

**Alternative considered:** Builder → Document tree → Renderer. Rejected: overkill for this refactoring. The `output.rs` primitives already handle the complex layout (two-column trace, separators, etc.).

### Decision: JSON field rename `context` → `facts`

The JSON output will use `facts` instead of `context` for the per-result context object.

**Rationale:** Matches the domain language used throughout the codebase (`ContextFacts` type, `:fact` CLI argument, "context facts" in documentation). The old name was ambiguous (could mean "execution context", "error context", etc.).

**Breaking change:** Yes, but acceptable for 0.x and the tool's primary use is human-readable output.

### Decision: Keep builders in command files (not separate modules)

`CheckReport` lives in `cmd_check.rs`, `EvalReport` in `cmd_eval.rs`.

**Rationale:** Each builder is tightly coupled to its command's output structure. Extracting to separate files adds navigation overhead without reuse benefits. Can be split later if needed.

**Alternative considered:** `src/report/check.rs`, `src/report/eval.rs`. Rejected: premature abstraction.

### Decision: Exit logic stays in `cmd_check()` / `cmd_eval()`

Builders indicate exit status via methods (`exit_code()`, `has_failures()`) but don't call `std::process::exit()`.

**Rationale:** Keeps side effects explicit at the top level. Makes builders pure and easily testable.

## Risks / Trade-offs

**Risk:** Builders add boilerplate for simple commands  
**Mitigation:** Only applied to `cmd_check` and `cmd_eval`. `cmd_parse` and `cmd_hook` remain unchanged.

**Risk:** JSON field rename breaks existing integrations  
**Mitigation:** Document in changelog. The tool is primarily used interactively; JSON consumption is likely minimal at this stage.

**Risk:** Text output drift (builders might not reproduce exact formatting)  
**Mitigation:** Manual verification against current output. Add snapshot tests if the project adopts them.

**Risk:** Over-engineering  
**Mitigation:** Keep builders simple. No generic traits, no complex type parameters. Just structs with methods.

## Migration Plan

No external migration needed. The change is internal refactoring with one breaking JSON field rename.

Steps:
1. Implement `CheckReport` builder in `cmd_check.rs`
2. Update `cmd_check()` to use builder
3. Verify text output matches exactly (manual)
4. Verify JSON structure (field rename documented)
5. Repeat for `cmd_eval`
6. Run existing tests

Rollback: Revert commit. No data migration.
