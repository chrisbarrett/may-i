## 1. Integration test harness

- [ ] 1.1 Write `tests/oracle_trace_v1.rs` with a test-case loader that parses `tests/fixtures/v1/cases.toml` into (name, command, facts) tuples
- [ ] 1.2 Implement output capture: call `may_i_config::load` + `evaluate_with_fold` + `print_trace` rendering into a `String` buffer with `COLUMNS=80` and `colored::control::set_override(true)`
- [ ] 1.3 Implement config path normalisation — replace the `config: ...` line in both actual and expected output with `config: <config-path>`
- [ ] 1.4 Implement stripped comparison: strip ANSI from captured output, compare against `.txt` snapshot, produce a clear diff on failure
- [ ] 1.5 Implement raw comparison: compare captured output byte-for-byte against `.raw` snapshot, produce a clear diff on failure
- [ ] 1.6 Verify the test harness compiles and runs (all 24 cases execute, failures are expected at this stage)

## 2. Expose rendering internals for testability

- [ ] 2.1 Extract the trace + result rendering from `cmd_eval.rs` into a function that writes to `impl Write` instead of `println!` directly, so the test can capture output without subprocess spawning
- [ ] 2.2 Ensure `output::print_trace` and the result footer can write to a buffer — may need `write!` variants alongside `println!`

## 3. V1 source recovery

- [ ] 3.1 Add a detection mechanism for whether a loaded config was migrated from V1 (e.g. a `migrated: bool` flag on `Config`)
- [ ] 3.2 Implement span-based source extraction: for each rule, extract `source_text[rule.span.start..rule.span.end]` to get the original V1 s-expression
- [ ] 3.3 Implement V1 pretty-printing: parse the extracted V1 text and render it as the left column of the trace, replacing the current `to_doc()` approach for migrated configs
- [ ] 3.4 Implement annotation overlay: map TracingFold annotations (match results, decisions) onto the V1 pretty-printed lines using needle matching

## 4. Iterate on trace renderer

- [ ] 4.1 Fix which rules are shown — oracle shows all command-matching rules with annotation evidence, not just the terminal rule
- [ ] 4.2 Fix positional comparison annotations — oracle shows `"arg" = "pattern" → no` for non-matching positional comparisons
- [ ] 4.3 Fix effect/args structure — oracle shows `(args ...)` and `(effect ...)` as siblings, not effect nested in args
- [ ] 4.4 Fix pattern display — oracle shows original `(anywhere "-r")` not migration-expanded `(anywhere "-r" "--recursive")`
- [ ] 4.5 Run full snapshot suite, fix remaining divergences until all 24 cases pass on stripped output
- [ ] 4.6 Fix colour divergences until all 24 cases pass on raw ANSI output
