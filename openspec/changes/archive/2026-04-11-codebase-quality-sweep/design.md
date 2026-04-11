## Context

The may-i codebase is ~40k lines across 7 crates + binary. A systematic review found a latent bug (nested-Or matching), ~300 lines of duplicated logic, imprecise types allowing impossible states, missing property tests on critical paths, and API hygiene issues. All changes are internal — no CLI behaviour changes except the bug fix.

## Goals / Non-Goals

**Goals:**
- Fix the nested-Or matching bug
- Reduce duplicated code paths that create maintenance burden
- Encode domain invariants at the type level (fewer impossible states)
- Add property tests to the highest-risk untested code paths
- Tighten API surface and fix idiomatic Rust issues

**Non-Goals:**
- Behaviour changes beyond the bug fix
- Documentation improvements
- Performance optimisation
- Restructuring crate boundaries (e.g. folding layout into binary — deferred)
- Breaking up the largest functions (annotation.rs, effects.rs) — separate change

## Decisions

### D1: Execution order — types first, then deduplication, then tests, then hygiene

Type changes (TerminalDecision, PositionalMatchKind, Ordered ArgPattern) alter struct shapes that deduplication and tests depend on. Deduplication removes code that tests would otherwise need to cover. Hygiene (&str, pub visibility) is mechanical and goes last.

Alternative: parallel streams per crate. Rejected — too many cross-crate type changes create merge conflicts.

### D2: TerminalDecision replaces Allow/Ask/Deny enum variants

```rust
// Before (3 variants, each with Option<String>)
Effect::Allow(Option<String>), Effect::Ask(Option<String>), Effect::Deny(Option<String>)

// After (1 variant with Decision enum)
Effect::Terminal { decision: Decision, reason: Option<String> }
```

Every match on Allow/Ask/Deny collapses to a single arm. The `Decision` enum already exists and is used throughout. This is the highest-impact type change — touches annotation.rs, effects.rs, fold.rs, config parsers, and tests.

Alternative: keep three variants, add a `fn decision(&self) -> Decision` method. Rejected — doesn't eliminate the three-way match pattern.

### D3: PositionalMatchKind enum replaces covarying Options

```rust
// Before
struct PositionalElementDetail {
    binding: Option<BindDetail>,
    expr_match: Option<ExprMatchDetail>,
    cond_branch_index: Option<usize>,
    matched: bool,
}

// After
enum PositionalMatchKind {
    Bind(BindDetail),
    ExprMatch(ExprMatchDetail),
    Cond { branch_index: usize, detail: ExprMatchDetail },
    Wildcard,
}
struct PositionalElementDetail {
    kind: PositionalMatchKind,
    matched: bool,
}
```

Eliminates impossible states (e.g. binding=Some AND expr_match=Some simultaneously). The `matched` field stays on the outer struct since all variants need it.

### D4: Ordered { mode, patterns, continuation } merges Positional/Exact

```rust
enum MatchMode { Positional, Exact }

// ArgPattern::Ordered replaces both Positional and Exact
Ordered {
    mode: MatchMode,
    patterns: Vec<PositionalArg>,
    continuation: Option<Box<Effect>>,
}
```

The eval branches that currently duplicate ~110 lines become a single branch with a `mode` check for the one behavioural difference (whether consumed == args.len() is enforced).

### D5: vector_syntax moves to config parser layer

`FactQuery::Presence` drops its `vector_syntax: bool` field. The config parser records the syntax choice in a local enum during parsing and uses it only for serialisation. This removes ~20 instances of `vector_syntax: false` in test constructors.

### D6: LoadedConfig wrapper in binary crate

```rust
// In src/ (binary crate)
struct LoadedConfig {
    config: Config,
    source_text: String,
    pre_migration_forms: Option<Vec<(Span, Doc<()>)>>,
}
```

`Config` in core loses `source_text` and `pre_migration_forms` fields. The binary's config loading code wraps the result. TracingFold::from_loaded_config(&LoadedConfig) replaces the repeated `.with_source_text().with_pre_migration_forms()` chain.

### D7: Property test priorities — H1-H5 first, M1-M8 second

The 5 high-priority tests (shell parser no-panic, config parse roundtrips, migration with defines, resolution no-panic, Doc functor laws) cover the biggest risk areas. Medium-priority tests are added if time permits. Low-priority tests are deferred.

New `Arbitrary` impls needed: `Doc<A>`, extend `any_config()` to include defines.

### D8: Bug fix via deletion

`match_command_pattern` in effects.rs is deleted entirely. Call sites switch to `pattern.is_match(command)`. No new code needed — the correct implementation already exists in core.

## Risks / Trade-offs

**[Large blast radius]** → Type changes touch all crates. Mitigated by: doing type changes first in isolation, running full test suite after each change, and the fact that all consumers are internal.

**[Test churn]** → Many existing tests reference old type shapes (e.g. `ArgPattern::Positional`, `Effect::Allow`). Mitigated by: mechanical find-and-replace for most cases; proptest generators updated once.

**[TerminalDecision ergonomics]** → Matching `Effect::Terminal { decision: Decision::Allow, .. }` is more verbose than `Effect::Allow(..)`. Trade-off accepted — the three-way unreachable!() pattern it eliminates is worse.

**[vector_syntax removal]** → If any code outside config parsing checks this field, it breaks. Mitigated by: grep for all usages before removing.
