//! Parser-binding environment for `(authorise #var)` / `(bound? #var)` /
//! `(matches? #var PAT)`.
//!
//! Section 5 of the parser-named-bindings change. `parse_argv` is the
//! unified entry point that supersedes `split_outer_tail` and
//! `parser_positional_args`: given a tokenised argv and a resolved
//! parser, it returns the positional residual that rule-body matchers
//! walk and the binding environment that rule-body verbs consult.

use may_i_core::ast::{BindingName, FlagsMode, ResolvedParser};

use super::decompose::Expansion;

/// A captured token paired with its expansion provenance. `expansion` is
/// `None` for a token whose source word was literal; `Some(display)` when
/// the word was expansion-bearing (the display text names the word in
/// floor reasons). The provenance is recorded at capture time from the
/// originating word — it cannot be re-derived from `text`, where a
/// captured `\$` and a live `$` are indistinguishable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundToken {
    pub(crate) text: String,
    pub(crate) expansion: Expansion,
}

impl BoundToken {
    pub(crate) fn new(text: impl Into<String>, expansion: Expansion) -> Self {
        Self {
            text: text.into(),
            expansion,
        }
    }

    #[cfg(test)]
    pub(crate) fn literal(text: impl Into<String>) -> Self {
        Self::new(text, None)
    }
}

/// Value of a parser-bound name.
///
/// `Token` is a single string (default for `(parameter NAME #var)` and
/// `(positional #var PAT)` without a repeating quantifier). `Tokens`
/// is a list (multi-token positionals, `(many-till …)` captures, and
/// `(rest …)` tails). `Unbound` records that the name is declared but
/// the parser produced no value — `(authorise #var)` on an `Unbound`
/// binding is a no-match (matches the historical boundary-absent
/// semantics of `(tail (after …))`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BindingValue {
    Token(BoundToken),
    Tokens(Vec<BoundToken>),
    /// Occurrence count of a `(flag NAME (count #v))` binding. Always
    /// "bound" (decision: `(bound? #count)` is true even for `0`).
    Count(u32),
    Unbound,
}

impl BindingValue {
    /// A single-token binding with no expansion provenance (test helper).
    #[cfg(test)]
    pub(crate) fn token(text: impl Into<String>) -> Self {
        BindingValue::Token(BoundToken::literal(text))
    }

    /// A token-list binding with no expansion provenance (test helper).
    #[cfg(test)]
    pub(crate) fn tokens<I: IntoIterator<Item = S>, S: Into<String>>(items: I) -> Self {
        BindingValue::Tokens(items.into_iter().map(BoundToken::literal).collect())
    }

    /// True iff the value is `Unbound` or carries no tokens. A `Count`
    /// is never empty — a counted flag binds even when it counts zero.
    pub(crate) fn is_empty(&self) -> bool {
        match self {
            BindingValue::Unbound => true,
            BindingValue::Token(t) => t.text.is_empty(),
            BindingValue::Tokens(v) => v.is_empty(),
            BindingValue::Count(_) => false,
        }
    }

    /// Coerce to a single space-joined string for predicate matching.
    /// `Token` round-trips as-is; `Tokens` joins with single spaces;
    /// `Count` renders its integer; `Unbound` yields `None`.
    pub(crate) fn as_joined(&self) -> Option<String> {
        match self {
            BindingValue::Token(t) => Some(t.text.clone()),
            BindingValue::Tokens(v) if !v.is_empty() => Some(
                v.iter()
                    .map(|t| t.text.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            BindingValue::Count(n) => Some(n.to_string()),
            BindingValue::Tokens(_) | BindingValue::Unbound => None,
        }
    }

    /// Display text of the first expansion-bearing captured token, if any.
    /// `Some` means the binding's string coercion under-determines the
    /// runtime value, so a non-wildcard match against it cannot be proven.
    pub(crate) fn first_expansion(&self) -> Option<&str> {
        match self {
            BindingValue::Token(t) => t.expansion.as_deref(),
            BindingValue::Tokens(v) => v.iter().find_map(|t| t.expansion.as_deref()),
            BindingValue::Count(_) | BindingValue::Unbound => None,
        }
    }

    /// View as an ordered collection of tokens, for quantifier folds.
    /// `Tokens` yields its slice; every other shape yields an empty
    /// slice (quantifiers only run against `Collection Token` bindings,
    /// enforced by the shape checker).
    pub(crate) fn as_collection(&self) -> &[BoundToken] {
        match self {
            BindingValue::Tokens(v) => v,
            BindingValue::Token(_) | BindingValue::Count(_) | BindingValue::Unbound => &[],
        }
    }
}

/// The set of parser-bound names produced by [`parse_argv`].
///
/// Lookup is by [`BindingName`]; missing entries resolve to
/// [`BindingValue::Unbound`] so consumers don't need to distinguish
/// "declared but empty" from "not declared at all" — both are
/// no-match.
#[derive(Debug, Clone, Default)]
pub(crate) struct Bindings {
    map: std::collections::HashMap<BindingName, BindingValue>,
}

impl Bindings {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Insert a binding. Overwrites a previous value for the same name
    /// (last-write-wins matches the "default to last value" decision
    /// from design.md for multi-occurrence parameters).
    pub(crate) fn insert(&mut self, name: BindingName, value: BindingValue) {
        self.map.insert(name, value);
    }

    /// Resolve a binding. Returns `Unbound` if the name was never
    /// produced; callers can distinguish via [`BindingValue::is_empty`]
    /// if they care.
    pub(crate) fn get(&self, name: &BindingName) -> BindingValue {
        self.map.get(name).cloned().unwrap_or(BindingValue::Unbound)
    }

    /// True iff `name` resolves to a non-empty value.
    pub(crate) fn is_bound(&self, name: &BindingName) -> bool {
        !self.get(name).is_empty()
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&BindingName, &BindingValue)> {
        self.map.iter()
    }
}

/// Parse a tokenised argv under a resolved parser, producing the
/// positional residual that rule-body matchers walk and the binding
/// environment that `(authorise …)` / `(bound? …)` / `(matches? …)`
/// consult.
///
/// The residual is returned as owned `String`s rather than borrowed
/// slices because the slice-borrowing pattern from
/// `parser_positional_args` doesn't compose with the binding
/// environment (which needs to outlive the argv for recursion); the
/// allocation is one `Vec` per evaluation and shows up in flame graphs
/// as negligible.
pub(crate) fn parse_argv(
    parser: &ResolvedParser,
    argv: &[String],
    expansions: &[Expansion],
) -> (Vec<String>, Bindings) {
    debug_assert_eq!(argv.len(), expansions.len());
    let mut bindings = Bindings::new();

    // Boundary: outer vs tail per flags_mode.
    //
    // - `posix`: outer = flags only; tail = first-positional onwards.
    //   Declared positionals consume from the *front* of the tail
    //   slice; `(rest …)` collects what's left.
    // - `until`: outer = pre-boundary; tail = post-boundary. The
    //   boundary token is consumed and dropped. Declared positionals
    //   consume from outer's positional residual; `(rest …)`
    //   collects the tail.
    // - `permute`: outer = whole argv; tail = none. Declared
    //   positionals consume from the positional residual; `(rest …)`
    //   collects what's left of the residual.
    let argv_split = super::entry::split_outer_tail(argv, parser);
    let (outer, tail_slice) = (argv_split.outer, argv_split.tail);
    // The outer scope is always a prefix of argv and the tail a suffix,
    // so the expansion slices align by length.
    let outer_exp = &expansions[..outer.len()];
    let tail_exp = tail_slice.map(|t| &expansions[argv.len() - t.len()..]);

    // Parameter bindings: walk the outer slice (which is everything
    // under `permute` and pre-boundary otherwise) for declared
    // parameters with bindings.
    collect_parameter_bindings(outer, outer_exp, parser, &mut bindings);

    // Counted flags: `(flag NAME (count #v))` binds #v to the number of
    // recognised occurrences across the flag-bearing region.
    collect_flag_count_bindings(outer, parser, &mut bindings);

    // The "positional region" — where declared positionals match —
    // differs by mode. Under posix it's the tail slice (everything
    // after the outer-flags region); under permute and until it's
    // the residual of the outer slice after flag/parameter peeling.
    let mut positional_region: Vec<BoundToken> = match &parser.flags_mode {
        FlagsMode::Posix => tail_slice
            .map(|t| bound_tokens(t, tail_exp.unwrap_or(&[])))
            .unwrap_or_default(),
        FlagsMode::Permute | FlagsMode::Until(_) => positional_tokens(outer, outer_exp, parser),
    };

    // Declared positionals consume from the front of the positional
    // region in source order. The split carries (consumed, remaining)
    // so the rule-visible residual can keep positional-decl tokens
    // while the rest binding picks up only the unclaimed tail.
    let split = collect_positional_bindings(
        std::mem::take(&mut positional_region),
        parser,
        &mut bindings,
    );

    // Rest binding: collects the unconsumed remainder. Under `until`
    // mode the rest is the post-boundary slice (declared positionals
    // sit in the pre-boundary region); under posix and permute the
    // rest is whatever positional declarations didn't claim.
    if let Some(rest_name) = &parser.rest {
        let value = match &parser.flags_mode {
            FlagsMode::Until(_) => match tail_slice {
                Some(tail) if !tail.is_empty() => {
                    BindingValue::Tokens(bound_tokens(tail, tail_exp.unwrap_or(&[])))
                }
                _ => BindingValue::Unbound,
            },
            FlagsMode::Posix | FlagsMode::Permute => {
                if split.remaining.is_empty() {
                    BindingValue::Unbound
                } else {
                    BindingValue::Tokens(split.remaining.clone())
                }
            }
        };
        bindings.insert(rest_name.clone(), value);
    }

    // The residual visible to rule-body matchers:
    //
    // - permute:  positional residual after flag peeling. Declared
    //             positionals' tokens stay in the residual (they're
    //             positionally visible to `(positional …)` matchers).
    // - posix:    only declared-positional tokens (the rest tail is
    //             hidden from rule-body so matchers don't pick up the
    //             recurse target by accident).
    // - until:    outer's positional residual (pre-boundary). The
    //             post-boundary slice is the rest binding only.
    let residual: Vec<String> = match &parser.flags_mode {
        FlagsMode::Permute => {
            let mut out = split.consumed;
            out.extend(split.remaining);
            out.into_iter().map(|t| t.text).collect()
        }
        FlagsMode::Posix => split.consumed.into_iter().map(|t| t.text).collect(),
        FlagsMode::Until(_) => positional_tokens(outer, outer_exp, parser)
            .into_iter()
            .map(|t| t.text)
            .collect(),
    };

    (residual, bindings)
}

/// Pair a token slice with its aligned expansion slice.
fn bound_tokens(tokens: &[String], expansions: &[Expansion]) -> Vec<BoundToken> {
    debug_assert_eq!(tokens.len(), expansions.len());
    tokens
        .iter()
        .zip(expansions)
        .map(|(t, e)| BoundToken::new(t.clone(), e.clone()))
        .collect()
}

/// Walk `outer` and pair every declared `(parameter X #var)` with its
/// captured value. Mirrors the seek logic in `effects::find_parameter_value_*`
/// but is binding-aware.
fn collect_parameter_bindings(
    outer: &[String],
    outer_exp: &[Expansion],
    parser: &ResolvedParser,
    bindings: &mut Bindings,
) {
    for decl in &parser.parameters {
        let Some(binding_name) = decl.binding.clone() else {
            continue;
        };
        let value = capture_parameter_value(outer, outer_exp, decl, parser);
        bindings.insert(binding_name, value);
    }
}

/// Find the captured value for a single parameter declaration in `outer`.
/// Returns `Unbound` when the parameter is absent. For `Capture::ManyTill`
/// the value is `Tokens(...)`; otherwise `Token(...)`. Last-occurrence
/// wins for multi-occurrence captures.
fn capture_parameter_value(
    outer: &[String],
    outer_exp: &[Expansion],
    decl: &may_i_core::ast::ParameterDecl,
    parser: &ResolvedParser,
) -> BindingValue {
    use may_i_core::ast::Capture;

    let style = &parser.style;
    let separators = style.separators();
    let space_separated = separators.iter().any(|s| s == " ");
    // Declared spellings, in style-aware token form (e.g. `--namespace`).
    let tokens: Vec<String> = decl
        .names
        .iter()
        .map(|n| parser.token_for_name(n))
        .collect();
    // Inline-separator probes: `--namespace=`, `--namespace:` etc.
    let inline_probes: Vec<String> = tokens
        .iter()
        .flat_map(|t| {
            separators.iter().filter_map(move |sep| {
                if sep.trim().is_empty() {
                    None
                } else {
                    Some(format!("{t}{sep}"))
                }
            })
        })
        .collect();

    let mut last_single: Option<BoundToken> = None;
    let mut last_many: Option<Vec<BoundToken>> = None;
    // Every single-token occurrence in source order, for `(set …)`.
    let mut all_singles: Vec<BoundToken> = Vec::new();

    let mut i = 0;
    while i < outer.len() {
        let arg = &outer[i];
        // Inline form: `--namespace=value` — extract the value directly.
        // The value inherits the whole token's expansion provenance.
        if let Some(value) = inline_probes
            .iter()
            .find_map(|p| arg.strip_prefix(p).map(str::to_owned))
        {
            let tok = BoundToken::new(value, outer_exp[i].clone());
            all_singles.push(tok.clone());
            last_single = Some(tok);
            i += 1;
            continue;
        }
        // Bare-token form: arg matches a declared spelling exactly.
        let bare_match = tokens.iter().any(|t| t == arg);
        if !bare_match {
            i += 1;
            continue;
        }
        match &decl.capture {
            Capture::Single => {
                if space_separated && i + 1 < outer.len() {
                    let tok = BoundToken::new(outer[i + 1].clone(), outer_exp[i + 1].clone());
                    all_singles.push(tok.clone());
                    last_single = Some(tok);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Capture::ManyTill { terminator } => {
                let mut collected = Vec::new();
                let mut j = i + 1;
                while j < outer.len() {
                    if terminator.is_match(&outer[j]) {
                        break;
                    }
                    collected.push(BoundToken::new(outer[j].clone(), outer_exp[j].clone()));
                    j += 1;
                }
                last_many = Some(collected);
                i = j + 1;
            }
            // `Capture` is `#[non_exhaustive]`; treat unknown variants
            // as single-token captures.
            _ => {
                if space_separated && i + 1 < outer.len() {
                    let tok = BoundToken::new(outer[i + 1].clone(), outer_exp[i + 1].clone());
                    all_singles.push(tok.clone());
                    last_single = Some(tok);
                    i += 2;
                } else {
                    i += 1;
                }
            }
        }
    }

    // `(set #v)` collects every occurrence in source order (duplicates
    // preserved), binding to the empty list when the parameter is
    // absent — never `Unbound`, so quantifiers see an empty collection.
    if matches!(decl.shape_form, may_i_core::ast::ParamShapeForm::Set) {
        return BindingValue::Tokens(all_singles);
    }

    match (last_many, last_single) {
        (Some(v), _) => BindingValue::Tokens(v),
        (None, Some(s)) => BindingValue::Token(s),
        (None, None) => BindingValue::Unbound,
    }
}

/// Bind every `(flag NAME (count #v))` declaration to its occurrence
/// count in `outer`. Flags without a count binding are skipped (they
/// contribute no rule-visible value).
fn collect_flag_count_bindings(outer: &[String], parser: &ResolvedParser, bindings: &mut Bindings) {
    for decl in &parser.flags {
        let Some(binding_name) = decl.count_binding.clone() else {
            continue;
        };
        let n = count_flag_occurrences(outer, decl, parser);
        bindings.insert(binding_name, BindingValue::Count(n));
    }
}

/// Count occurrences of a flag across its recognised spellings: exact
/// short/long tokens, members of a combined-short cluster (`-vvv`), and
/// the `--name=VALUE` form (counted once per token).
fn count_flag_occurrences(
    outer: &[String],
    decl: &may_i_core::ast::FlagDecl,
    parser: &ResolvedParser,
) -> u32 {
    use may_i_core::pattern::is_short_flag_name;
    let style = &parser.style;
    let short_prefix = style.short_prefix();
    let long_prefix = style.long_prefix();

    let mut count: u32 = 0;
    for arg in outer {
        for name in &decl.names {
            let token = parser.token_for_name(name);
            if arg == &token {
                count += 1;
                continue;
            }
            // `--name=value` (and `--name=false`) — one occurrence each.
            if !long_prefix.is_empty()
                && !is_short_flag_name(name)
                && arg.starts_with(&format!("{token}="))
            {
                count += 1;
                continue;
            }
            // Combined-short cluster: `-xvv` contains two `v`s. Only
            // applies to single-character short names under a non-empty
            // short prefix that is distinct from the long prefix.
            let is_short_cluster = !short_prefix.is_empty()
                && short_prefix != long_prefix
                && arg.starts_with(short_prefix)
                && (long_prefix.is_empty() || !arg.starts_with(long_prefix));
            if is_short_flag_name(name) && is_short_cluster {
                let cluster = &arg[short_prefix.len()..];
                // Guard: only treat as a cluster when every character is
                // a short flag letter (avoids miscounting `-O2`-style
                // value-bearing shorts).
                if !cluster.is_empty() && cluster.chars().all(|c| c.is_ascii_alphabetic()) {
                    let ch = name.chars().next().expect("short name is one char");
                    count += cluster.chars().filter(|c| *c == ch).count() as u32;
                }
            }
        }
    }
    count
}

/// Result of matching declared positionals against an input region.
struct PositionalSplit {
    /// Tokens consumed by `(positional …)` declarations, in source
    /// order. Remain visible to rule-body matchers — declared
    /// positionals don't hide their tokens, they only name them.
    consumed: Vec<BoundToken>,
    /// Tokens that no positional declaration claimed. An `(rest …)`
    /// declaration binds these; under `permute` they also stay in
    /// the rule-visible residual.
    remaining: Vec<BoundToken>,
}

/// Walk declared positionals against `region` in source order. Each
/// declaration's quantifier drives how many tokens it claims; bindings
/// for declarations carrying a `#var` are recorded.
fn collect_positional_bindings(
    region: Vec<BoundToken>,
    parser: &ResolvedParser,
    bindings: &mut Bindings,
) -> PositionalSplit {
    use may_i_core::pattern::Quantifier;
    if parser.positionals.is_empty() {
        return PositionalSplit {
            consumed: Vec::new(),
            remaining: region,
        };
    }
    let mut remaining = region;
    let mut consumed: Vec<BoundToken> = Vec::new();
    for decl in &parser.positionals {
        match decl.quantifier {
            Quantifier::One | Quantifier::Optional => {
                if remaining.is_empty() {
                    if let Some(name) = &decl.binding {
                        bindings.insert(name.clone(), BindingValue::Unbound);
                    }
                    continue;
                }
                let tok = remaining.remove(0);
                if let Some(name) = &decl.binding {
                    bindings.insert(name.clone(), BindingValue::Token(tok.clone()));
                }
                consumed.push(tok);
            }
            Quantifier::OneOrMore | Quantifier::ZeroOrMore => {
                let collected = std::mem::take(&mut remaining);
                if let Some(name) = &decl.binding {
                    bindings.insert(name.clone(), BindingValue::Tokens(collected.clone()));
                }
                consumed.extend(collected);
            }
        }
    }
    PositionalSplit {
        consumed,
        remaining,
    }
}

/// Owned positional residual with expansion provenance. Thin adapter over
/// the single index-reporting tokeniser in `entry` — the binding
/// environment stores owned tokens in the `Bindings` map, so it cannot
/// hold the borrowed slices `entry::parser_positional_args` returns. The
/// outer/tail split likewise goes through `entry::split_outer_tail`; this
/// module keeps no copy of the style-aware scanning logic.
fn positional_tokens(
    args: &[String],
    expansions: &[Expansion],
    parser: &ResolvedParser,
) -> Vec<BoundToken> {
    super::entry::parser_positional_indices(args, parser)
        .into_iter()
        .map(|i| BoundToken::new(args[i].clone(), expansions[i].clone()))
        .collect()
}

// Tests assert one variant and `panic!`/ignore the rest; the catch-all arm is
// intentional here.
#[cfg(test)]
#[allow(clippy::wildcard_enum_match_arm)]
mod tests {
    use super::*;
    use may_i_core::ast::{
        Capture, FlagDecl, FlagsMode, ParamShapeForm, ParameterDecl, ParameterTreatment,
        PositionalDecl, ResolvedParser, Style,
    };

    fn parser_permute() -> ResolvedParser {
        let mut p = ResolvedParser::synthetic_gnu("any");
        p.flags_mode = FlagsMode::Permute;
        p
    }

    fn parser_posix_with_rest(rest: &str) -> ResolvedParser {
        let mut p = parser_permute();
        p.style = Style::default_gnu();
        p.flags_mode = FlagsMode::Posix;
        p.rest = Some(BindingName::parse(rest).unwrap());
        p
    }

    fn parser_until(boundary: &[&str], rest: &str) -> ResolvedParser {
        let mut p = parser_permute();
        p.flags_mode = FlagsMode::Until(boundary.iter().map(|s| s.to_string()).collect());
        p.rest = Some(BindingName::parse(rest).unwrap());
        p
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// All-literal expansion provenance for a test argv.
    fn none_exp(argv: &[String]) -> Vec<Expansion> {
        vec![None; argv.len()]
    }

    /// Texts of a captured token list, for comparisons.
    fn texts(v: &[BoundToken]) -> Vec<String> {
        v.iter().map(|t| t.text.clone()).collect()
    }

    #[test]
    fn permute_mode_no_rest_binding_yields_empty_environment() {
        let parser = parser_permute();
        let (residual, bindings) = parse_argv(
            &parser,
            &argv(&["-a", "foo", "bar"]),
            &none_exp(&argv(&["-a", "foo", "bar"])),
        );
        assert_eq!(residual, vec!["foo", "bar"]);
        assert!(bindings.iter().next().is_none());
    }

    #[test]
    fn posix_mode_binds_rest_to_tokens_after_flags() {
        let parser = parser_posix_with_rest("cmd");
        let (_residual, bindings) = parse_argv(
            &parser,
            &argv(&["-u", "rm", "-rf", "/tmp/x"]),
            &none_exp(&argv(&["-u", "rm", "-rf", "/tmp/x"])),
        );
        let cmd = BindingName::parse("cmd").unwrap();
        match bindings.get(&cmd) {
            BindingValue::Tokens(v) => {
                assert_eq!(
                    texts(&v),
                    vec!["rm".to_string(), "-rf".to_string(), "/tmp/x".to_string()]
                )
            }
            other => panic!("expected Tokens binding, got {other:?}"),
        }
    }

    #[test]
    fn until_mode_consumes_boundary_token() {
        let parser = parser_until(&["--"], "cmd");
        let (_residual, bindings) = parse_argv(
            &parser,
            &argv(&["mise", "exec", "--", "cargo", "test"]),
            &none_exp(&argv(&["mise", "exec", "--", "cargo", "test"])),
        );
        let cmd = BindingName::parse("cmd").unwrap();
        match bindings.get(&cmd) {
            BindingValue::Tokens(v) => {
                assert_eq!(texts(&v), vec!["cargo".to_string(), "test".to_string()])
            }
            other => panic!("expected Tokens, got {other:?}"),
        }
    }

    #[test]
    fn until_mode_boundary_absent_yields_unbound() {
        let parser = parser_until(&["--"], "cmd");
        let (_residual, bindings) = parse_argv(
            &parser,
            &argv(&["mise", "exec", "no-boundary"]),
            &none_exp(&argv(&["mise", "exec", "no-boundary"])),
        );
        let cmd = BindingName::parse("cmd").unwrap();
        assert_eq!(bindings.get(&cmd), BindingValue::Unbound);
    }

    #[test]
    fn parameter_with_binding_captures_value() {
        let mut parser = parser_permute();
        parser.parameters.push(ParameterDecl {
            names: vec!["c".into()],
            treatment: ParameterTreatment::None,
            shape_form: may_i_core::ast::ParamShapeForm::Unannotated,
            capture: Capture::Single,
            binding: Some(BindingName::parse("c").unwrap()),
        });
        let (_residual, bindings) = parse_argv(
            &parser,
            &argv(&["-c", "echo hi"]),
            &none_exp(&argv(&["-c", "echo hi"])),
        );
        let c = BindingName::parse("c").unwrap();
        assert_eq!(bindings.get(&c), BindingValue::token("echo hi"));
    }

    #[test]
    fn parameter_without_binding_does_not_appear() {
        let mut parser = parser_permute();
        parser.parameters.push(ParameterDecl {
            names: vec!["c".into()],
            treatment: ParameterTreatment::None,
            shape_form: may_i_core::ast::ParamShapeForm::Unannotated,
            capture: Capture::Single,
            binding: None,
        });
        let (_residual, bindings) = parse_argv(
            &parser,
            &argv(&["-c", "echo hi"]),
            &none_exp(&argv(&["-c", "echo hi"])),
        );
        // No declared binding ⇒ no entry produced.
        assert!(bindings.iter().next().is_none());
    }

    #[test]
    fn positional_binding_consumes_residual_token() {
        let mut parser = parser_posix_with_rest("cmd");
        parser.positionals.push(PositionalDecl {
            binding: Some(BindingName::parse("host").unwrap()),
            pattern: may_i_core::pattern::Expr::Wildcard,
            quantifier: may_i_core::pattern::Quantifier::One,
        });
        let (residual, bindings) = parse_argv(
            &parser,
            &argv(&["user@host", "ls"]),
            &none_exp(&argv(&["user@host", "ls"])),
        );
        let host = BindingName::parse("host").unwrap();
        assert_eq!(bindings.get(&host), BindingValue::token("user@host"));
        let cmd = BindingName::parse("cmd").unwrap();
        match bindings.get(&cmd) {
            BindingValue::Tokens(v) => assert_eq!(texts(&v), vec!["ls".to_string()]),
            other => panic!("expected Tokens, got {other:?}"),
        }
        assert!(residual.contains(&"user@host".to_string()));
    }

    // ── expansion provenance is recorded at capture time ────────────

    #[test]
    fn parameter_capture_records_expansion_provenance() {
        let mut parser = parser_permute();
        parser.parameters.push(ParameterDecl {
            names: vec!["c".into()],
            treatment: ParameterTreatment::None,
            shape_form: may_i_core::ast::ParamShapeForm::Unannotated,
            capture: Capture::Single,
            binding: Some(BindingName::parse("c").unwrap()),
        });
        let args = argv(&["-c", "X"]);
        let exps = vec![None, Some("$X".to_string())];
        let (_residual, bindings) = parse_argv(&parser, &args, &exps);
        let c = BindingName::parse("c").unwrap();
        assert_eq!(
            bindings.get(&c),
            BindingValue::Token(BoundToken::new("X", Some("$X".to_string())))
        );
        assert_eq!(bindings.get(&c).first_expansion(), Some("$X"));
    }

    #[test]
    fn positional_capture_records_expansion_provenance() {
        let mut parser = parser_permute();
        parser.positionals.push(PositionalDecl {
            binding: Some(BindingName::parse("paths").unwrap()),
            pattern: may_i_core::pattern::Expr::Wildcard,
            quantifier: may_i_core::pattern::Quantifier::OneOrMore,
        });
        let args = argv(&["/tmp/a", "/tmp/HOME"]);
        let exps = vec![None, Some("/tmp/$HOME".to_string())];
        let (_residual, bindings) = parse_argv(&parser, &args, &exps);
        let paths = BindingName::parse("paths").unwrap();
        match bindings.get(&paths) {
            BindingValue::Tokens(v) => {
                assert_eq!(v[0].expansion, None);
                assert_eq!(v[1].expansion.as_deref(), Some("/tmp/$HOME"));
            }
            other => panic!("expected Tokens, got {other:?}"),
        }
    }

    #[test]
    fn literal_capture_records_no_provenance() {
        let mut parser = parser_permute();
        parser.parameters.push(ParameterDecl {
            names: vec!["c".into()],
            treatment: ParameterTreatment::None,
            shape_form: may_i_core::ast::ParamShapeForm::Unannotated,
            capture: Capture::Single,
            binding: Some(BindingName::parse("c").unwrap()),
        });
        let args = argv(&["-c", "literal"]);
        let (_residual, bindings) = parse_argv(&parser, &args, &none_exp(&args));
        let c = BindingName::parse("c").unwrap();
        assert_eq!(bindings.get(&c).first_expansion(), None);
    }

    // ── shape-typed-bindings: multi-occurrence parameter eval ───────

    fn set_param(name: &str, binding: &str) -> ParameterDecl {
        ParameterDecl {
            names: vec![name.into()],
            treatment: ParameterTreatment::None,
            shape_form: ParamShapeForm::Set,
            capture: Capture::Single,
            binding: Some(BindingName::parse(binding).unwrap()),
        }
    }

    #[test]
    fn set_parameter_collects_all_occurrences_in_order() {
        let mut parser = parser_permute();
        parser.parameters.push(set_param("o", "opts"));
        let (_r, b) = parse_argv(
            &parser,
            &argv(&["-o", "A=1", "-o", "B=2", "host"]),
            &none_exp(&argv(&["-o", "A=1", "-o", "B=2", "host"])),
        );
        assert_eq!(
            b.get(&BindingName::parse("opts").unwrap()),
            BindingValue::tokens(["A=1", "B=2"])
        );
    }

    #[test]
    fn set_parameter_preserves_duplicates() {
        let mut parser = parser_permute();
        parser.parameters.push(set_param("o", "opts"));
        let (_r, b) = parse_argv(
            &parser,
            &argv(&["-o", "X", "-o", "X"]),
            &none_exp(&argv(&["-o", "X", "-o", "X"])),
        );
        assert_eq!(
            b.get(&BindingName::parse("opts").unwrap()),
            BindingValue::tokens(["X", "X"])
        );
    }

    #[test]
    fn set_parameter_absent_is_empty_collection_not_bound() {
        let mut parser = parser_permute();
        parser.parameters.push(set_param("o", "opts"));
        let (_r, b) = parse_argv(&parser, &argv(&["host"]), &none_exp(&argv(&["host"])));
        let opts = BindingName::parse("opts").unwrap();
        assert_eq!(b.get(&opts), BindingValue::Tokens(vec![]));
        assert!(!b.is_bound(&opts), "empty set is not bound");
    }

    #[test]
    fn last_and_unannotated_keep_final_value() {
        for form in [ParamShapeForm::Last, ParamShapeForm::Unannotated] {
            let mut parser = parser_permute();
            parser.parameters.push(ParameterDecl {
                names: vec!["O".into()],
                treatment: ParameterTreatment::None,
                shape_form: form,
                capture: Capture::Single,
                binding: Some(BindingName::parse("opt").unwrap()),
            });
            let (_r, b) = parse_argv(
                &parser,
                &argv(&["-O", "0", "-O", "2", "file.c"]),
                &none_exp(&argv(&["-O", "0", "-O", "2", "file.c"])),
            );
            assert_eq!(
                b.get(&BindingName::parse("opt").unwrap()),
                BindingValue::token("2"),
                "form {form:?}"
            );
        }
    }

    fn count_flag(name: &str, binding: &str) -> FlagDecl {
        FlagDecl {
            names: vec![name.into()],
            count_binding: Some(BindingName::parse(binding).unwrap()),
        }
    }

    #[test]
    fn count_flag_combined_short_cluster() {
        let mut parser = parser_permute();
        parser.flags.push(count_flag("v", "verbosity"));
        let (_r, b) = parse_argv(
            &parser,
            &argv(&["-vvv", "https://example.com"]),
            &none_exp(&argv(&["-vvv", "https://example.com"])),
        );
        assert_eq!(
            b.get(&BindingName::parse("verbosity").unwrap()),
            BindingValue::Count(3)
        );
    }

    #[test]
    fn count_flag_repeated_long_and_short() {
        let mut parser = parser_permute();
        parser.flags.push(FlagDecl {
            names: vec!["r".into(), "recursive".into()],
            count_binding: Some(BindingName::parse("r").unwrap()),
        });
        let (_r, b) = parse_argv(
            &parser,
            &argv(&["--recursive", "-r", "pattern"]),
            &none_exp(&argv(&["--recursive", "-r", "pattern"])),
        );
        assert_eq!(
            b.get(&BindingName::parse("r").unwrap()),
            BindingValue::Count(2)
        );
    }

    #[test]
    fn count_flag_absent_is_zero_and_bound() {
        let mut parser = parser_permute();
        parser.flags.push(count_flag("v", "verbosity"));
        let (_r, b) = parse_argv(
            &parser,
            &argv(&["https://example.com"]),
            &none_exp(&argv(&["https://example.com"])),
        );
        let v = BindingName::parse("verbosity").unwrap();
        assert_eq!(b.get(&v), BindingValue::Count(0));
        assert!(b.is_bound(&v), "a count binds even at zero");
    }

    // ── Section 5.5 property checkpoint ─────────────────────────────

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 256,
            max_shrink_iters: 50,
            ..Default::default()
        })]

        /// Totality: parse_argv never panics on any argv, under any
        /// mode.
        #[test]
        fn parse_argv_total(
            args in proptest::collection::vec("[a-zA-Z0-9_=:/.-]{0,10}", 0..12),
            mode in 0u8..3,
        ) {
            let mut parser = parser_permute();
            parser.flags_mode = match mode {
                0 => FlagsMode::Posix,
                1 => FlagsMode::Permute,
                _ => FlagsMode::Until(vec!["--".to_string()]),
            };
            let _ = parse_argv(&parser, &args, &none_exp(&args));
        }

        /// Determinism: same (parser, argv) yields the same result on
        /// repeated calls.
        #[test]
        fn parse_argv_deterministic(
            args in proptest::collection::vec("[a-zA-Z0-9_=:/.-]{0,10}", 0..12),
        ) {
            let parser = parser_posix_with_rest("cmd");
            let (r1, b1) = parse_argv(&parser, &args, &none_exp(&args));
            let (r2, b2) = parse_argv(&parser, &args, &none_exp(&args));
            proptest::prop_assert_eq!(r1, r2);
            let cmd = BindingName::parse("cmd").unwrap();
            proptest::prop_assert_eq!(b1.get(&cmd), b2.get(&cmd));
        }

        /// `(until BOUNDARY)` mode invariant: the boundary token, if
        /// present, appears in *neither* the residual nor the rest
        /// binding.
        #[test]
        fn until_mode_boundary_token_elided(
            prefix in proptest::collection::vec("[a-z]{1,4}", 0..6),
            suffix in proptest::collection::vec("[a-z]{1,4}", 0..6),
        ) {
            let parser = parser_until(&["BOUND"], "cmd");
            let mut args = prefix.clone();
            args.push("BOUND".to_string());
            args.extend(suffix.iter().cloned());

            let (residual, bindings) = parse_argv(&parser, &args, &none_exp(&args));
            proptest::prop_assert!(!residual.iter().any(|t| t == "BOUND"),
                "boundary token leaked into residual: {residual:?}");
            let cmd = BindingName::parse("cmd").unwrap();
            if let BindingValue::Tokens(v) = bindings.get(&cmd) {
                proptest::prop_assert!(!v.iter().any(|t| t.text == "BOUND"),
                    "boundary token leaked into rest binding: {v:?}");
            }
        }

        /// `(set #v)` binds exactly the value tokens, in source order,
        /// including duplicates.
        #[test]
        fn set_collects_inserted_values_in_order(
            vals in proptest::collection::vec("[a-zA-Z0-9=._/]{1,8}", 0..8),
        ) {
            let mut parser = parser_permute();
            parser.parameters.push(set_param("o", "opts"));
            let mut args = Vec::new();
            for v in &vals {
                args.push("-o".to_string());
                args.push(v.clone());
            }
            let (_r, b) = parse_argv(&parser, &args, &none_exp(&args));
            match b.get(&BindingName::parse("opts").unwrap()) {
                BindingValue::Tokens(got) => proptest::prop_assert_eq!(texts(&got), vals),
                other => proptest::prop_assert!(false, "expected Tokens, got {:?}", other),
            }
        }

        /// `(count #v)` over repeated separate short flags equals the
        /// number of occurrences.
        #[test]
        fn count_equals_separate_short_occurrences(k in 0u32..6) {
            let mut parser = parser_permute();
            parser.flags.push(count_flag("v", "n"));
            let mut args: Vec<String> = (0..k).map(|_| "-v".to_string()).collect();
            args.push("url".into());
            let (_r, b) = parse_argv(&parser, &args, &none_exp(&args));
            proptest::prop_assert_eq!(
                b.get(&BindingName::parse("n").unwrap()),
                BindingValue::Count(k)
            );
        }

        /// `(count #v)` over a single combined-short cluster `-vvv…`
        /// equals the cluster length.
        #[test]
        fn count_equals_combined_short_cluster_length(k in 1u32..6) {
            let mut parser = parser_permute();
            parser.flags.push(count_flag("v", "n"));
            let cluster = format!("-{}", "v".repeat(k as usize));
            let (_r, b) = parse_argv(&parser, &argv(&[&cluster, "url"]), &none_exp(&argv(&[&cluster, "url"])));
            proptest::prop_assert_eq!(
                b.get(&BindingName::parse("n").unwrap()),
                BindingValue::Count(k)
            );
        }

        /// posix-mode invariant: under (flags posix), the first
        /// non-flag token in argv begins the rest binding (when
        /// declared). Every subsequent token is part of the rest.
        #[test]
        fn posix_mode_first_positional_starts_rest(
            flags in proptest::collection::vec(prop_oneof_flag(), 0..4),
            positional in "[a-z][a-z0-9]{0,4}",
            tail in proptest::collection::vec("[a-z0-9]{0,4}", 0..4),
        ) {
            let parser = parser_posix_with_rest("cmd");
            let mut args = flags;
            args.push(positional.clone());
            args.extend(tail.iter().cloned());

            let (_residual, bindings) = parse_argv(&parser, &args, &none_exp(&args));
            let cmd = BindingName::parse("cmd").unwrap();
            match bindings.get(&cmd) {
                BindingValue::Tokens(v) => {
                    proptest::prop_assert_eq!(v.first().map(|t| t.text.as_str()), Some(positional.as_str()));
                }
                other => proptest::prop_assert!(false, "expected Tokens binding, got {:?}", other),
            }
        }
    }

    /// Strategy for flag-shaped tokens used by the posix proptest
    /// above. Only emits flags that *don't* consume their next arg
    /// under GNU semantics: short flags (`-x`) and inline-value long
    /// flags (`--foo=bar`). Bare `--long` would (under
    /// `gnu_long_consumes_next`) eat the following positional and
    /// break the test's invariant.
    fn prop_oneof_flag() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;
        prop_oneof![
            "[a-z]{1,3}".prop_map(|s| format!("-{s}")),
            "[a-z]{1,3}=[a-z0-9]{1,3}".prop_map(|s| format!("--{s}")),
        ]
    }
}
