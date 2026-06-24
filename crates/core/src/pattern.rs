// Argument and command patterns for the unified rule DSL.

use crate::ast::Effect;
use crate::doc::Doc;
use crate::primitives::{Keyword, ToDoc};

/// How many arguments a positional expression consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantifier {
    /// Match exactly one arg.
    One,
    /// Match zero or one arg: `(? e)`
    Optional,
    /// Match one or more args: `(+ e)`
    OneOrMore,
    /// Match zero or more args: `(* e)`
    ZeroOrMore,
}

impl Quantifier {
    #[cfg(test)]
    pub(crate) fn min(self) -> usize {
        match self {
            Quantifier::One | Quantifier::OneOrMore => 1,
            Quantifier::Optional | Quantifier::ZeroOrMore => 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_repeating(self) -> bool {
        matches!(self, Quantifier::OneOrMore | Quantifier::ZeroOrMore)
    }
}

/// An expression that matches a single string, optionally carrying effects.
///
/// This type uses the fixpoint-of-functor pattern internally, enabling generic
/// traversals via the `ExprF` base functor.
#[derive(Clone)]
#[non_exhaustive]
pub enum Expr<E: std::fmt::Debug + ToDoc = Effect> {
    /// Exact string match.
    Literal(String),
    /// Regex match.
    Regex(regex::Regex),
    /// Matches any string.
    Wildcard,
    /// All sub-expressions must match.
    And(Vec<Expr<E>>),
    /// Any sub-expression must match.
    Or(Vec<Expr<E>>),
    /// Inverts the match result.
    Not(Box<Expr<E>>),
    /// Branches with effects; first matching branch wins.
    Cond(Vec<ExprBranch<E>>),
    /// Bind the matched value to a fact key.
    Bind { key: Keyword, expr: Box<Expr<E>> },
}

/// A branch in an expression-level cond.
#[derive(Debug, Clone)]
pub struct ExprBranch<E: std::fmt::Debug + ToDoc = Effect> {
    pub test: Expr<E>,
    pub effect: E,
}

impl<E: std::fmt::Debug + ToDoc> Expr<E> {
    /// Check if the expression matches the given text (ignoring effects).
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Expr::Literal(s) => text == s,
            Expr::Regex(re) => re.is_match(text),
            Expr::Wildcard => true,
            Expr::And(exprs) => exprs.iter().all(|e| e.is_match(text)),
            Expr::Or(exprs) => exprs.iter().any(|e| e.is_match(text)),
            Expr::Not(expr) => !expr.is_match(text),
            Expr::Cond(branches) => branches.iter().any(|b| b.test.is_match(text)),
            Expr::Bind { expr, .. } => expr.is_match(text),
        }
    }

    #[cfg(test)]
    pub(crate) fn is_wildcard(&self) -> bool {
        matches!(self, Expr::Wildcard)
    }

    /// True when this expression matches every possible value — the bare
    /// wildcard `*`, possibly under a binding. Such an expression constrains
    /// nothing, so a match against an expansion-bearing word is sound; any
    /// other shape constrains the value and cannot be proven for a word
    /// whose runtime value is unknown (see the expansion-bearing-word
    /// requirement in the security model).
    pub fn matches_any_value(&self) -> bool {
        match self {
            Expr::Wildcard => true,
            Expr::Bind { expr, .. } => expr.matches_any_value(),
            Expr::Literal(_)
            | Expr::Regex(_)
            | Expr::And(_)
            | Expr::Or(_)
            | Expr::Not(_)
            | Expr::Cond(_) => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn find_effect(&self, text: &str) -> Option<&E> {
        match self {
            Expr::Literal(_) | Expr::Regex(_) | Expr::Wildcard => None,
            Expr::And(exprs) => exprs.iter().find_map(|e| e.find_effect(text)),
            Expr::Or(exprs) => exprs.iter().find_map(|e| e.find_effect(text)),
            Expr::Not(expr) => expr.find_effect(text),
            Expr::Cond(branches) => branches
                .iter()
                .find(|b| b.test.is_match(text))
                .map(|b| &b.effect),
            Expr::Bind { expr, .. } => expr.find_effect(text),
        }
    }

    /// Convert to a Doc representation.
    pub fn to_doc(&self) -> Doc {
        match self {
            Expr::Literal(s) => Doc::atom(format!("\"{s}\"")),
            Expr::Regex(re) => Doc::list(vec![
                Doc::atom("regex"),
                Doc::atom(format!("\"{}\"", re.as_str())),
            ]),
            Expr::Wildcard => Doc::atom("*"),
            Expr::And(exprs) => {
                let mut cs = vec![Doc::atom("and")];
                cs.extend(exprs.iter().map(|e| e.to_doc()));
                if exprs.len() > 4 {
                    Doc::broken_list(cs)
                } else {
                    Doc::list(cs)
                }
            }
            Expr::Or(exprs) => {
                let mut cs = vec![Doc::atom("or")];
                cs.extend(exprs.iter().map(|e| e.to_doc()));
                if exprs.len() > 4 {
                    Doc::broken_list(cs)
                } else {
                    Doc::list(cs)
                }
            }
            Expr::Not(inner) => Doc::list(vec![Doc::atom("not"), inner.to_doc()]),
            Expr::Cond(branches) => {
                let mut cs = vec![Doc::atom("cond")];
                for b in branches {
                    cs.push(Doc::list(vec![b.test.to_doc(), b.effect.to_doc()]));
                }
                Doc::list(cs)
            }
            Expr::Bind { key, expr } => Doc::vector(vec![key.to_doc(), expr.to_doc()]),
        }
    }
}

impl std::fmt::Display for Expr {
    #[coverage(off)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expr::Literal(s) => write!(f, "\"{s}\""),
            Expr::Regex(re) => write!(f, "(regex \"{}\")", re.as_str()),
            Expr::Wildcard => write!(f, "*"),
            Expr::And(exprs) => {
                write!(f, "(and")?;
                for e in exprs {
                    write!(f, " {e}")?;
                }
                write!(f, ")")
            }
            Expr::Or(exprs) => {
                write!(f, "(or")?;
                for e in exprs {
                    write!(f, " {e}")?;
                }
                write!(f, ")")
            }
            Expr::Not(inner) => write!(f, "(not {inner})"),
            Expr::Cond(branches) => {
                write!(f, "(cond")?;
                for b in branches {
                    write!(f, " ({} {})", b.test, b.effect)?;
                }
                write!(f, ")")
            }
            Expr::Bind { key, expr } => {
                write!(f, "[{key} {expr}]")
            }
        }
    }
}

impl<E: std::fmt::Debug + ToDoc> std::fmt::Debug for Expr<E> {
    #[coverage(off)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expr::Literal(s) => f.debug_tuple("Literal").field(s).finish(),
            Expr::Regex(re) => f.debug_tuple("Regex").field(&re.as_str()).finish(),
            Expr::Wildcard => write!(f, "Wildcard"),
            Expr::And(exprs) => f.debug_tuple("And").field(exprs).finish(),
            Expr::Or(exprs) => f.debug_tuple("Or").field(exprs).finish(),
            Expr::Not(expr) => f.debug_tuple("Not").field(expr).finish(),
            Expr::Cond(branches) => f.debug_tuple("Cond").field(branches).finish(),
            Expr::Bind { key, expr } => f
                .debug_struct("Bind")
                .field("key", key)
                .field("expr", expr)
                .finish(),
        }
    }
}

/// Pattern for matching commands in rules.
/// Position 1 of a rule is always the command pattern.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CommandPattern {
    /// Exact command name match.
    Literal(String),

    /// Matches any of the given command names.
    Or(Vec<CommandPattern>),
}

impl CommandPattern {
    /// Check if a command name matches this pattern.
    pub fn is_match(&self, command: &str) -> bool {
        match self {
            CommandPattern::Literal(lit) => lit == command,
            CommandPattern::Or(patterns) => patterns.iter().any(|p| p.is_match(command)),
        }
    }
}

/// A positional term: either a single quantified pattern, or a quantified
/// sequence group whose sub-sequence is the quantified unit. Groups nest, so
/// a term forms a tree.
///
/// `(? "run" (? "--"))` is a `Group` with `Optional` quantifier over the
/// sub-sequence `["run", (? "--")]`; the inner `(? "--")` is a `Single`.
///
/// Invariant: a `Group`'s sub-sequence is non-empty — a quantifier head must
/// wrap at least one sub-pattern. The representation is private and the smart
/// constructors enforce this, so an empty group is unconstructible.
#[derive(Debug, Clone)]
pub struct PosTerm {
    repr: PosTermRepr,
}

#[derive(Debug, Clone)]
enum PosTermRepr {
    Single {
        quantifier: Quantifier,
        pattern: Expr<Effect>,
    },
    Group {
        quantifier: Quantifier,
        seq: Vec<PosTerm>,
    },
}

/// Borrowed view of a [`PosTerm`], for matching and rendering. The owned
/// representation stays private; consumers dispatch on this.
pub enum PosTermView<'a> {
    Single {
        quantifier: Quantifier,
        pattern: &'a Expr<Effect>,
    },
    Group {
        quantifier: Quantifier,
        seq: &'a [PosTerm],
    },
}

impl PosTerm {
    /// A single required term (`Quantifier::One`).
    pub fn one(pattern: Expr<Effect>) -> Self {
        Self::single(Quantifier::One, pattern)
    }

    /// A single quantified term wrapping one pattern.
    pub fn single(quantifier: Quantifier, pattern: Expr<Effect>) -> Self {
        Self {
            repr: PosTermRepr::Single {
                quantifier,
                pattern,
            },
        }
    }

    /// A single quantified term, pattern-first (builder ergonomics). Same as
    /// [`PosTerm::single`] with the arguments swapped.
    pub fn with_quantifier(pattern: Expr<Effect>, quantifier: Quantifier) -> Self {
        Self::single(quantifier, pattern)
    }

    /// A quantified sequence group. Returns `None` when `seq` is empty: a
    /// quantifier head must wrap at least one sub-pattern.
    pub fn group(quantifier: Quantifier, seq: Vec<PosTerm>) -> Option<Self> {
        if seq.is_empty() {
            None
        } else {
            Some(Self {
                repr: PosTermRepr::Group { quantifier, seq },
            })
        }
    }

    /// The term's quantifier (`One` for a bare required pattern).
    pub fn quantifier(&self) -> Quantifier {
        match &self.repr {
            PosTermRepr::Single { quantifier, .. } | PosTermRepr::Group { quantifier, .. } => {
                *quantifier
            }
        }
    }

    /// If this is a bare required pattern (`Single` with `Quantifier::One`),
    /// take its inner expression; otherwise return `self` unchanged. The parser
    /// uses this to collapse a single-sub-pattern quantifier head into a
    /// `Single` term, while a single *quantified* sub-pattern stays a group.
    pub fn into_bare_pattern(self) -> Result<Expr<Effect>, Self> {
        // The first arm refines `Single` by quantifier value, so the remaining
        // cases (non-`One` singles and all groups) cannot be enumerated as whole
        // variants; the catch-all also rebinds `repr` to reconstruct `self`.
        #[allow(clippy::wildcard_enum_match_arm)]
        match self.repr {
            PosTermRepr::Single {
                quantifier: Quantifier::One,
                pattern,
            } => Ok(pattern),
            repr => Err(Self { repr }),
        }
    }

    /// Borrowed view for dispatch.
    pub fn view(&self) -> PosTermView<'_> {
        match &self.repr {
            PosTermRepr::Single {
                quantifier,
                pattern,
            } => PosTermView::Single {
                quantifier: *quantifier,
                pattern,
            },
            PosTermRepr::Group { quantifier, seq } => PosTermView::Group {
                quantifier: *quantifier,
                seq,
            },
        }
    }

    /// Render to a `Doc`: `(Q elem …)` for groups and quantified singles, the
    /// bare pattern doc for a `One` single. Nested groups recurse.
    pub fn to_doc(&self) -> Doc {
        match &self.repr {
            PosTermRepr::Single {
                quantifier: Quantifier::One,
                pattern,
            } => pattern.to_doc(),
            PosTermRepr::Single {
                quantifier,
                pattern,
            } => Doc::list(vec![
                Doc::atom(quantifier_glyph(*quantifier)),
                pattern.to_doc(),
            ]),
            PosTermRepr::Group { quantifier, seq } => {
                let mut cs = vec![Doc::atom(quantifier_glyph(*quantifier))];
                cs.extend(seq.iter().map(PosTerm::to_doc));
                Doc::list(cs)
            }
        }
    }
}

/// The head glyph for a quantifier in surface syntax. `One` has no glyph (a
/// bare pattern); callers must not render it as a head.
fn quantifier_glyph(q: Quantifier) -> &'static str {
    match q {
        Quantifier::One => "",
        Quantifier::Optional => "?",
        Quantifier::OneOrMore => "+",
        Quantifier::ZeroOrMore => "*",
    }
}

impl std::fmt::Display for PosTerm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.view() {
            PosTermView::Single {
                quantifier: Quantifier::One,
                pattern,
            } => write!(f, "{pattern}"),
            PosTermView::Single {
                quantifier,
                pattern,
            } => write!(f, "({} {pattern})", quantifier_glyph(quantifier)),
            PosTermView::Group { quantifier, seq } => {
                write!(f, "({}", quantifier_glyph(quantifier))?;
                for term in seq {
                    write!(f, " {term}")?;
                }
                write!(f, ")")
            }
        }
    }
}

/// Whether an ordered pattern requires exact or prefix matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Match positional args by position (skip flags), prefix match.
    Positional,
    /// Like Positional, but requires exactly as many positional args as patterns.
    Exact,
}

/// Pattern for matching command arguments.
#[derive(Debug, Clone)]
pub enum ArgPattern {
    /// Match positional args by position (skip flags).
    /// Syntax: `(positional PATTERN ... [. EFFECT])` or `(exact PATTERN ... [. EFFECT])`
    Ordered {
        mode: MatchMode,
        patterns: Vec<PosTerm>,
        /// Optional continuation effect evaluated with remaining args.
        continuation: Option<Box<crate::ast::Effect>>,
    },

    /// Token appears anywhere in argv.
    /// Syntax: `(anywhere PATTERN ...)`
    Anywhere(Vec<Expr<Effect>>),

    /// Token must NOT appear anywhere in argv.
    /// Syntax: `(forbidden PATTERN ...)`
    Forbidden(Vec<Expr<Effect>>),

    /// Boolean flag presence test.
    /// Syntax: `(flag X)` where `X` is a string (single-char short, multi-char
    /// long) or a vector `[short long]`. Non-consuming.
    Flag { names: Vec<String> },

    /// Match the value of a named flag against `form`.
    /// Syntax: `(parameter X FORM)`. Consumes the flag and its value from the
    /// view available to sibling positional matchers in the same rule.
    Parameter {
        names: Vec<String>,
        form: ParameterForm,
    },

    /// Recurse on the wrapper-tail slice. Syntax: `(tail (authorise))`.
    /// The tail comes from the parser's `(tail (after …))` declaration if
    /// present, else from residual positionals after preceding
    /// `(positional …)` matches.
    Tail,
}

/// How a `(parameter X FORM)` pattern interprets the flag's value.
#[derive(Debug, Clone)]
pub enum ParameterForm {
    /// Match the flag value as a single token against this expression.
    /// Supports literals, regex, wildcard, fact-bind, and `and`/`or`/`not`/`cond`.
    Match(Expr<Effect>),
    /// Treat the flag value as a command line and recurse via the evaluator,
    /// the same way `(authorise)` does over its host context.
    Authorise,
}

impl ArgPattern {
    /// Create a simple positional pattern from expressions.
    pub fn positional(exprs: Vec<Expr<Effect>>) -> Self {
        ArgPattern::Ordered {
            mode: MatchMode::Positional,
            patterns: exprs.into_iter().map(PosTerm::one).collect(),
            continuation: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn positional_with_continuation(
        exprs: Vec<Expr<Effect>>,
        continuation: crate::ast::Effect,
    ) -> Self {
        ArgPattern::Ordered {
            mode: MatchMode::Positional,
            patterns: exprs.into_iter().map(PosTerm::one).collect(),
            continuation: Some(Box::new(continuation)),
        }
    }

    #[cfg(test)]
    pub(crate) fn exact(exprs: Vec<Expr<Effect>>) -> Self {
        ArgPattern::Ordered {
            mode: MatchMode::Exact,
            patterns: exprs.into_iter().map(PosTerm::one).collect(),
            continuation: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn exact_with_continuation(
        exprs: Vec<Expr<Effect>>,
        continuation: crate::ast::Effect,
    ) -> Self {
        ArgPattern::Ordered {
            mode: MatchMode::Exact,
            patterns: exprs.into_iter().map(PosTerm::one).collect(),
            continuation: Some(Box::new(continuation)),
        }
    }

    #[cfg(test)]
    pub(crate) fn anywhere(exprs: Vec<Expr<Effect>>) -> Self {
        ArgPattern::Anywhere(exprs)
    }

    #[cfg(test)]
    pub(crate) fn forbidden(exprs: Vec<Expr<Effect>>) -> Self {
        ArgPattern::Forbidden(exprs)
    }
}

/// Classify a flag name as short (single character) or long (multi character).
/// Single-character names denote short flags; longer names denote long flags.
pub fn is_short_flag_name(name: &str) -> bool {
    name.chars().count() == 1
}

/// The on-the-wire token form for a flag name. `-x` for shorts, `--long` for
/// longs. Used by both the evaluator (to match flag tokens) and the implicit
/// value-bearing flag registration that Parameter feeds into the tokeniser.
pub fn flag_token_for_name(name: &str) -> String {
    if is_short_flag_name(name) {
        format!("-{name}")
    } else {
        format!("--{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;
    use crate::test_generators::any_expr;
    use proptest::prelude::*;

    #[test]
    fn command_pattern_literal_matches_exactly() {
        let pattern = CommandPattern::Literal("git".into());
        assert!(pattern.is_match("git"));
        assert!(!pattern.is_match("hub"));
    }

    #[test]
    fn command_pattern_or_matches_any() {
        let pattern = CommandPattern::Or(vec![
            CommandPattern::Literal("git".into()),
            CommandPattern::Literal("hub".into()),
        ]);
        assert!(pattern.is_match("git"));
        assert!(pattern.is_match("hub"));
        assert!(!pattern.is_match("svn"));
    }

    #[test]
    fn pos_term_one_creates_required_single() {
        let arg = PosTerm::one(Expr::Literal("test".into()));
        assert!(matches!(arg.quantifier(), Quantifier::One));
        assert!(matches!(arg.view(), PosTermView::Single { .. }));
    }

    #[test]
    fn pos_term_single_sets_quantifier() {
        let arg = PosTerm::single(Quantifier::Optional, Expr::Wildcard);
        assert!(matches!(arg.quantifier(), Quantifier::Optional));
    }

    /// Task 1.1: `(? "run" (? "--"))` constructs as a nested Group/Single term.
    #[test]
    fn pos_term_nested_group_constructs() {
        let inner = PosTerm::single(Quantifier::Optional, Expr::Literal("--".into()));
        let group = PosTerm::group(
            Quantifier::Optional,
            vec![PosTerm::one(Expr::Literal("run".into())), inner],
        )
        .expect("non-empty group");

        match group.view() {
            PosTermView::Group {
                quantifier: Quantifier::Optional,
                seq,
            } => {
                assert_eq!(seq.len(), 2);
                assert!(matches!(
                    seq[0].view(),
                    PosTermView::Single {
                        quantifier: Quantifier::One,
                        pattern: Expr::Literal(s),
                    } if s == "run"
                ));
                assert!(matches!(
                    seq[1].view(),
                    PosTermView::Single {
                        quantifier: Quantifier::Optional,
                        ..
                    }
                ));
            }
            PosTermView::Single { .. } | PosTermView::Group { .. } => panic!("expected group"),
        }
    }

    #[test]
    fn pos_term_empty_group_is_unconstructible() {
        assert!(PosTerm::group(Quantifier::Optional, vec![]).is_none());
    }

    /// Task 1.4: rendering nests groups under their head glyph.
    #[test]
    fn pos_term_to_doc_renders_nested_group() {
        let group = PosTerm::group(
            Quantifier::Optional,
            vec![
                PosTerm::one(Expr::Literal("run".into())),
                PosTerm::single(Quantifier::Optional, Expr::Literal("--".into())),
            ],
        )
        .expect("non-empty group");
        assert_eq!(group.to_string(), r#"(? "run" (? "--"))"#);
    }

    #[test]
    fn arg_pattern_positional_creates_correctly() {
        let pattern =
            ArgPattern::positional(vec![Expr::Literal("a".into()), Expr::Literal("b".into())]);
        assert!(
            matches!(pattern, ArgPattern::Ordered { mode: MatchMode::Positional, patterns, continuation: None } if patterns.len() == 2)
        );
    }

    #[test]
    fn arg_pattern_exact_creates_correctly() {
        let pattern = ArgPattern::exact(vec![Expr::Literal("x".into())]);
        assert!(
            matches!(pattern, ArgPattern::Ordered { mode: MatchMode::Exact, patterns, continuation: None } if patterns.len() == 1)
        );
    }

    #[test]
    fn arg_pattern_anywhere_creates_correctly() {
        let pattern = ArgPattern::anywhere(vec![Expr::Literal("--flag".into())]);
        assert!(matches!(pattern, ArgPattern::Anywhere(exprs) if exprs.len() == 1));
    }

    #[test]
    fn arg_pattern_forbidden_creates_correctly() {
        let pattern = ArgPattern::forbidden(vec![Expr::Literal("--dangerous".into())]);
        assert!(matches!(pattern, ArgPattern::Forbidden(exprs) if exprs.len() == 1));
    }

    #[test]
    fn positional_with_continuation_sets_continuation() {
        let cont = Effect::allow(None);
        let pattern = ArgPattern::positional_with_continuation(vec![], cont);
        assert!(
            matches!(pattern, ArgPattern::Ordered { mode: MatchMode::Positional, continuation: Some(_), patterns } if patterns.is_empty())
        );
    }

    #[test]
    fn positional_with_continuation_with_patterns() {
        let cont = Effect::ask(Some("confirm".into()));
        let pattern = ArgPattern::positional_with_continuation(
            vec![Expr::Literal("arg1".into()), Expr::Literal("arg2".into())],
            cont,
        );
        assert!(
            matches!(pattern, ArgPattern::Ordered { mode: MatchMode::Positional, continuation: Some(_), patterns } if patterns.len() == 2)
        );
    }

    #[test]
    fn exact_with_continuation_sets_continuation() {
        let cont = Effect::deny(Some("blocked".into()));
        let pattern = ArgPattern::exact_with_continuation(vec![], cont);
        assert!(
            matches!(pattern, ArgPattern::Ordered { mode: MatchMode::Exact, continuation: Some(_), patterns } if patterns.is_empty())
        );
    }

    #[test]
    fn exact_with_continuation_with_patterns() {
        let cont = Effect::allow(Some("safe".into()));
        let pattern = ArgPattern::exact_with_continuation(vec![Expr::Literal("cmd".into())], cont);
        assert!(
            matches!(pattern, ArgPattern::Ordered { mode: MatchMode::Exact, continuation: Some(_), patterns } if patterns.len() == 1)
        );
    }

    #[test]
    fn quantifier_one_has_min_1() {
        assert_eq!(Quantifier::One.min(), 1);
        assert!(!Quantifier::One.is_repeating());
    }

    #[test]
    fn quantifier_optional_has_min_0() {
        assert_eq!(Quantifier::Optional.min(), 0);
        assert!(!Quantifier::Optional.is_repeating());
    }

    #[test]
    fn quantifier_one_or_more_has_min_1() {
        assert_eq!(Quantifier::OneOrMore.min(), 1);
        assert!(Quantifier::OneOrMore.is_repeating());
    }

    #[test]
    fn quantifier_zero_or_more_has_min_0() {
        assert_eq!(Quantifier::ZeroOrMore.min(), 0);
        assert!(Quantifier::ZeroOrMore.is_repeating());
    }

    #[test]
    fn expr_literal_matches() {
        let expr = Expr::<Effect>::Literal("test".into());
        assert!(expr.is_match("test"));
        assert!(!expr.is_match("other"));
    }

    #[test]
    fn expr_wildcard_matches_anything() {
        let expr = Expr::<Effect>::Wildcard;
        assert!(expr.is_match("anything"));
        assert!(expr.is_match(""));
    }

    #[test]
    fn expr_is_wildcard_works() {
        assert!(Expr::<Effect>::Wildcard.is_wildcard());
        assert!(!Expr::<Effect>::Literal("test".into()).is_wildcard());
    }

    // --- is_match: Regex and Not ---

    #[test]
    fn expr_regex_matches() {
        let expr = Expr::<Effect>::Regex(regex::Regex::new("^foo").unwrap());
        assert!(expr.is_match("foobar"));
        assert!(!expr.is_match("barfoo"));
    }

    #[test]
    fn expr_not_inverts_match() {
        let expr = Expr::<Effect>::Not(Box::new(Expr::Literal("yes".into())));
        assert!(expr.is_match("no"));
        assert!(!expr.is_match("yes"));
    }

    // --- is_match: Cond and Bind ---

    #[test]
    fn expr_cond_matches_if_any_branch_test_matches() {
        let expr = Expr::<Effect>::Cond(vec![ExprBranch {
            test: Expr::Literal("yes".into()),
            effect: Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
        }]);
        assert!(expr.is_match("yes"));
        assert!(!expr.is_match("no"));
    }

    #[test]
    fn expr_bind_delegates_to_inner() {
        let expr = Expr::<Effect>::Bind {
            key: Keyword::new(":test").unwrap(),
            expr: Box::new(Expr::Literal("val".into())),
        };
        assert!(expr.is_match("val"));
        assert!(!expr.is_match("other"));
    }

    // --- to_doc: broken_list paths (And/Or with >4 items) ---

    #[test]
    fn expr_and_over_4_items_hits_broken_list() {
        let expr = Expr::<Effect>::And(vec![
            Expr::Literal("a".into()),
            Expr::Literal("b".into()),
            Expr::Literal("c".into()),
            Expr::Literal("d".into()),
            Expr::Literal("e".into()),
        ]);
        let doc = expr.to_doc();
        assert!(!format!("{doc:?}").is_empty());
    }

    #[test]
    fn expr_or_over_4_items_hits_broken_list() {
        let expr = Expr::<Effect>::Or(vec![
            Expr::Literal("a".into()),
            Expr::Literal("b".into()),
            Expr::Literal("c".into()),
            Expr::Literal("d".into()),
            Expr::Literal("e".into()),
        ]);
        let doc = expr.to_doc();
        assert!(!format!("{doc:?}").is_empty());
    }

    // --- find_effect: And, Or, Not, Bind ---

    #[test]
    fn find_effect_in_and() {
        let inner = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect::Terminal {
                decision: Decision::Allow,
                reason: Some("found".into()),
            },
        }]);
        let expr = Expr::And(vec![inner]);
        assert!(expr.find_effect("anything").is_some());
    }

    #[test]
    fn find_effect_in_or() {
        let inner = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect::Terminal {
                decision: Decision::Allow,
                reason: Some("found".into()),
            },
        }]);
        let expr = Expr::Or(vec![inner]);
        assert!(expr.find_effect("anything").is_some());
    }

    #[test]
    fn find_effect_in_not() {
        let inner = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect::Terminal {
                decision: Decision::Allow,
                reason: Some("found".into()),
            },
        }]);
        let expr = Expr::Not(Box::new(inner));
        assert!(expr.find_effect("anything").is_some());
    }

    #[test]
    fn find_effect_in_bind() {
        let inner = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect::Terminal {
                decision: Decision::Allow,
                reason: Some("found".into()),
            },
        }]);
        let expr = Expr::Bind {
            key: Keyword::new(":k").unwrap(),
            expr: Box::new(inner),
        };
        assert!(expr.find_effect("anything").is_some());
    }

    // --- proptest: to_doc never panics for arbitrary Expr ---

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn expr_to_doc_never_panics(expr in any_expr(3)) {
            let doc = expr.to_doc();
            assert!(!format!("{doc:?}").is_empty());
        }
    }
}
