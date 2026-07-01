//! Arbitrary implementations for fuzz testing.
//!
//! Provides `arbitrary::Arbitrary` impls for core types, gated behind the
//! `arbitrary` feature. Recursive types use remaining fuel in `Unstructured`
//! to limit depth. `regex::Regex` fields generate simple alphabetic patterns.

use arbitrary::{Arbitrary, Unstructured};

use crate::ast::{
    Check, Config, Define, Effect, Predicate, Provenance, Rule, SecurityConfig, Spanned,
};
use crate::context::ContextFacts;
use crate::pattern::{
    ArgPattern, CommandPattern, Expr, ExprBranch, MatchMode, PosTerm, Quantifier,
};
use crate::predicates::{FactPattern, FactQuery};
use crate::primitives::{Decision, Keyword};
use crate::span::Span;

/// Generate an alphabetic string of length 1..=max_len from the fuzzer input.
fn arb_alpha(u: &mut Unstructured, max_len: usize) -> arbitrary::Result<String> {
    let len = u.int_in_range(1..=max_len)?;
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        s.push(u.int_in_range(b'a'..=b'z')? as char);
    }
    Ok(s)
}

/// Generate a simple regex that is always valid.
fn arb_regex(u: &mut Unstructured) -> arbitrary::Result<regex::Regex> {
    let s = arb_alpha(u, 8)?;
    Ok(regex::Regex::new(&s).unwrap())
}

/// Check whether there's enough data left for recursive generation.
fn has_fuel(u: &Unstructured) -> bool {
    !u.is_empty() && u.len() > 4
}

// --- Primitives ---

impl<'a> Arbitrary<'a> for Span {
    fn arbitrary(_u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Span::new(0, 0))
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

impl<'a, T: Arbitrary<'a>> Arbitrary<'a> for Spanned<T> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Spanned::new(T::arbitrary(u)?, Span::new(0, 0)))
    }
}

impl<'a> Arbitrary<'a> for Decision {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=2)? {
            0 => Ok(Decision::Allow),
            1 => Ok(Decision::Ask),
            _ => Ok(Decision::Deny),
        }
    }
}

impl<'a> Arbitrary<'a> for Keyword {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let s = arb_alpha(u, 10)?;
        Ok(Keyword::new(format!(":{s}")).unwrap())
    }
}

impl<'a> Arbitrary<'a> for ContextFacts {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let count = u.int_in_range(0..=5)?;
        let mut facts = ContextFacts::default();
        for _ in 0..count {
            let key = Keyword::arbitrary(u)?;
            if u.arbitrary()? {
                facts.insert_present(key);
            } else {
                facts.insert_scalar(key, arb_alpha(u, 15)?);
            }
        }
        Ok(facts)
    }
}

impl<'a> Arbitrary<'a> for Quantifier {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=3)? {
            0 => Ok(Quantifier::One),
            1 => Ok(Quantifier::Optional),
            2 => Ok(Quantifier::OneOrMore),
            _ => Ok(Quantifier::ZeroOrMore),
        }
    }
}

// --- Patterns ---

impl<'a> Arbitrary<'a> for FactPattern {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if !has_fuel(u) {
            // Leaf only
            return match u.int_in_range(0..=2)? {
                0 => Ok(FactPattern::Literal(arb_alpha(u, 15)?)),
                1 => Ok(FactPattern::Wildcard),
                _ => Ok(FactPattern::Regex(arb_regex(u)?)),
            };
        }
        match u.int_in_range(0..=5)? {
            0 => Ok(FactPattern::Literal(arb_alpha(u, 15)?)),
            1 => Ok(FactPattern::Wildcard),
            2 => Ok(FactPattern::Regex(arb_regex(u)?)),
            3 => {
                let count = u.int_in_range(1..=3)?;
                let pats = (0..count)
                    .map(|_| FactPattern::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(FactPattern::And(pats))
            }
            4 => {
                let count = u.int_in_range(1..=3)?;
                let pats = (0..count)
                    .map(|_| FactPattern::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(FactPattern::Or(pats))
            }
            _ => Ok(FactPattern::Not(Box::new(FactPattern::arbitrary(u)?))),
        }
    }
}

impl<'a> Arbitrary<'a> for FactQuery {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(FactQuery::Presence {
                key: Keyword::arbitrary(u)?,
            })
        } else {
            Ok(FactQuery::Value {
                key: Keyword::arbitrary(u)?,
                pattern: FactPattern::arbitrary(u)?,
            })
        }
    }
}

impl<'a> Arbitrary<'a> for CommandPattern {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=1)? {
            0 => Ok(CommandPattern::Literal(arb_alpha(u, 15)?)),
            _ => {
                let count = u.int_in_range(2..=3)?;
                let pats = (0..count)
                    .map(|_| Ok(CommandPattern::Literal(arb_alpha(u, 15)?)))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(CommandPattern::Or(pats))
            }
        }
    }
}

impl<'a> Arbitrary<'a> for Expr<Effect> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if !has_fuel(u) {
            return match u.int_in_range(0..=2)? {
                0 => Ok(Expr::Literal(arb_alpha(u, 15)?)),
                1 => Ok(Expr::Wildcard),
                _ => Ok(Expr::Regex(arb_regex(u)?)),
            };
        }
        match u.int_in_range(0..=7)? {
            0 => Ok(Expr::Literal(arb_alpha(u, 15)?)),
            1 => Ok(Expr::Wildcard),
            2 => Ok(Expr::Regex(arb_regex(u)?)),
            3 => {
                let count = u.int_in_range(1..=3)?;
                let exprs = (0..count)
                    .map(|_| Expr::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(Expr::And(exprs))
            }
            4 => {
                let count = u.int_in_range(1..=3)?;
                let exprs = (0..count)
                    .map(|_| Expr::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(Expr::Or(exprs))
            }
            5 => Ok(Expr::Not(Box::new(Expr::arbitrary(u)?))),
            6 => {
                let count = u.int_in_range(1..=2)?;
                let branches = (0..count)
                    .map(|_| ExprBranch::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(Expr::Cond(branches))
            }
            _ => Ok(Expr::Bind {
                key: Keyword::arbitrary(u)?,
                expr: Box::new(Expr::arbitrary(u)?),
            }),
        }
    }
}

impl<'a> Arbitrary<'a> for ExprBranch<Effect> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(ExprBranch {
            test: Expr::arbitrary(u)?,
            effect: Effect::arbitrary(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for PosTerm {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let quantifier = Quantifier::arbitrary(u)?;
        // Bound group nesting: only branch into a group when the entropy budget
        // is healthy, and require a non-empty sub-sequence.
        if u.arbitrary()? && !u.is_empty() {
            let count = u.int_in_range(1..=3)?;
            let seq = (0..count)
                .map(|_| PosTerm::arbitrary(u))
                .collect::<arbitrary::Result<Vec<_>>>()?;
            Ok(PosTerm::group(quantifier, seq).expect("count >= 1"))
        } else {
            Ok(PosTerm::single(quantifier, Expr::arbitrary(u)?))
        }
    }
}

impl<'a> Arbitrary<'a> for ArgPattern {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=3)? {
            0 => {
                let count = u.int_in_range(0..=3)?;
                let patterns = (0..count)
                    .map(|_| PosTerm::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(ArgPattern::Ordered {
                    mode: MatchMode::Positional,
                    patterns,
                    continuation: None,
                })
            }
            1 => {
                let count = u.int_in_range(0..=3)?;
                let patterns = (0..count)
                    .map(|_| PosTerm::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(ArgPattern::Ordered {
                    mode: MatchMode::Exact,
                    patterns,
                    continuation: None,
                })
            }
            2 => {
                let count = u.int_in_range(1..=3)?;
                let exprs = (0..count)
                    .map(|_| Expr::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(ArgPattern::Anywhere(exprs))
            }
            _ => {
                let count = u.int_in_range(1..=3)?;
                let exprs = (0..count)
                    .map(|_| Expr::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(ArgPattern::Forbidden(exprs))
            }
        }
    }
}

// --- AST ---

impl<'a> Arbitrary<'a> for Effect {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let reason: Option<String> = if u.arbitrary()? {
            Some(arb_alpha(u, 20)?)
        } else {
            None
        };

        if !has_fuel(u) {
            return match u.int_in_range(0..=2)? {
                0 => Ok(Effect::Terminal {
                    decision: Decision::arbitrary(u)?,
                    reason,
                }),
                1 => Ok(Effect::CommandPattern(CommandPattern::arbitrary(u)?)),
                _ => Ok(Effect::ArgPattern(ArgPattern::arbitrary(u)?)),
            };
        }

        match u.int_in_range(0..=7)? {
            0 => Ok(Effect::Terminal {
                decision: Decision::arbitrary(u)?,
                reason,
            }),
            1 => Ok(Effect::CommandPattern(CommandPattern::arbitrary(u)?)),
            2 => Ok(Effect::ArgPattern(ArgPattern::arbitrary(u)?)),
            3 => {
                let count = u.int_in_range(1..=3)?;
                let effects = (0..count)
                    .map(|_| Spanned::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(Effect::And { effects })
            }
            4 => {
                let count = u.int_in_range(1..=3)?;
                let effects = (0..count)
                    .map(|_| Spanned::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(Effect::Or { effects })
            }
            5 => Ok(Effect::Not {
                effect: Box::new(Spanned::arbitrary(u)?),
            }),
            6 => Ok(Effect::When {
                predicate: Spanned::arbitrary(u)?,
                effect: Box::new(Spanned::arbitrary(u)?),
            }),
            _ => Ok(Effect::If {
                predicate: Spanned::arbitrary(u)?,
                then_effect: Box::new(Spanned::arbitrary(u)?),
                else_effect: Box::new(Spanned::arbitrary(u)?),
            }),
        }
    }
}

impl<'a> Arbitrary<'a> for Predicate {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if !has_fuel(u) {
            return match u.int_in_range(0..=1)? {
                0 => Ok(Predicate::Fact(FactQuery::arbitrary(u)?)),
                _ => Ok(Predicate::Arg(ArgPattern::arbitrary(u)?)),
            };
        }
        match u.int_in_range(0..=4)? {
            0 => Ok(Predicate::Fact(FactQuery::arbitrary(u)?)),
            1 => Ok(Predicate::Arg(ArgPattern::arbitrary(u)?)),
            2 => {
                let count = u.int_in_range(2..=3)?;
                let preds = (0..count)
                    .map(|_| Predicate::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(Predicate::And(preds))
            }
            3 => {
                let count = u.int_in_range(2..=3)?;
                let preds = (0..count)
                    .map(|_| Predicate::arbitrary(u))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                Ok(Predicate::Or(preds))
            }
            _ => Ok(Predicate::Not(Box::new(Predicate::arbitrary(u)?))),
        }
    }
}

impl<'a> Arbitrary<'a> for Rule {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Rule {
            command_effect: Spanned::arbitrary(u)?,
            effect: Spanned::arbitrary(u)?,
            checks: vec![],
            provenance: Provenance::PrimaryConfig,
            span: Span::new(0, 0),
        })
    }
}

impl<'a> Arbitrary<'a> for crate::EntryEnv {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let count = u.int_in_range(0..=4)?;
        let mut names = Vec::with_capacity(count);
        for _ in 0..count {
            names.push(arb_alpha(u, 12)?);
        }
        Ok(crate::EntryEnv::from_names(names))
    }
}

impl<'a> Arbitrary<'a> for Check {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Check {
            command: arb_alpha(u, 15)?,
            expected: Decision::arbitrary(u)?,
            context: ContextFacts::arbitrary(u)?,
            entry_env: crate::EntryEnv::arbitrary(u)?,
            span: Span::new(0, 0),
        })
    }
}

impl<'a> Arbitrary<'a> for Define {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Define {
            name: arb_alpha(u, 15)?,
            predicate: Spanned::arbitrary(u)?,
            provenance: Provenance::PrimaryConfig,
            span: Span::new(0, 0),
        })
    }
}

impl<'a> Arbitrary<'a> for SecurityConfig {
    fn arbitrary(_u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(SecurityConfig::default())
    }
}

impl<'a> Arbitrary<'a> for Config {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let rule_count = u.int_in_range(0..=5)?;
        let rules = (0..rule_count)
            .map(|_| Rule::arbitrary(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        Ok(Config {
            defines: vec![],
            rules,
            security: SecurityConfig::default(),
            checks: vec![],
            style_specs: vec![],
            parsers: vec![],
            audit: Default::default(),
            matcher_budget: Default::default(),
        })
    }
}
