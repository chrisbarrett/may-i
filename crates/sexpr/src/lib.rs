pub mod cst;
mod sexpr;
mod span;

#[cfg(any(test, feature = "test-generators"))]
pub mod test_generators;

pub use cst::{
    CstNode, RewriteRule, Shape, ShapeF, Trivia, TriviaAnn, parse as parse_cst,
    rewrite_until_convergence,
};
pub use sexpr::{Sexpr, needs_quoting, quote_string};
pub use span::RawError;

/// Parse a string containing zero or more s-expressions.
///
/// This function uses the CST parser internally and converts the result to Sexpr
/// for backward compatibility.
#[must_use]
pub fn parse(input: &str) -> (Vec<Sexpr>, Vec<RawError>) {
    let (cst_nodes, errors) = parse_cst(input);
    let sexprs: Vec<Sexpr> = cst_nodes.iter().map(|n| n.to_sexpr()).collect();
    (sexprs, errors)
}
