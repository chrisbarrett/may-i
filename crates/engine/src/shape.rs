//! Binding shapes — the contributor-facing type vocabulary the engine
//! checks rule bodies against.
//!
//! **Contributor-facing.** The word *shape* and the variant names
//! (`Token`, `Command`, `CollectionToken`, `Count`) are internal. The
//! user-facing surface (error messages, REFERENCE.md) describes the same
//! distinctions as "a single value", "a command line", "a list of
//! values", and "a count" — see the `binding-shapes` spec, decision D5,
//! and [`Shape::user_phrase`].
//!
//! A binding's shape is a pure function of its parser-side declaration
//! (decision D2); the rule body never narrows or widens it. The shape is
//! computed by [`shape_of_parameter`] / [`shape_of_flag`] /
//! [`shape_of_positional`] / [`shape_of_rest`] and collected per parser
//! into a [`ShapeEnv`].

use std::collections::HashMap;

use may_i_core::Span;
use may_i_core::ast::{
    BindingName, Capture, FlagDecl, ParamShapeForm, ParameterDecl, ParameterTreatment,
    PositionalDecl, ResolvedParser,
};
use may_i_core::pattern::Quantifier;

/// The closed, four-member shape vocabulary (decision D1). No subtyping;
/// `Token` and `Command` are distinct even though both store strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Shape {
    /// A single argv token.
    Token,
    /// A captured value that is itself a command line.
    Command,
    /// An ordered sequence of zero or more tokens.
    CollectionToken,
    /// A non-negative integer derived from counting flag occurrences.
    Count,
}

impl Shape {
    /// The user-facing phrase for this shape (decision D5). Rendered
    /// error text uses these phrases; the internal variant names SHALL
    /// NOT leak into user-facing prose.
    pub fn user_phrase(self) -> &'static str {
        match self {
            Shape::Token => "a single value",
            Shape::Command => "a command line",
            Shape::CollectionToken => "a list of values",
            Shape::Count => "a count",
        }
    }
}

/// Shape of a `(parameter …)` declaration's binding.
///
/// `(many-till …)` captures and `(command …)`/authorise treatments are
/// command-bearing; `(set …)` is a collection; everything else (the
/// unannotated form, `(one …)`, `(last …)`) is a single token.
pub fn shape_of_parameter(decl: &ParameterDecl) -> Shape {
    if matches!(decl.capture, Capture::ManyTill { .. }) {
        return Shape::Command;
    }
    if matches!(decl.treatment, ParameterTreatment::Authorise) {
        return Shape::Command;
    }
    match decl.shape_form {
        ParamShapeForm::Set => Shape::CollectionToken,
        ParamShapeForm::Command => Shape::Command,
        ParamShapeForm::Unannotated | ParamShapeForm::One | ParamShapeForm::Last => Shape::Token,
    }
}

/// Shape of a `(flag …)` declaration's binding, or `None` when the flag
/// declares no `(count #v)` binding (a presence-only flag carries no
/// value for rule bodies to reference).
pub fn shape_of_flag(decl: &FlagDecl) -> Option<Shape> {
    decl.count_binding.as_ref().map(|_| Shape::Count)
}

/// Shape of a `(positional …)` declaration's binding. A repeating
/// quantifier (`*`/`+`) yields a collection; `one`/`?` yields a single
/// token.
pub fn shape_of_positional(decl: &PositionalDecl) -> Shape {
    match decl.quantifier {
        Quantifier::ZeroOrMore | Quantifier::OneOrMore => Shape::CollectionToken,
        Quantifier::One | Quantifier::Optional => Shape::Token,
    }
}

/// Shape of a `(rest #v)` binding — always a command line (the token
/// list whose first element is the inner command name).
pub fn shape_of_rest() -> Shape {
    Shape::Command
}

/// The kind of declaration that bound a `#var`, carrying the rewrite
/// material each kind admits (decision D1). Hint selection dispatches on
/// this so a remedy never proposes a form the declaration cannot take —
/// e.g. a `(parameter NAME …)` rewrite for a `Positional` binding.
///
/// `Parameter`/`Flag` carry the declaring NAME (for parameter/flag
/// rewrites); `Positional`/`Rest` carry none, because those forms have no
/// name and no `(command …)` arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclKind {
    Parameter { name: String },
    Flag { name: String },
    Positional,
    Rest,
}

/// A binding's declared shape, the source span of the declaration that
/// assigned it (when known — synthetic parsers carry no spans), and the
/// kind of declaration that bound it (for kind-aware rewrite hints).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeDecl {
    pub shape: Shape,
    pub decl_span: Option<Span>,
    pub decl_kind: DeclKind,
}

/// The declared shapes of every `#var` a parser body binds, keyed by
/// name. Built once per parser (decision D2: shapes come from
/// declarations alone) and consulted by the shape checker.
#[derive(Debug, Clone, Default)]
pub struct ShapeEnv {
    map: HashMap<BindingName, ShapeDecl>,
}

impl ShapeEnv {
    /// Collect the declared shapes from a resolved parser, pairing each
    /// with the span of its `#var` declaration atom.
    pub fn from_parser(parser: &ResolvedParser) -> Self {
        let mut map = HashMap::new();
        let mut insert = |name: &BindingName, shape: Shape, decl_kind: DeclKind| {
            map.insert(
                name.clone(),
                ShapeDecl {
                    shape,
                    decl_span: parser.binding_spans.get(name).copied(),
                    decl_kind,
                },
            );
        };
        // Parameters and flags are name-bearing by construction (the
        // config parser rejects empty name vectors; synthetic parsers
        // supply a spelling too). Requiring a spelling here keeps that
        // invariant at the boundary — `DeclKind::Parameter`/`Flag` never
        // carries an empty name, so a hint can never render
        // `(parameter "" …)`. A name-less declaration is silently skipped
        // rather than fabricating a placeholder.
        for decl in &parser.parameters {
            if let (Some(binding), Some(spelling)) = (&decl.binding, decl.names.first()) {
                insert(
                    binding,
                    shape_of_parameter(decl),
                    DeclKind::Parameter {
                        name: spelling.clone(),
                    },
                );
            }
        }
        for decl in &parser.flags {
            if let (Some(binding), Some(shape), Some(spelling)) =
                (&decl.count_binding, shape_of_flag(decl), decl.names.first())
            {
                insert(
                    binding,
                    shape,
                    DeclKind::Flag {
                        name: spelling.clone(),
                    },
                );
            }
        }
        for decl in &parser.positionals {
            if let Some(name) = &decl.binding {
                insert(name, shape_of_positional(decl), DeclKind::Positional);
            }
        }
        if let Some(name) = &parser.rest {
            insert(name, shape_of_rest(), DeclKind::Rest);
        }
        Self { map }
    }

    /// The declared shape of `name`, or `None` if the parser binds no
    /// such name.
    pub fn get(&self, name: &BindingName) -> Option<Shape> {
        self.map.get(name).map(|d| d.shape)
    }

    /// The full declaration (shape + span) for `name`.
    pub fn get_decl(&self, name: &BindingName) -> Option<ShapeDecl> {
        self.map.get(name).cloned()
    }

    /// Build from a precomputed name → declaration map.
    pub fn from_map(map: HashMap<BindingName, ShapeDecl>) -> Self {
        Self { map }
    }

    /// True if the parser binds no `#var` at all.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Iterate over the declared bindings.
    pub fn iter(&self) -> impl Iterator<Item = (&BindingName, &ShapeDecl)> {
        self.map.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::ast::{FlagsMode, Style};
    use may_i_core::pattern::Expr;

    fn bn(s: &str) -> BindingName {
        BindingName::parse(s).unwrap()
    }

    fn param(shape_form: ParamShapeForm) -> ParameterDecl {
        ParameterDecl {
            names: vec!["o".into()],
            treatment: ParameterTreatment::None,
            shape_form,
            capture: Capture::Single,
            binding: Some(bn("v")),
        }
    }

    #[test]
    fn unannotated_parameter_is_token() {
        assert_eq!(
            shape_of_parameter(&param(ParamShapeForm::Unannotated)),
            Shape::Token
        );
    }

    #[test]
    fn one_and_last_are_token() {
        assert_eq!(
            shape_of_parameter(&param(ParamShapeForm::One)),
            Shape::Token
        );
        assert_eq!(
            shape_of_parameter(&param(ParamShapeForm::Last)),
            Shape::Token
        );
    }

    #[test]
    fn set_is_collection() {
        assert_eq!(
            shape_of_parameter(&param(ParamShapeForm::Set)),
            Shape::CollectionToken
        );
    }

    #[test]
    fn command_form_is_command() {
        assert_eq!(
            shape_of_parameter(&param(ParamShapeForm::Command)),
            Shape::Command
        );
    }

    #[test]
    fn authorise_treatment_is_command() {
        let mut d = param(ParamShapeForm::Unannotated);
        d.treatment = ParameterTreatment::Authorise;
        assert_eq!(shape_of_parameter(&d), Shape::Command);
    }

    #[test]
    fn many_till_capture_is_command() {
        let mut d = param(ParamShapeForm::Unannotated);
        d.capture = Capture::ManyTill {
            terminator: Expr::Literal(";".into()),
        };
        assert_eq!(shape_of_parameter(&d), Shape::Command);
    }

    #[test]
    fn flag_count_is_count_otherwise_none() {
        assert_eq!(
            shape_of_flag(&FlagDecl {
                names: vec!["v".into()],
                count_binding: Some(bn("n")),
            }),
            Some(Shape::Count)
        );
        assert_eq!(shape_of_flag(&FlagDecl::new(vec!["v".into()])), None);
    }

    #[test]
    fn positional_shape_follows_quantifier() {
        let mk = |q| PositionalDecl {
            binding: Some(bn("p")),
            pattern: Expr::Wildcard,
            quantifier: q,
        };
        assert_eq!(shape_of_positional(&mk(Quantifier::One)), Shape::Token);
        assert_eq!(shape_of_positional(&mk(Quantifier::Optional)), Shape::Token);
        assert_eq!(
            shape_of_positional(&mk(Quantifier::ZeroOrMore)),
            Shape::CollectionToken
        );
        assert_eq!(
            shape_of_positional(&mk(Quantifier::OneOrMore)),
            Shape::CollectionToken
        );
    }

    #[test]
    fn rest_is_command() {
        assert_eq!(shape_of_rest(), Shape::Command);
    }

    #[test]
    fn shape_env_collects_every_binding_kind() {
        let parser = ResolvedParser {
            program: "ssh".into(),
            style: Style::default_gnu(),
            flags: vec![FlagDecl {
                names: vec!["v".into()],
                count_binding: Some(bn("verbosity")),
            }],
            parameters: vec![ParameterDecl {
                names: vec!["o".into()],
                treatment: ParameterTreatment::None,
                shape_form: ParamShapeForm::Set,
                capture: Capture::Single,
                binding: Some(bn("opts")),
            }],
            positionals: vec![PositionalDecl {
                binding: Some(bn("host")),
                pattern: Expr::Wildcard,
                quantifier: Quantifier::One,
            }],
            flags_mode: FlagsMode::Posix,
            rest: Some(bn("cmd")),
            binding_spans: Default::default(),
        };
        let env = ShapeEnv::from_parser(&parser);
        assert_eq!(env.get(&bn("opts")), Some(Shape::CollectionToken));
        assert_eq!(env.get(&bn("verbosity")), Some(Shape::Count));
        assert_eq!(env.get(&bn("host")), Some(Shape::Token));
        assert_eq!(env.get(&bn("cmd")), Some(Shape::Command));
        assert_eq!(env.get(&bn("nope")), None);
    }

    #[test]
    fn shape_env_records_declaration_kind_per_source() {
        let parser = ResolvedParser {
            program: "ssh".into(),
            style: Style::default_gnu(),
            flags: vec![FlagDecl {
                names: vec!["v".into()],
                count_binding: Some(bn("verbosity")),
            }],
            parameters: vec![ParameterDecl {
                names: vec!["o".into()],
                treatment: ParameterTreatment::None,
                shape_form: ParamShapeForm::Set,
                capture: Capture::Single,
                binding: Some(bn("opts")),
            }],
            positionals: vec![PositionalDecl {
                binding: Some(bn("host")),
                pattern: Expr::Wildcard,
                quantifier: Quantifier::One,
            }],
            flags_mode: FlagsMode::Posix,
            rest: Some(bn("cmd")),
            binding_spans: Default::default(),
        };
        let env = ShapeEnv::from_parser(&parser);
        assert_eq!(
            env.get_decl(&bn("opts")).map(|d| d.decl_kind),
            Some(DeclKind::Parameter { name: "o".into() })
        );
        assert_eq!(
            env.get_decl(&bn("verbosity")).map(|d| d.decl_kind),
            Some(DeclKind::Flag { name: "v".into() })
        );
        assert_eq!(
            env.get_decl(&bn("host")).map(|d| d.decl_kind),
            Some(DeclKind::Positional)
        );
        assert_eq!(
            env.get_decl(&bn("cmd")).map(|d| d.decl_kind),
            Some(DeclKind::Rest)
        );
    }
}
