// Producer/renderer seam for trace output.
//
// `TraceNode` is the opaque tree the trace producer emits and the
// renderers consume. Fields are private; the constructor surface admits
// only valid (Role, Evidence) shapes. Renderers SHALL access node
// content via accessors only — they MUST NOT pattern-match on internal
// enum variants. See `openspec/specs/output-rendering/spec.md`.

use std::collections::BTreeSet;

use may_i_core::Decision;
use may_i_core::doc::{Doc, DocF, LayoutHint};

#[derive(Clone, Debug)]
pub struct TraceNode {
    body: Body,
    role: Role,
    evidence: Option<Evidence>,
    dimmed: bool,
    layout: Layout,
}

#[derive(Clone, Debug)]
enum Body {
    Atom(String),
    List(Vec<TraceNode>),
    Vector(Vec<TraceNode>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Auto,
    AlwaysBreak,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    Plain,
    Rule { line: Option<usize> },
    Command,
    ArgMatch,
    FactQuery,
    EffectDecision,
    VarRef { name: String },
    Combinator,
    BindMatch { key: String },
    RegexMatch,
    PositionalMatch,
    CollapsedEllipsis,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    Match {
        matched: bool,
    },
    SetMembership {
        token: String,
        observed: Vec<String>,
        matched: bool,
    },
    CapturedValue {
        source: CaptureSource,
        value: String,
    },
    FactValues {
        expected: String,
        observed: BTreeSet<String>,
        matched: bool,
    },
    FactAbsent,
    Decision {
        decision: Decision,
        reason: Option<String>,
    },
    Regex {
        pattern: String,
        actual: String,
        matched: bool,
    },
    Positional {
        actual: String,
        pattern_text: String,
        matched: bool,
    },
    Bind {
        value: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureSource {
    Tail,
    Parameter,
}

impl TraceNode {
    pub fn plain_atom(text: impl Into<String>) -> Self {
        Self {
            body: Body::Atom(text.into()),
            role: Role::Plain,
            evidence: None,
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    pub fn plain_list(children: Vec<TraceNode>) -> Self {
        Self {
            body: Body::List(children),
            role: Role::Plain,
            evidence: None,
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    pub fn plain_vector(children: Vec<TraceNode>) -> Self {
        Self {
            body: Body::Vector(children),
            role: Role::Plain,
            evidence: None,
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    /// Collapsed-ellipsis stand-in for skipped children. Always dimmed,
    /// always the atom "…".
    pub fn ellipsis() -> Self {
        Self {
            body: Body::Atom("…".into()),
            role: Role::CollapsedEllipsis,
            evidence: None,
            dimmed: true,
            layout: Layout::Auto,
        }
    }

    pub fn role(&self) -> &Role {
        &self.role
    }

    pub fn evidence(&self) -> Option<&Evidence> {
        self.evidence.as_ref()
    }

    pub fn dimmed(&self) -> bool {
        self.dimmed
    }

    pub fn layout(&self) -> Layout {
        self.layout
    }

    /// Atom payload, or `None` if this node is a list/vector.
    pub fn label(&self) -> Option<&str> {
        match &self.body {
            Body::Atom(s) => Some(s),
            Body::List(_) | Body::Vector(_) => None,
        }
    }

    /// List children, or empty if this node is an atom.
    pub fn children(&self) -> &[TraceNode] {
        match &self.body {
            Body::Atom(_) => &[],
            Body::List(cs) | Body::Vector(cs) => cs,
        }
    }

    /// True if this node renders with `[ ]` brackets rather than `( )`.
    pub fn is_vector(&self) -> bool {
        matches!(self.body, Body::Vector(_))
    }

    /// Mark this node and its subtree as dimmed.
    pub fn into_dimmed(mut self) -> Self {
        self.dimmed = true;
        match &mut self.body {
            Body::List(cs) | Body::Vector(cs) => {
                *cs = cs.drain(..).map(|c| c.into_dimmed()).collect();
            }
            Body::Atom(_) => {}
        }
        self
    }

    /// Command-pattern match site, atomic (literal pattern).
    pub fn command_atom(label: impl Into<String>, matched: bool) -> Self {
        Self {
            body: Body::Atom(label.into()),
            role: Role::Command,
            evidence: Some(Evidence::Match { matched }),
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    /// Command-pattern match site, composite (e.g. `(or …)` over sub-patterns).
    pub fn command_list(children: Vec<TraceNode>, matched: bool) -> Self {
        Self {
            body: Body::List(children),
            role: Role::Command,
            evidence: Some(Evidence::Match { matched }),
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    /// Per-token atom annotated with set-membership evidence.
    pub fn arg_token_atom(
        label: impl Into<String>,
        token: String,
        observed: Vec<String>,
        matched: bool,
    ) -> Self {
        Self {
            body: Body::Atom(label.into()),
            role: Role::ArgMatch,
            evidence: Some(Evidence::SetMembership {
                token,
                observed,
                matched,
            }),
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    /// Effect-decision (allow / ask / deny) atom carrying its outcome.
    pub fn effect_decision_atom(
        label: impl Into<String>,
        decision: Decision,
        reason: Option<String>,
    ) -> Self {
        Self {
            body: Body::Atom(label.into()),
            role: Role::EffectDecision,
            evidence: Some(Evidence::Decision { decision, reason }),
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    /// Named-predicate (`define`) reference.
    pub fn var_ref(children: Vec<TraceNode>, name: String, matched: bool) -> Self {
        Self {
            body: Body::List(children),
            role: Role::VarRef { name },
            evidence: Some(Evidence::Match { matched }),
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    /// Combinator / quantifier node (`and`, `or`, `not`, `if`, `cond`,
    /// `when`, `unless`, `anywhere`). `broken` selects `Layout::AlwaysBreak`.
    pub fn combinator(children: Vec<TraceNode>, satisfied: bool, broken: bool) -> Self {
        Self {
            body: Body::List(children),
            role: Role::Combinator,
            evidence: Some(Evidence::Match { matched: satisfied }),
            dimmed: false,
            layout: if broken {
                Layout::AlwaysBreak
            } else {
                Layout::Auto
            },
        }
    }

    /// Combinator without rendered evidence (used for shape-only combinators
    /// like `not`'s plain wrapper).
    pub fn combinator_plain(children: Vec<TraceNode>, broken: bool) -> Self {
        Self {
            body: Body::List(children),
            role: Role::Combinator,
            evidence: None,
            dimmed: false,
            layout: if broken {
                Layout::AlwaysBreak
            } else {
                Layout::Auto
            },
        }
    }

    /// Positional argv match (literal vs actual).
    pub fn positional_atom(
        label: impl Into<String>,
        actual: String,
        pattern_text: String,
        matched: bool,
    ) -> Self {
        Self {
            body: Body::Atom(label.into()),
            role: Role::PositionalMatch,
            evidence: Some(Evidence::Positional {
                actual,
                pattern_text,
                matched,
            }),
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    /// Rule-level node carrying optional source line. `matched` is used by
    /// renderers that highlight a rule as a whole.
    pub fn rule(children: Vec<TraceNode>, line: Option<usize>, matched: bool) -> Self {
        Self {
            body: Body::List(children),
            role: Role::Rule { line },
            evidence: Some(Evidence::Match { matched }),
            dimmed: false,
            layout: Layout::AlwaysBreak,
        }
    }

    /// Build a plain `TraceNode` tree from an unannotated `Doc`. List and
    /// Vector docs preserve their bracket style for renderer fidelity.
    pub fn from_doc(doc: Doc<()>) -> Self {
        let layout = match doc.layout {
            LayoutHint::AlwaysBreak => Layout::AlwaysBreak,
            _ => Layout::Auto,
        };
        let body = match doc.node {
            DocF::Atom(s) => Body::Atom(s),
            DocF::List(cs) => Body::List(cs.into_iter().map(TraceNode::from_doc).collect()),
            DocF::Vector(cs) => Body::Vector(cs.into_iter().map(TraceNode::from_doc).collect()),
        };
        Self {
            body,
            role: Role::Plain,
            evidence: None,
            dimmed: doc.dimmed,
            layout,
        }
    }

    /// Replace this node's role and evidence in-place.
    pub(crate) fn with_role_and_evidence(mut self, role: Role, evidence: Option<Evidence>) -> Self {
        self.role = role;
        self.evidence = evidence;
        self
    }

    /// Replace this node's layout hint.
    pub(crate) fn with_layout(mut self, layout: Layout) -> Self {
        self.layout = layout;
        self
    }

    /// Mark this node (not its subtree) as dimmed.
    pub(crate) fn with_dimmed_self(mut self) -> Self {
        self.dimmed = true;
        self
    }

    /// Mutable access to list children for in-place rewrites by the
    /// producer (used to relocate evidence onto cond-branch bodies).
    pub(crate) fn children_mut(&mut self) -> Option<&mut Vec<TraceNode>> {
        match &mut self.body {
            Body::List(cs) | Body::Vector(cs) => Some(cs),
            Body::Atom(_) => None,
        }
    }

    /// Convert this node into a list of children if it is a list/vector;
    /// otherwise return None (atoms cannot be flattened).
    pub(crate) fn into_children(self) -> Option<Vec<TraceNode>> {
        match self.body {
            Body::List(cs) | Body::Vector(cs) => Some(cs),
            Body::Atom(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_atom_has_plain_role_no_evidence_not_dimmed() {
        let n = TraceNode::plain_atom("rule");
        assert_eq!(n.role(), &Role::Plain);
        assert_eq!(n.evidence(), None);
        assert!(!n.dimmed());
        assert_eq!(n.label(), Some("rule"));
        assert!(n.children().is_empty());
    }

    #[test]
    fn plain_list_has_no_label_and_yields_children_in_order() {
        let n = TraceNode::plain_list(vec![TraceNode::plain_atom("a"), TraceNode::plain_atom("b")]);
        assert_eq!(n.label(), None);
        assert_eq!(n.children().len(), 2);
        assert_eq!(n.children()[0].label(), Some("a"));
        assert_eq!(n.children()[1].label(), Some("b"));
        assert_eq!(n.layout(), Layout::Auto);
    }

    #[test]
    fn ellipsis_is_dimmed_collapsed_atom() {
        let n = TraceNode::ellipsis();
        assert_eq!(n.role(), &Role::CollapsedEllipsis);
        assert_eq!(n.label(), Some("…"));
        assert!(n.dimmed());
        assert_eq!(n.evidence(), None);
    }

    #[test]
    fn into_dimmed_marks_subtree_dimmed() {
        let n = TraceNode::plain_list(vec![
            TraceNode::plain_atom("a"),
            TraceNode::plain_list(vec![TraceNode::plain_atom("b")]),
        ])
        .into_dimmed();
        assert!(n.dimmed());
        assert!(n.children()[0].dimmed());
        assert!(n.children()[1].dimmed());
        assert!(n.children()[1].children()[0].dimmed());
    }
}
