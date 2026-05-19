// Producer/renderer seam for trace output.
//
// `TraceNode` is the opaque tree the trace producer emits and the
// renderers consume. Fields are private; the constructor surface admits
// only valid (Role, Evidence) shapes. Renderers SHALL access node
// content via accessors only — they MUST NOT pattern-match on internal
// enum variants. See `openspec/specs/output-rendering/spec.md`.

use std::collections::BTreeSet;

use may_i_core::Decision;

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

    pub fn plain_broken_list(children: Vec<TraceNode>) -> Self {
        Self {
            body: Body::List(children),
            role: Role::Plain,
            evidence: None,
            dimmed: false,
            layout: Layout::AlwaysBreak,
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

    /// Atom payload, or `None` if this node is a list.
    pub fn label(&self) -> Option<&str> {
        match &self.body {
            Body::Atom(s) => Some(s),
            Body::List(_) => None,
        }
    }

    /// List children, or empty if this node is an atom.
    pub fn children(&self) -> &[TraceNode] {
        match &self.body {
            Body::Atom(_) => &[],
            Body::List(cs) => cs,
        }
    }

    /// Mark this node and its subtree as dimmed.
    pub fn into_dimmed(mut self) -> Self {
        self.dimmed = true;
        if let Body::List(cs) = &mut self.body {
            *cs = cs.drain(..).map(|c| c.into_dimmed()).collect();
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

    /// Arg-pattern node carrying set-membership evidence (anywhere/forbidden).
    pub fn arg_set_membership(
        children: Vec<TraceNode>,
        token: String,
        observed: Vec<String>,
        matched: bool,
    ) -> Self {
        Self {
            body: Body::List(children),
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

    /// Arg-pattern node carrying an authorise-style captured value.
    pub fn arg_captured(children: Vec<TraceNode>, source: CaptureSource, value: String) -> Self {
        Self {
            body: Body::List(children),
            role: Role::ArgMatch,
            evidence: Some(Evidence::CapturedValue { source, value }),
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    /// Arg-pattern node with no per-token evidence (predicate or wrapper).
    pub fn arg_plain_list(children: Vec<TraceNode>, matched: bool) -> Self {
        Self {
            body: Body::List(children),
            role: Role::ArgMatch,
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

    /// Fact query that observed values for its key.
    pub fn fact_query_values(
        children: Vec<TraceNode>,
        expected: String,
        observed: BTreeSet<String>,
        matched: bool,
    ) -> Self {
        Self {
            body: Body::List(children),
            role: Role::FactQuery,
            evidence: Some(Evidence::FactValues {
                expected,
                observed,
                matched,
            }),
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    /// Fact query that failed because the key was absent from context.
    pub fn fact_query_absent(children: Vec<TraceNode>) -> Self {
        Self {
            body: Body::List(children),
            role: Role::FactQuery,
            evidence: Some(Evidence::FactAbsent),
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    /// Fact query with no observed-value details (e.g. presence-only).
    pub fn fact_query_match(children: Vec<TraceNode>, matched: bool) -> Self {
        Self {
            body: Body::List(children),
            role: Role::FactQuery,
            evidence: Some(Evidence::Match { matched }),
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

    /// Effect-decision list (e.g. `(effect :allow "reason")`).
    pub fn effect_decision_list(
        children: Vec<TraceNode>,
        decision: Decision,
        reason: Option<String>,
    ) -> Self {
        Self {
            body: Body::List(children),
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

    /// Bind (`#var (authorise)`) match.
    pub fn bind_match(children: Vec<TraceNode>, key: String, value: Option<String>) -> Self {
        Self {
            body: Body::List(children),
            role: Role::BindMatch { key },
            evidence: Some(Evidence::Bind { value }),
            dimmed: false,
            layout: Layout::Auto,
        }
    }

    /// Regex match site.
    pub fn regex_match_atom(
        label: impl Into<String>,
        pattern: String,
        actual: String,
        matched: bool,
    ) -> Self {
        Self {
            body: Body::Atom(label.into()),
            role: Role::RegexMatch,
            evidence: Some(Evidence::Regex {
                pattern,
                actual,
                matched,
            }),
            dimmed: false,
            layout: Layout::Auto,
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

    /// Replace this node's body's child at `i`. Used by structural-decision
    /// helpers in the producer (e.g. cond-branch evidence relocation).
    pub(crate) fn map_child<F>(mut self, i: usize, f: F) -> Self
    where
        F: FnOnce(TraceNode) -> TraceNode,
    {
        if let Body::List(cs) = &mut self.body
            && i < cs.len()
        {
            let child = std::mem::replace(&mut cs[i], TraceNode::plain_atom(""));
            cs[i] = f(child);
        }
        self
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
    fn plain_broken_list_uses_always_break_layout() {
        let n = TraceNode::plain_broken_list(vec![TraceNode::plain_atom("x")]);
        assert_eq!(n.layout(), Layout::AlwaysBreak);
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
