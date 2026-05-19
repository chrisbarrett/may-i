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
