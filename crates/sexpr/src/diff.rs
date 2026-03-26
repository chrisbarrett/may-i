//! Diff computation and annotation for CST nodes.
//!
//! This module provides types for diff annotations. The actual diff computation
//! has been moved to using text-based diff with the `similar` crate.

use crate::cst::TriviaAnn;

/// Type of change for a diff annotation.
#[derive(Debug, Clone, PartialEq)]
pub enum ChangeType {
    /// Node is unchanged between original and migrated.
    Unchanged,
    /// Node has been modified, with the replacement stored.
    Modified {
        after: crate::cst::CstNode<TriviaAnn>,
    },
    /// Node has been deleted (no corresponding migrated node).
    Deleted,
}

impl ChangeType {
    /// Check if this change type is "unchanged".
    pub fn is_unchanged(&self) -> bool {
        matches!(self, ChangeType::Unchanged)
    }

    /// Check if this change type is "modified".
    pub fn is_modified(&self) -> bool {
        matches!(self, ChangeType::Modified { .. })
    }

    /// Check if this change type is "deleted".
    pub fn is_deleted(&self) -> bool {
        matches!(self, ChangeType::Deleted)
    }
}

/// Diff annotation combining trivia and change status.
#[derive(Debug, Clone, PartialEq)]
pub struct DiffAnn {
    /// Original trivia annotation.
    pub trivia: TriviaAnn,
    /// Change status for this node.
    pub change: ChangeType,
}

/// Type alias for plain CST (with only trivia annotation).
pub type PlainCst = crate::cst::CstNode<TriviaAnn>;

/// Type alias for diff-annotated CST.
pub type DiffCst = crate::cst::CstNode<DiffAnn>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_type_helpers() {
        assert!(ChangeType::Unchanged.is_unchanged());
        assert!(!ChangeType::Unchanged.is_modified());
        assert!(!ChangeType::Unchanged.is_deleted());

        let modified = ChangeType::Modified {
            after: crate::cst::CstNode {
                ann: TriviaAnn::default(),
                shape: crate::cst::ShapeF::Atom("test".into()),
            },
        };
        assert!(!modified.is_unchanged());
        assert!(modified.is_modified());
        assert!(!modified.is_deleted());

        assert!(!ChangeType::Deleted.is_unchanged());
        assert!(!ChangeType::Deleted.is_modified());
        assert!(ChangeType::Deleted.is_deleted());
    }
}
