//! Diff computation and annotation for CST nodes.
//!
//! This module provides a form-wise diff mechanism that annotates CST nodes
//! with their change status (unchanged, modified, deleted).

use crate::cst::{CstNode, ShapeF, TriviaAnn};

/// Type of change for a diff annotation.
#[derive(Debug, Clone, PartialEq)]
pub enum ChangeType {
    /// Node is unchanged between original and migrated.
    Unchanged,
    /// Node has been modified, with the replacement stored.
    Modified { after: CstNode<TriviaAnn> },
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
pub type PlainCst = CstNode<TriviaAnn>;

/// Type alias for diff-annotated CST.
pub type DiffCst = CstNode<DiffAnn>;

/// Compute diff between original and migrated CSTs.
///
/// This function compares top-level forms and annotates each with its change status.
/// It performs a structural comparison to determine if forms are identical.
///
/// # Arguments
///
/// * `original` - The original CST nodes from parsing the input file.
/// * `migrated` - The migrated CST nodes after applying transformations.
///
/// # Returns
///
/// A vector of diff-annotated CST nodes, preserving the original structure
/// but with change annotations added.
pub fn compute_diff(original: Vec<PlainCst>, migrated: Vec<PlainCst>) -> Vec<DiffCst> {
    let mut result = Vec::new();
    let mut mig_iter = migrated.into_iter().peekable();

    for orig in original {
        // Determine the change type by comparing shapes
        let change = if let Some(mig) = mig_iter.peek() {
            if shapes_equal(&orig, mig) {
                // Shapes are equal - mark as unchanged and consume the migrated form
                mig_iter.next();
                ChangeType::Unchanged
            } else {
                // Shapes differ - mark as modified with the replacement
                ChangeType::Modified {
                    after: mig_iter.next().unwrap(),
                }
            }
        } else {
            // No more migrated nodes - this one was deleted
            ChangeType::Deleted
        };

        result.push(CstNode {
            ann: DiffAnn {
                trivia: orig.ann.clone(),
                change: change.clone(),
            },
            shape: orig
                .shape
                .map_ref(|child| Box::new(annotate_child(child, &change))),
        });
    }

    // Handle insertions: any remaining migrated nodes are insertions
    // We represent insertions as new nodes with empty trivia and Modified status
    for mig in mig_iter {
        result.push(CstNode {
            ann: DiffAnn {
                trivia: TriviaAnn::default(),
                change: ChangeType::Modified { after: mig },
            },
            shape: ShapeF::List(vec![]), // Placeholder, will be replaced
        });
    }

    result
}

/// Annotate a child node with the parent's change status.
/// For unchanged parents, children are also unchanged.
/// For modified/deleted parents, children inherit the parent's status.
fn annotate_child(child: &PlainCst, parent_change: &ChangeType) -> DiffCst {
    let change = match parent_change {
        ChangeType::Unchanged => ChangeType::Unchanged,
        ChangeType::Deleted => ChangeType::Deleted,
        ChangeType::Modified { .. } => {
            // For modified parents, we need to determine if this specific child
            // was modified. For now, mark as unchanged and let structural diff
            // handle it at the top level.
            ChangeType::Unchanged
        }
    };

    CstNode {
        ann: DiffAnn {
            trivia: child.ann.clone(),
            change: change.clone(),
        },
        shape: child
            .shape
            .map_ref(|c| Box::new(annotate_child(c, &change))),
    }
}

/// Compare two CST nodes for structural equality.
///
/// This compares the shape of the nodes (atoms, lists, etc.) without
/// considering trivia (whitespace, comments) or span information.
fn shapes_equal(a: &PlainCst, b: &PlainCst) -> bool {
    match (&a.shape, &b.shape) {
        (ShapeF::Atom(a_str), ShapeF::Atom(b_str)) => a_str == b_str,
        (ShapeF::Str(a_str), ShapeF::Str(b_str)) => a_str == b_str,
        (ShapeF::List(a_children), ShapeF::List(b_children)) => {
            if a_children.len() != b_children.len() {
                return false;
            }
            a_children
                .iter()
                .zip(b_children.iter())
                .all(|(a, b)| shapes_equal(a, b))
        }
        (ShapeF::Vector(a_children), ShapeF::Vector(b_children)) => {
            if a_children.len() != b_children.len() {
                return false;
            }
            a_children
                .iter()
                .zip(b_children.iter())
                .all(|(a, b)| shapes_equal(a, b))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cst::parse;

    fn parse_forms(input: &str) -> Vec<PlainCst> {
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty(), "Parse errors: {:?}", errors);
        nodes.into_iter().map(|b| *b).collect()
    }

    #[test]
    fn test_unchanged_form() {
        let input = "(foo bar)";
        let original = parse_forms(input);
        let migrated = parse_forms(input);

        let diff = compute_diff(original, migrated);

        assert_eq!(diff.len(), 1);
        assert!(diff[0].ann.change.is_unchanged());
    }

    #[test]
    fn test_modified_form() {
        let original = parse_forms("(old-syntax x)");
        let migrated = parse_forms("(new-syntax x)");

        let diff = compute_diff(original, migrated);

        assert_eq!(diff.len(), 1);
        assert!(diff[0].ann.change.is_modified());
    }

    #[test]
    fn test_deleted_form() {
        let original = parse_forms("(foo) (bar)");
        let migrated = parse_forms("(foo)");

        let diff = compute_diff(original, migrated);

        assert_eq!(diff.len(), 2);
        assert!(diff[0].ann.change.is_unchanged());
        assert!(diff[1].ann.change.is_deleted());
    }

    #[test]
    fn test_multiple_forms() {
        let original = parse_forms("(a) (b) (c)");
        let migrated = parse_forms("(a) (B) (c)");

        let diff = compute_diff(original, migrated);

        assert_eq!(diff.len(), 3);
        assert!(diff[0].ann.change.is_unchanged());
        assert!(diff[1].ann.change.is_modified());
        assert!(diff[2].ann.change.is_unchanged());
    }

    #[test]
    fn test_shapes_equal_atoms() {
        let a = parse_forms("foo");
        let b = parse_forms("foo");
        let c = parse_forms("bar");

        assert!(shapes_equal(&a[0], &b[0]));
        assert!(!shapes_equal(&a[0], &c[0]));
    }

    #[test]
    fn test_shapes_equal_lists() {
        let a = parse_forms("(foo bar)");
        let b = parse_forms("(foo bar)");
        let c = parse_forms("(foo baz)");

        assert!(shapes_equal(&a[0], &b[0]));
        assert!(!shapes_equal(&a[0], &c[0]));
    }

    #[test]
    fn test_shapes_equal_nested() {
        let a = parse_forms("(foo (bar baz))");
        let b = parse_forms("(foo (bar baz))");
        let c = parse_forms("(foo (bar qux))");

        assert!(shapes_equal(&a[0], &b[0]));
        assert!(!shapes_equal(&a[0], &c[0]));
    }

    #[test]
    fn test_diff_preserves_structure() {
        let original = parse_forms("(foo (bar baz))");
        let migrated = parse_forms("(foo (bar baz))");

        let diff = compute_diff(original, migrated);

        // Check that the structure is preserved
        if let ShapeF::List(children) = &diff[0].shape {
            assert_eq!(children.len(), 2);
            if let ShapeF::List(nested) = &children[1].shape {
                assert_eq!(nested.len(), 2);
            } else {
                panic!("expected nested list");
            }
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn test_change_type_helpers() {
        assert!(ChangeType::Unchanged.is_unchanged());
        assert!(!ChangeType::Unchanged.is_modified());
        assert!(!ChangeType::Unchanged.is_deleted());

        let modified = ChangeType::Modified {
            after: parse_forms("(foo)")[0].clone(),
        };
        assert!(!modified.is_unchanged());
        assert!(modified.is_modified());
        assert!(!modified.is_deleted());

        assert!(!ChangeType::Deleted.is_unchanged());
        assert!(!ChangeType::Deleted.is_modified());
        assert!(ChangeType::Deleted.is_deleted());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::cst::parse;
    use proptest::prelude::*;

    fn arb_cst() -> impl Strategy<Value = PlainCst> {
        let leaf = "[a-z]+".prop_map(|s| {
            let (nodes, _) = parse(&s);
            (*nodes.into_iter().next().unwrap()).clone()
        });

        leaf.prop_recursive(3, 10, 3, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 1..5).prop_map(|children| {
                    let input = format!(
                        "({})",
                        children
                            .iter()
                            .map(|c: &PlainCst| c.as_atom().unwrap_or("x").to_string())
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                    let (nodes, _) = parse(&input);
                    (*nodes.into_iter().next().unwrap()).clone()
                }),
            ]
        })
    }

    proptest! {
        #[test]
        fn diff_of_identical_is_unchanged(original in arb_cst()) {
            let diff = compute_diff(vec![original.clone()], vec![original]);
            prop_assert_eq!(diff.len(), 1);
            prop_assert!(diff[0].ann.change.is_unchanged());
        }

        #[test]
        fn diff_preserves_node_count(original in arb_cst()) {
            let diff = compute_diff(vec![original.clone()], vec![original]);
            prop_assert_eq!(diff.len(), 1);
        }
    }
}
