// Evaluation-semantics integration tests: decision evaluation, binding
// recursion, carrier hardening, flag and boundary handling, and the
// segment-decision fixtures.

#[path = "../common/mod.rs"]
mod common;

mod binding_recursion;
mod carrier_hardening;
mod display_safe_boundary;
mod double_dash_boundary;
mod flag_and_parameter;
mod quantifier_sequence_groups;
mod segment_decisions_fixtures;
mod unified_eval_integration;
mod wrapper_tail_scoping;
