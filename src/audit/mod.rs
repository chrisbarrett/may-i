// Audit log: the record schema, threshold gate, settings resolution, and the
// best-effort append-only writer.
//
// An `AuditRecord` is a wire type — its JSON shape is the contract, so it has
// public fields and is serialised verbatim. One record is emitted per recorded
// evaluation, as a single line of JSON.

mod record;
mod resolve;
mod tap;
mod writer;

pub use record::{AuditMode, AuditRecord, AuditSource, timestamp_now};
pub use resolve::{AuditOverrides, resolve_audit_config};
pub use tap::AuditTap;
pub use writer::{append_best_effort, default_audit_path};

use may_i_core::ast::AuditThreshold;

/// Whether an outcome is recorded: the decision meets the threshold, OR the
/// command failed to parse (always recorded at any non-`off` threshold).
pub fn should_record(
    threshold: AuditThreshold,
    decision: may_i_core::Decision,
    parse_ok: bool,
) -> bool {
    if threshold.is_off() {
        return false;
    }
    threshold.records(decision) || !parse_ok
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use may_i_core::Decision;

    #[test]
    fn off_records_nothing_even_on_parse_failure() {
        assert!(!should_record(AuditThreshold::Off, Decision::Deny, false));
    }

    #[test]
    fn parse_failure_always_recorded_at_non_off() {
        // ask floors below deny, but a parse failure is still recorded.
        assert!(should_record(AuditThreshold::Deny, Decision::Ask, false));
    }

    #[test]
    fn deny_threshold_omits_clean_ask_and_allow() {
        assert!(should_record(AuditThreshold::Deny, Decision::Deny, true));
        assert!(!should_record(AuditThreshold::Deny, Decision::Ask, true));
        assert!(!should_record(AuditThreshold::Deny, Decision::Allow, true));
    }

    #[test]
    fn all_records_every_clean_decision() {
        assert!(should_record(AuditThreshold::All, Decision::Allow, true));
        assert!(should_record(AuditThreshold::All, Decision::Ask, true));
        assert!(should_record(AuditThreshold::All, Decision::Deny, true));
    }

    use proptest::prelude::*;

    fn any_threshold() -> impl Strategy<Value = AuditThreshold> {
        prop_oneof![
            Just(AuditThreshold::Off),
            Just(AuditThreshold::Deny),
            Just(AuditThreshold::Ask),
            Just(AuditThreshold::All),
        ]
    }

    fn any_decision() -> impl Strategy<Value = Decision> {
        prop_oneof![
            Just(Decision::Allow),
            Just(Decision::Ask),
            Just(Decision::Deny),
        ]
    }

    proptest! {
        /// For every (threshold, decision, parse_ok), a record is written iff
        /// auditing is on AND (the decision meets the threshold OR the command
        /// failed to parse). The expected value is spelled out independently of
        /// the implementation so a bug in `records()` is caught.
        #[test]
        fn record_iff_meets_threshold_or_parse_failed(
            threshold in any_threshold(),
            decision in any_decision(),
            parse_ok in any::<bool>(),
        ) {
            let parse_failed = !parse_ok;
            let meets = match threshold {
                AuditThreshold::Off => false,
                AuditThreshold::Deny => decision == Decision::Deny,
                AuditThreshold::Ask => matches!(decision, Decision::Ask | Decision::Deny),
                AuditThreshold::All => true,
            };
            let expected = !matches!(threshold, AuditThreshold::Off) && (meets || parse_failed);
            prop_assert_eq!(should_record(threshold, decision, parse_ok), expected);
        }
    }
}
