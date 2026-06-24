// `AuditTap` — the data an evaluation hands back to the pipeline so it can
// build and emit an audit record at its terminal point. The closure (which
// owns the fold and the context) fills the tap; the pipeline owns the
// effective `AuditConfig`, the threshold gate, and the file write.

use may_i_core::Decision;
use may_i_engine::EvalResult;
use may_i_shell_parser::Severity;

use super::AuditSource;

/// Everything the pipeline needs from a completed (or trust-blocked)
/// evaluation to build one audit record.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditTap {
    pub decision: Decision,
    /// Operator-authored (or already-escaped `EvalResult`) reason text. When
    /// sourced from an evaluation it arrives via the escaped `DisplaySafe` and is
    /// stringified here; it is never raw, attacker-derived input on its own.
    pub reason: Option<String>,
    pub source: AuditSource,
    pub parse_ok: bool,
    pub diagnostic: Option<String>,
    pub rules: Vec<String>,
    pub cwd: Option<String>,
}

impl AuditTap {
    /// Build a tap for a normally-evaluated command. The source is
    /// `parse-floor` when the command carried an error-severity parse
    /// diagnostic (its decision floored to `ask`), otherwise `rule`.
    pub fn from_eval(
        result: &EvalResult,
        command: &str,
        rules: Vec<String>,
        cwd: Option<String>,
    ) -> Self {
        let error = result
            .parse_diagnostics
            .iter()
            .find(|d| d.severity == Severity::Error);
        let (source, parse_ok, diagnostic) = match error {
            Some(d) => (
                AuditSource::ParseFloor,
                false,
                Some(d.format_with_source(command)),
            ),
            None => (AuditSource::Rule, true, None),
        };
        Self {
            decision: result.decision,
            reason: result.reason.as_deref().map(String::from),
            source,
            parse_ok,
            diagnostic,
            rules,
            cwd,
        }
    }

    /// Build a tap for a Trust-gate short-circuit. The command never reached
    /// the evaluator, so parse status is reported clean and no rules decided.
    pub fn trust_block(decision: Decision, reason: String) -> Self {
        Self {
            decision,
            reason: Some(reason),
            source: AuditSource::TrustBlock,
            parse_ok: true,
            diagnostic: None,
            rules: Vec::new(),
            cwd: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_engine::DisplaySafe;

    #[test]
    fn clean_eval_is_rule_sourced() {
        let result = EvalResult::new(Decision::Deny, Some(DisplaySafe::new("danger")));
        let tap = AuditTap::from_eval(&result, "rm -rf /", vec!["h1".into()], None);
        assert_eq!(tap.source, AuditSource::Rule);
        assert!(tap.parse_ok);
        assert!(tap.diagnostic.is_none());
        assert_eq!(tap.rules, vec!["h1".to_string()]);
        assert_eq!(tap.decision, Decision::Deny);
    }

    #[test]
    fn parse_error_floors_to_parse_floor() {
        use may_i_shell_parser::{ParseDiagnostic, ParseDiagnosticKind, Span};
        let mut result = EvalResult::new(Decision::Ask, Some(DisplaySafe::new("floored")));
        result.parse_diagnostics.push(ParseDiagnostic {
            span: Span { start: 0, end: 1 },
            kind: ParseDiagnosticKind::UnterminatedDoubleQuote,
            severity: Severity::Error,
        });
        let tap = AuditTap::from_eval(&result, r#"echo ""#, vec![], None);
        assert_eq!(tap.source, AuditSource::ParseFloor);
        assert!(!tap.parse_ok);
        assert!(tap.diagnostic.is_some());
    }

    #[test]
    fn trust_block_tap_shape() {
        let tap = AuditTap::trust_block(Decision::Deny, "awaiting approval".into());
        assert_eq!(tap.source, AuditSource::TrustBlock);
        assert!(tap.parse_ok);
        assert!(tap.rules.is_empty());
    }
}
