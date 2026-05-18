// Intent: serialise a TrustBlock in the response shape dictated by the
// invocation mode. Sole call site for trust-block byte production —
// `cmd_eval`, `cmd_check`, and `cmd_claude_code_hook` MUST NOT hand-roll
// these payloads. Reachable only through `CommandPipeline::run`.

use std::io::Write;

use crate::pipeline::InvocationMode;
use crate::trust::TrustBlock;

use super::Terminal;

/// Emit `block` in the response shape for `mode`. `stdout` and `stderr`
/// are the pipeline's writers; `terminal` is held for symmetry with other
/// renderers (no current variant uses it, but keeping it on the signature
/// lets future text-mode shaping land without a churning surface change).
pub fn render_trust_block(
    stdout: &mut impl Write,
    _stderr: &mut impl Write,
    _terminal: &Terminal,
    block: &TrustBlock,
    mode: InvocationMode,
) {
    match mode {
        InvocationMode::Eval => {
            // Pre-refactor `cmd_eval` text mode emits nothing on a trust
            // block beyond what the prelude already showed; only JSON mode
            // serialises the payload. We carry that shape forward.
            //
            // The JSON branch always writes; the text branch is silent.
            // `pipeline::run` calls this regardless of `json`, so we
            // re-derive the JSON-vs-text choice from the block's call
            // site here: the only `InvocationMode::Eval` trust block
            // currently emitted runs through the JSON path (the gate
            // returns `None` in `TrustMode::Text`).
            let body = serde_json::json!({
                "decision": block.decision.to_string(),
                "reason": block.reason,
                "files": block.files,
            });
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string(&body).expect("response serialization is infallible")
            );
        }
        InvocationMode::Check => {
            // `cmd_check` does not consult the gate via `run`; reaching
            // this arm would indicate a pipeline-flow bug. Emit nothing
            // rather than panic so production users never see a stack
            // trace from a corner case.
        }
        InvocationMode::Hook => {
            let body = serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": block.decision.to_string(),
                    "permissionDecisionReason": block.reason,
                }
            });
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string(&body).expect("response serialization is infallible")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::Decision;

    fn block() -> TrustBlock {
        TrustBlock {
            decision: Decision::Ask,
            reason: "Untrusted rules for echo. Run: may-i trust".into(),
            files: vec!["/tmp/rules.lisp".into()],
        }
    }

    #[test]
    fn eval_mode_emits_decision_reason_files() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let term = Terminal::detect();
        render_trust_block(&mut out, &mut err, &term, &block(), InvocationMode::Eval);
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("parse json");
        assert_eq!(v["decision"], "ask");
        assert!(v["reason"].as_str().unwrap().contains("Untrusted"));
        assert_eq!(v["files"][0], "/tmp/rules.lisp");
        assert!(err.is_empty());
    }

    #[test]
    fn hook_mode_wraps_in_envelope() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let term = Terminal::detect();
        render_trust_block(&mut out, &mut err, &term, &block(), InvocationMode::Hook);
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("parse json");
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
        assert!(
            v["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("Untrusted")
        );
        assert!(err.is_empty());
    }

    #[test]
    fn check_mode_emits_nothing() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let term = Terminal::detect();
        render_trust_block(&mut out, &mut err, &term, &block(), InvocationMode::Check);
        assert!(out.is_empty());
        assert!(err.is_empty());
    }
}
