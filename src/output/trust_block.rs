// Intent: serialise a TrustBlock in the response shape dictated by the
// caller's `run_*` method. Two helpers (Eval, Hook) replace the legacy
// mode-switching `render_trust_block`. `cmd_*` modules MUST NOT hand-roll
// these payloads; the helpers are reachable only through the pipeline's
// `run_eval` and `run_hook` entry points.

use std::io::Write;

use crate::trust::TrustBlock;

use super::Terminal;

/// Emit `block` in the `eval` response shape. The text branch is silent
/// (only the prelude renders to stderr); the JSON branch writes the
/// `{decision, reason, files}` envelope to stdout.
pub fn render_eval_trust_block(
    stdout: &mut impl Write,
    _stderr: &mut impl Write,
    _terminal: &Terminal,
    block: &TrustBlock,
    json: bool,
) {
    if !json {
        // Text-mode `eval` shows nothing past the prelude on a trust block
        // (the gate returns `None` in `TrustMode::Text`, so this branch is
        // only reachable from a future caller). Preserve current bytes.
        return;
    }
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

/// Emit `block` in the Claude Code hook response shape (always JSON,
/// wrapped in `hookSpecificOutput`).
pub fn render_hook_trust_block(stdout: &mut impl Write, block: &TrustBlock) {
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
    fn eval_json_emits_decision_reason_files() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let term = Terminal::detect();
        render_eval_trust_block(&mut out, &mut err, &term, &block(), true);
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("parse json");
        assert_eq!(v["decision"], "ask");
        assert!(v["reason"].as_str().unwrap().contains("Untrusted"));
        assert_eq!(v["files"][0], "/tmp/rules.lisp");
        assert!(err.is_empty());
    }

    #[test]
    fn eval_text_emits_nothing() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let term = Terminal::detect();
        render_eval_trust_block(&mut out, &mut err, &term, &block(), false);
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    #[test]
    fn hook_wraps_in_envelope() {
        let mut out = Vec::new();
        render_hook_trust_block(&mut out, &block());
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
    }
}
