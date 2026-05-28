// Intent: body-typed renderers driven by the pipeline's `run_*` entry
// points. One renderer per body type; each branches on `json` internally
// so handler closures never touch `pipeline.json()`. No mode-dispatch
// indirection remains.

use std::io::Write;
use std::path::Path;

use may_i_engine::EvalResult;

use may_i_core::Decision;

use crate::output::{
    CheckOutput, CheckResultView, EvalOutput, Terminal, render_check_results_json, trace_to_json,
};
use crate::pipeline::{CheckOutcomeBody, EvalOutcomeBody, HarnessProfile};

/// Eval body → text or JSON. Sole caller: `CommandPipeline::run_eval`.
pub fn render_eval(
    stdout: &mut impl Write,
    terminal: &Terminal,
    json: bool,
    body: &EvalOutcomeBody,
) {
    if json {
        render_eval_json(stdout, body);
    } else {
        render_eval_text(stdout, terminal, body);
    }
}

/// Check body → text or JSON. Sole caller: `CommandPipeline::run_check`.
pub fn render_check(
    stdout: &mut impl Write,
    terminal: &Terminal,
    json: bool,
    body: &CheckOutcomeBody,
) {
    if json {
        render_check_json(stdout, body);
    } else {
        render_check_text(stdout, terminal, body);
    }
}

/// Hook response → JSON envelope. Sole caller:
/// `CommandPipeline::run_hook`. Hook mode is JSON-only by design.
///
/// Codex rejects `permissionDecision: "ask"` as an unsupported value, so
/// under the Codex profile an `ask` decision is emitted without the
/// `permissionDecision`/`permissionDecisionReason` keys and the reason
/// (if any) is surfaced as `additionalContext` instead. `allow` and
/// `deny` keep the Claude Code envelope under both profiles.
pub fn render_hook(stdout: &mut impl Write, profile: HarnessProfile, result: &EvalResult) {
    let body = match (profile, result.decision) {
        (HarnessProfile::Codex, Decision::Ask) => codex_ask_envelope(result.reason.as_deref()),
        _ => standard_envelope(result.decision.to_string(), result.reason.as_deref()),
    };
    let _ = writeln!(
        stdout,
        "{}",
        serde_json::to_string(&body).expect("response serialization is infallible")
    );
}

pub(super) fn standard_envelope(decision: String, reason: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason.unwrap_or_default(),
        }
    })
}

pub(super) fn codex_ask_envelope(reason: Option<&str>) -> serde_json::Value {
    let mut hook = serde_json::Map::new();
    hook.insert("hookEventName".into(), serde_json::json!("PreToolUse"));
    if let Some(reason) = reason.filter(|r| !r.is_empty()) {
        hook.insert("additionalContext".into(), serde_json::json!(reason));
    }
    serde_json::json!({ "hookSpecificOutput": hook })
}

fn render_eval_text(stdout: &mut impl Write, terminal: &Terminal, body: &EvalOutcomeBody) {
    let config_path = Path::new(&body.display_path);
    let builder = EvalOutput {
        config_path,
        trace_entries: &body.traces,
        command: &body.command,
        colored_command: &body.colored,
        eval_result: &body.result,
    };
    builder.render(stdout, terminal);
}

fn render_eval_json(stdout: &mut impl Write, body: &EvalOutcomeBody) {
    let mut json = serde_json::json!({
        "decision": body.result.decision.to_string(),
        "reason": body.result.reason.clone().unwrap_or_default(),
        "trace": trace_to_json(&body.traces),
    });
    if !body.result.parse_diagnostics.is_empty() {
        json["parse_diagnostics"] = serde_json::json!(
            body.result
                .parse_diagnostics
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "span": { "start": d.span.start, "end": d.span.end },
                        "kind": d.kind,
                        "severity": d.severity,
                        "message": d.message(),
                    })
                })
                .collect::<Vec<_>>()
        );
    }
    let _ = writeln!(
        stdout,
        "{}",
        serde_json::to_string(&json).expect("response serialization is infallible")
    );
}

fn render_check_text(stdout: &mut impl Write, terminal: &Terminal, body: &CheckOutcomeBody) {
    let config_path = Path::new(&body.display_path);
    let views: Vec<CheckResultView<'_>> = body
        .results
        .iter()
        .map(|r| CheckResultView {
            command: &r.command,
            expected: r.expected,
            actual: r.actual,
            passed: r.passed,
            context: &r.context,
            location: r.extra.location.as_deref(),
            reason: r.reason.as_deref(),
            traces: &r.extra.traces,
        })
        .collect();
    let builder = CheckOutput {
        config_path,
        results: &views,
        verbose: body.verbose,
    };
    builder.render(stdout, terminal);
}

fn render_check_json(stdout: &mut impl Write, body: &CheckOutcomeBody) {
    let json = render_check_results_json(body.passed, body.failed, &body.results);
    let _ = writeln!(
        stdout,
        "{}",
        serde_json::to_string(&json).expect("response serialization is infallible")
    );
}

#[cfg(test)]
mod tests {
    use may_i_core::{ContextFacts, Decision};
    use may_i_engine::EvalResult;
    use may_i_engine::check::CheckResult;

    use super::*;
    use crate::cmd_check::TraceExtra;
    use crate::output::strip_ansi;

    fn term() -> Terminal {
        Terminal::detect()
    }

    fn eval_body() -> EvalOutcomeBody {
        EvalOutcomeBody {
            command: "echo hi".into(),
            colored: "echo hi".into(),
            result: EvalResult::new(Decision::Allow, Some("safe".into())),
            traces: vec![],
            display_path: "/tmp/cfg.lisp".into(),
        }
    }

    fn check_body() -> CheckOutcomeBody {
        CheckOutcomeBody {
            results: vec![CheckResult {
                command: "echo hi".into(),
                expected: Decision::Allow,
                actual: Decision::Allow,
                passed: true,
                context: ContextFacts::default(),
                reason: None,
                extra: TraceExtra {
                    location: None,
                    traces: vec![],
                },
            }],
            verbose: false,
            passed: 1,
            failed: 0,
            display_path: "/tmp/cfg.lisp".into(),
        }
    }

    #[test]
    fn eval_text_writes_result_block() {
        let mut out = Vec::new();
        render_eval(&mut out, &term(), false, &eval_body());
        let s = strip_ansi(&String::from_utf8(out).unwrap());
        assert!(s.contains("Result"));
        assert!(s.contains("echo hi"));
    }

    #[test]
    fn eval_json_writes_decision_reason_trace() {
        let mut out = Vec::new();
        render_eval(&mut out, &term(), true, &eval_body());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("parse");
        assert_eq!(v["decision"], "allow");
        assert_eq!(v["reason"], "safe");
        assert!(v["trace"].is_array());
    }

    #[test]
    fn check_text_writes_summary() {
        let mut out = Vec::new();
        render_check(&mut out, &term(), false, &check_body());
        let s = strip_ansi(&String::from_utf8(out).unwrap());
        assert!(s.contains("Summary"));
    }

    #[test]
    fn check_json_writes_envelope() {
        let mut out = Vec::new();
        render_check(&mut out, &term(), true, &check_body());
        let v: serde_json::Value = serde_json::from_slice(&out).expect("parse");
        assert_eq!(v["passed"], 1);
        assert_eq!(v["failed"], 0);
        assert!(v["results"].is_array());
    }

    fn render(
        profile: HarnessProfile,
        decision: Decision,
        reason: Option<&str>,
    ) -> serde_json::Value {
        let result = EvalResult::new(decision, reason.map(str::to_string));
        let mut out = Vec::new();
        render_hook(&mut out, profile, &result);
        serde_json::from_slice(&out).expect("parse")
    }

    #[test]
    fn claude_code_allow_emits_standard_envelope() {
        let v = render(HarnessProfile::ClaudeCode, Decision::Allow, Some("ok"));
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(v["hookSpecificOutput"]["permissionDecisionReason"], "ok");
    }

    #[test]
    fn claude_code_ask_keeps_permission_decision() {
        let v = render(HarnessProfile::ClaudeCode, Decision::Ask, Some("review"));
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecisionReason"],
            "review"
        );
        assert!(v["hookSpecificOutput"].get("additionalContext").is_none());
    }

    #[test]
    fn claude_code_deny_emits_standard_envelope() {
        let v = render(HarnessProfile::ClaudeCode, Decision::Deny, Some("bad"));
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(v["hookSpecificOutput"]["permissionDecisionReason"], "bad");
    }

    #[test]
    fn codex_allow_matches_claude_code_envelope() {
        let cc = render(HarnessProfile::ClaudeCode, Decision::Allow, Some("ok"));
        let cx = render(HarnessProfile::Codex, Decision::Allow, Some("ok"));
        assert_eq!(cc, cx);
    }

    #[test]
    fn codex_deny_matches_claude_code_envelope() {
        let cc = render(HarnessProfile::ClaudeCode, Decision::Deny, Some("bad"));
        let cx = render(HarnessProfile::Codex, Decision::Deny, Some("bad"));
        assert_eq!(cc, cx);
    }

    #[test]
    fn codex_ask_with_reason_surfaces_additional_context() {
        let v = render(HarnessProfile::Codex, Decision::Ask, Some("needs review"));
        let hook = &v["hookSpecificOutput"];
        assert_eq!(hook["hookEventName"], "PreToolUse");
        assert_eq!(hook["additionalContext"], "needs review");
        assert!(hook.get("permissionDecision").is_none());
        assert!(hook.get("permissionDecisionReason").is_none());
    }

    #[test]
    fn codex_ask_without_reason_omits_additional_context() {
        let v = render(HarnessProfile::Codex, Decision::Ask, None);
        let hook = &v["hookSpecificOutput"];
        assert_eq!(hook["hookEventName"], "PreToolUse");
        assert!(hook.get("additionalContext").is_none());
        assert!(hook.get("permissionDecision").is_none());
        assert!(hook.get("permissionDecisionReason").is_none());
    }

    #[test]
    fn codex_ask_with_empty_reason_omits_additional_context() {
        let v = render(HarnessProfile::Codex, Decision::Ask, Some(""));
        let hook = &v["hookSpecificOutput"];
        assert!(hook.get("additionalContext").is_none());
    }
}
