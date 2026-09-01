use may_i_core::ContextFacts;
use may_i_engine::check::CheckResult;

use crate::annotation::{CombineRole, TraceEntry};
use crate::cmd_check::TraceExtra;
use crate::output::format_flags_mode;
use crate::trace::TraceNode;
use crate::trace::node::{CaptureSource, Evidence, Role};

pub fn render_check_results_json(
    passed: usize,
    failed: usize,
    results: &[CheckResult<TraceExtra>],
) -> serde_json::Value {
    let json_results: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "command": r.command,
                "expected": r.expected.to_string(),
                "actual": r.actual.to_string(),
                "passed": r.passed,
                "context": context_to_json(&r.context),
                "location": r.extra.location,
                "reason": r.reason,
                "trace": trace_to_json(&r.extra.traces),
            })
        })
        .collect();
    serde_json::json!({
        "passed": passed,
        "failed": failed,
        "results": json_results,
    })
}

fn context_to_json(context: &ContextFacts) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for (key, values) in context.iter() {
        if values.is_empty() {
            obj.insert(key.to_string(), serde_json::Value::Bool(true));
        } else if values.len() == 1 {
            obj.insert(
                key.to_string(),
                serde_json::Value::String(values.iter().next().unwrap().clone()),
            );
        } else {
            let arr: Vec<serde_json::Value> = values
                .iter()
                .map(|v| serde_json::Value::String(v.clone()))
                .collect();
            obj.insert(key.to_string(), serde_json::Value::Array(arr));
        }
    }
    serde_json::Value::Object(obj)
}

pub fn trace_to_json(entries: &[TraceEntry]) -> Vec<serde_json::Value> {
    entries
        .iter()
        .map(|entry| match entry {
            TraceEntry::SegmentHeader { command, decision } => serde_json::json!({
                "type": "segment_header",
                "command": command,
                "decision": decision.to_string(),
            }),
            TraceEntry::EmbeddedCommand { source, decision } => serde_json::json!({
                "type": "embedded_command",
                "source": source,
                "decision": decision.to_string(),
            }),
            TraceEntry::UnresolvedExpansion { words } => serde_json::json!({
                "type": "unresolved_expansion",
                "words": words,
            }),
            TraceEntry::ArityGuess { flag, consumed } => serde_json::json!({
                "type": "arity_guess",
                "flag": flag,
                "consumed": consumed,
            }),
            TraceEntry::EntryEnvContribution { name } => serde_json::json!({
                "type": "entry_env_contribution",
                "name": name,
                "present": true,
            }),
            TraceEntry::DefaultAsk { reason } => serde_json::json!({
                "type": "default_ask",
                "reason": reason,
            }),
            TraceEntry::LocalFunctionCall { name } => serde_json::json!({
                "type": "local_function_call",
                "name": name,
            }),
            TraceEntry::ParseDiagnostics { diagnostics } => serde_json::json!({
                "type": "parse_diagnostics",
                "diagnostics": diagnostics.iter().map(|d| serde_json::json!({
                    "span": { "start": d.span.start, "end": d.span.end },
                    "kind": d.kind,
                    "severity": d.severity,
                    "message": d.message(),
                })).collect::<Vec<_>>(),
            }),
            TraceEntry::Parser {
                command,
                style,
                parameter_tokens,
                flags,
                rest_binding,
            } => serde_json::json!({
                "type": "parser",
                "command": command,
                "style": style,
                "parameter_tokens": parameter_tokens,
                "flags": format_flags_mode(flags),
                "rest_binding": rest_binding,
            }),
            TraceEntry::Rule {
                node,
                line,
                combine_role,
                ..
            } => {
                let mut annotations = Vec::new();
                collect_node_annotations(node, &mut annotations);
                let role = combine_role.map(|r| match r {
                    CombineRole::ReasonSource => "reason_source",
                    CombineRole::TiedSibling => "tied_sibling",
                });
                serde_json::json!({
                    "type": "rule",
                    "line": line,
                    "structure": node_to_json(node),
                    "annotations": annotations,
                    "combine_role": role,
                })
            }
        })
        .collect()
}

fn collect_node_annotations(node: &TraceNode, out: &mut Vec<serde_json::Value>) {
    if node.dimmed() {
        return;
    }
    if let Role::VarRef { name } = node.role() {
        let matched = matches!(node.evidence(), Some(Evidence::Match { matched: true }));
        let mut body = Vec::new();
        for child in node.children() {
            collect_node_annotations(child, &mut body);
        }
        out.push(serde_json::json!({
            "type": "var_ref",
            "name": name,
            "matched": matched,
            "body": body,
        }));
        return;
    }
    if let Some(json) = node_annotation_to_json(node) {
        out.push(json);
    }
    for child in node.children() {
        collect_node_annotations(child, out);
    }
}

fn capture_source_str(source: CaptureSource) -> &'static str {
    match source {
        CaptureSource::Tail => "tail",
        CaptureSource::Parameter => "parameter",
    }
}

fn node_annotation_to_json(node: &TraceNode) -> Option<serde_json::Value> {
    let evidence = node.evidence()?;
    Some(match (node.role(), evidence) {
        (Role::Command, Evidence::Match { matched }) => serde_json::json!({
            "type": "command_match",
            "matched": matched,
        }),
        (
            Role::ArgMatch,
            Evidence::SetMembership {
                token,
                observed,
                matched,
            },
        ) => {
            let mut obj = serde_json::json!({
                "type": "arg_match",
                "matched": matched,
                "evidence": {
                    "kind": "set_membership",
                    "token": token,
                    "observed": observed,
                },
            });
            if token.is_empty() {
                obj["evidence"]["token"] = serde_json::Value::Null;
            }
            obj
        }
        (Role::ArgMatch, Evidence::CapturedValue { source, value }) => serde_json::json!({
            "type": "arg_match",
            "matched": true,
            "evidence": {
                "kind": "captured_value",
                "source": capture_source_str(*source),
                "value": value,
            },
            "captured_value": value,
        }),
        (Role::ArgMatch, Evidence::Match { matched }) => serde_json::json!({
            "type": "arg_match",
            "matched": matched,
        }),
        (
            Role::FactQuery,
            Evidence::FactValues {
                expected,
                observed,
                matched,
                ..
            },
        ) => serde_json::json!({
            "type": "fact_query",
            "source": expected,
            "matched": matched,
            "observed": observed,
        }),
        (Role::FactQuery, Evidence::FactAbsent) => serde_json::json!({
            "type": "fact_query",
            "matched": false,
            "failure_reason": "absent",
        }),
        (Role::FactQuery, Evidence::Match { matched }) => serde_json::json!({
            "type": "fact_query",
            "matched": matched,
        }),
        (Role::EffectDecision, Evidence::Decision { decision, reason }) => serde_json::json!({
            "type": "effect_decision",
            "decision": decision.to_string(),
            "reason": reason,
        }),
        (Role::BindMatch { key }, Evidence::Bind { value }) => serde_json::json!({
            "type": "bind_match",
            "key": key,
            "value": value,
        }),
        (
            Role::RegexMatch,
            Evidence::Regex {
                pattern,
                actual,
                matched,
            },
        ) => serde_json::json!({
            "type": "regex_match",
            "pattern": pattern,
            "actual": actual,
            "matched": matched,
        }),
        (Role::Combinator, Evidence::Match { matched }) => serde_json::json!({
            "type": "combinator",
            "result_is_nil": !matched,
        }),
        (
            Role::PositionalMatch,
            Evidence::Positional {
                actual,
                pattern_text,
                matched,
            },
        ) => serde_json::json!({
            "type": "positional_match",
            "actual_arg": actual,
            "pattern_text": pattern_text,
            "matched": matched,
        }),
        (Role::Rule { line }, Evidence::Match { matched }) => serde_json::json!({
            "type": "rule_match",
            "matched": matched,
            "line": line,
        }),
        _ => return None,
    })
}

fn node_to_json(node: &TraceNode) -> serde_json::Value {
    if let Some(s) = node.label() {
        return serde_json::json!(s);
    }
    let children: Vec<serde_json::Value> = node.children().iter().map(node_to_json).collect();
    serde_json::json!(children)
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::Decision;

    #[test]
    fn render_check_results_json_emits_envelope_with_per_result_fields() {
        let result = CheckResult {
            command: "git push".into(),
            expected: Decision::Allow,
            actual: Decision::Deny,
            passed: false,
            context: ContextFacts::default(),
            reason: Some("blocked by rule".into()),
            extra: TraceExtra {
                location: Some("/tmp/cfg.lisp:3:4".into()),
                traces: vec![TraceEntry::DefaultAsk {
                    reason: "no match".into(),
                }],
            },
        };
        let json = render_check_results_json(2, 1, std::slice::from_ref(&result));

        assert_eq!(json["passed"], 2);
        assert_eq!(json["failed"], 1);
        let results = json["results"].as_array().expect("results array");
        assert_eq!(results.len(), 1);
        let r0 = &results[0];
        assert_eq!(r0["command"], "git push");
        assert!(r0["expected"].as_str().unwrap().contains("allow"));
        assert!(r0["actual"].as_str().unwrap().contains("deny"));
        assert_eq!(r0["passed"], false);
        assert_eq!(r0["reason"], "blocked by rule");
        assert_eq!(r0["location"], "/tmp/cfg.lisp:3:4");
        assert_eq!(r0["trace"][0]["type"], "default_ask");
    }

    #[test]
    fn trace_to_json_segment_header() {
        let entries = vec![TraceEntry::SegmentHeader {
            command: "ls".into(),
            decision: Decision::Allow,
        }];
        let json = trace_to_json(&entries);
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["type"], "segment_header");
        assert_eq!(json[0]["command"], "ls");
    }

    #[test]
    fn trace_to_json_default_ask() {
        let entries = vec![TraceEntry::DefaultAsk {
            reason: "no rules".into(),
        }];
        let json = trace_to_json(&entries);
        assert_eq!(json[0]["type"], "default_ask");
    }

    #[test]
    fn trace_to_json_local_function_call() {
        let entries = vec![TraceEntry::LocalFunctionCall {
            name: "materialise".into(),
        }];
        let json = trace_to_json(&entries);
        assert_eq!(json[0]["type"], "local_function_call");
        assert_eq!(json[0]["name"], "materialise");
    }

    #[test]
    fn trace_to_json_rule_basic() {
        let node = TraceNode::rule(vec![TraceNode::plain_atom("rule")], Some(1), true);
        let entries = vec![TraceEntry::Rule {
            node,
            line: Some(1),
            pre_migration_doc: None,
            facts: vec![],
            inner_command: None,
            combine_role: None,
        }];
        let json = trace_to_json(&entries);
        assert_eq!(json[0]["type"], "rule");
        assert_eq!(json[0]["line"], 1);
    }
}
