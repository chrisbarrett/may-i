use may_i_core::doc::{Doc, DocF};

use crate::annotation::{Ann, CombineRole, TraceEntry};

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
            TraceEntry::DefaultAsk { reason } => serde_json::json!({
                "type": "default_ask",
                "reason": reason,
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
                tail,
            } => serde_json::json!({
                "type": "parser",
                "command": command,
                "style": style,
                "parameter_tokens": parameter_tokens,
                "tail": tail,
            }),
            TraceEntry::Rule {
                doc,
                line,
                combine_role,
                ..
            } => {
                let mut annotations = Vec::new();
                collect_json_annotations(doc, &mut annotations);
                let role = combine_role.map(|r| match r {
                    CombineRole::ReasonSource => "reason_source",
                    CombineRole::TiedSibling => "tied_sibling",
                });
                serde_json::json!({
                    "type": "rule",
                    "line": line,
                    "structure": doc_to_json(doc),
                    "annotations": annotations,
                    "combine_role": role,
                })
            }
        })
        .collect()
}

fn collect_json_annotations(doc: &Doc<Option<Ann>>, out: &mut Vec<serde_json::Value>) {
    if let Some(Ann::VarRef { name, matched }) = &doc.ann {
        // Collect child annotations into a nested body array.
        let mut body = Vec::new();
        if let DocF::List(children) | DocF::Vector(children) = &doc.node {
            for child in children {
                collect_json_annotations(child, &mut body);
            }
        }
        out.push(serde_json::json!({
            "type": "var_ref",
            "name": name,
            "matched": matched,
            "body": body,
        }));
        return;
    }
    if let Some(ann) = &doc.ann {
        out.push(ann_to_json(ann));
    }
    if let DocF::List(children) | DocF::Vector(children) = &doc.node {
        for child in children {
            collect_json_annotations(child, out);
        }
    }
}

fn ann_to_json(ann: &Ann) -> serde_json::Value {
    match ann {
        Ann::CommandMatch { matched } => serde_json::json!({
            "type": "command_match",
            "matched": matched,
        }),
        Ann::ArgMatch {
            search_tokens,
            arg_set,
            matched,
        } => serde_json::json!({
            "type": "arg_match",
            "search_tokens": search_tokens,
            "arg_set": arg_set,
            "matched": matched,
        }),
        Ann::FactQuery {
            query_source,
            matched,
            observed,
            failure_reason,
        } => serde_json::json!({
            "type": "fact_query",
            "source": query_source,
            "matched": matched,
            "observed": observed,
            "failure_reason": failure_reason,
        }),
        Ann::EffectDecision { decision, reason } => serde_json::json!({
            "type": "effect_decision",
            "decision": decision.to_string(),
            "reason": reason,
        }),
        Ann::BindMatch { key, value } => serde_json::json!({
            "type": "bind_match",
            "key": key,
            "value": value,
        }),
        Ann::RegexMatch {
            pattern,
            actual,
            matched,
        } => serde_json::json!({
            "type": "regex_match",
            "pattern": pattern,
            "actual": actual,
            "matched": matched,
        }),
        Ann::Combinator { result_is_nil } => serde_json::json!({
            "type": "combinator",
            "result_is_nil": result_is_nil,
        }),
        Ann::MayI {
            inner_command,
            decision,
            reason,
        } => serde_json::json!({
            "type": "may_i",
            "inner_command": inner_command,
            "decision": decision.to_string(),
            "reason": reason,
        }),
        Ann::PositionalMatch {
            actual_arg,
            pattern_text,
            matched,
        } => serde_json::json!({
            "type": "positional_match",
            "actual_arg": actual_arg,
            "pattern_text": pattern_text,
            "matched": matched,
        }),
        Ann::RuleMatch { matched, line } => serde_json::json!({
            "type": "rule_match",
            "matched": matched,
            "line": line,
        }),
        Ann::VarRef { name, matched } => serde_json::json!({
            "type": "var_ref",
            "name": name,
            "matched": matched,
        }),
    }
}

fn doc_to_json(doc: &Doc<Option<Ann>>) -> serde_json::Value {
    match &doc.node {
        DocF::Atom(s) => serde_json::json!(s),
        DocF::List(children) => {
            serde_json::json!(children.iter().map(doc_to_json).collect::<Vec<_>>())
        }
        DocF::Vector(children) => serde_json::json!({
            "type": "vector",
            "children": children.iter().map(doc_to_json).collect::<Vec<_>>(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_helpers::*;
    use may_i_core::Decision;

    #[test]
    fn trace_to_json_segment_header() {
        let entries = vec![TraceEntry::SegmentHeader {
            command: "ls".into(),
            decision: may_i_core::Decision::Allow,
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
    fn trace_to_json_rule() {
        let doc = atom_ann("test", Ann::CommandMatch { matched: true });
        let entries = vec![TraceEntry::Rule {
            doc,
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

    #[test]
    fn ann_to_json_command_match() {
        let json = ann_to_json(&Ann::CommandMatch { matched: true });
        assert_eq!(json["type"], "command_match");
        assert_eq!(json["matched"], true);
    }

    #[test]
    fn ann_to_json_arg_match() {
        let json = ann_to_json(&Ann::ArgMatch {
            search_tokens: vec!["t".into()],
            arg_set: vec!["a".into()],
            matched: false,
        });
        assert_eq!(json["type"], "arg_match");
        assert_eq!(json["matched"], false);
        assert_eq!(json["search_tokens"][0], "t");
    }

    #[test]
    fn ann_to_json_fact_query() {
        let json = ann_to_json(&Ann::FactQuery {
            query_source: "src".into(),
            matched: true,
            observed: Some(vec!["val".into()]),
            failure_reason: None,
        });
        assert_eq!(json["type"], "fact_query");
        assert_eq!(json["matched"], true);
        assert_eq!(json["observed"][0], "val");
    }

    #[test]
    fn ann_to_json_effect_decision() {
        let json = ann_to_json(&Ann::EffectDecision {
            decision: Decision::Deny,
            reason: Some("bad".into()),
        });
        assert_eq!(json["type"], "effect_decision");
        assert!(json["decision"].as_str().unwrap().contains("deny"));
        assert_eq!(json["reason"], "bad");
    }

    #[test]
    fn ann_to_json_bind_match() {
        let json = ann_to_json(&Ann::BindMatch {
            key: ":host".into(),
            value: Some("x".into()),
        });
        assert_eq!(json["type"], "bind_match");
        assert_eq!(json["key"], ":host");
    }

    #[test]
    fn ann_to_json_regex_match() {
        let json = ann_to_json(&Ann::RegexMatch {
            pattern: "foo.*".into(),
            actual: "foobar".into(),
            matched: true,
        });
        assert_eq!(json["type"], "regex_match");
        assert_eq!(json["matched"], true);
    }

    #[test]
    fn ann_to_json_combinator() {
        let json = ann_to_json(&Ann::Combinator {
            result_is_nil: true,
        });
        assert_eq!(json["type"], "combinator");
        assert_eq!(json["result_is_nil"], true);
    }

    #[test]
    fn ann_to_json_may_i() {
        let json = ann_to_json(&Ann::MayI {
            inner_command: "rm -rf".into(),
            decision: Decision::Deny,
            reason: Some("nope".into()),
        });
        assert_eq!(json["type"], "may_i");
        assert_eq!(json["inner_command"], "rm -rf");
    }

    #[test]
    fn ann_to_json_rule_match() {
        let json = ann_to_json(&Ann::RuleMatch {
            matched: true,
            line: Some(42),
        });
        assert_eq!(json["type"], "rule_match");
        assert_eq!(json["line"], 42);
    }

    #[test]
    fn ann_to_json_var_ref_matched() {
        let body_ann = Ann::FactQuery {
            query_source: ":agent".into(),
            matched: true,
            observed: Some(vec!["build".into()]),
            failure_reason: None,
        };
        let body_doc = atom_ann("(has [:agent \"build\"])", body_ann);
        let var_doc = list_ann(
            Ann::VarRef {
                name: "build-mode".into(),
                matched: true,
            },
            vec![atom("build-mode"), body_doc],
        );

        let mut annotations = Vec::new();
        collect_json_annotations(&var_doc, &mut annotations);

        // Should have exactly one top-level annotation: the var_ref
        assert_eq!(annotations.len(), 1);
        assert_eq!(annotations[0]["type"], "var_ref");
        assert_eq!(annotations[0]["name"], "build-mode");
        assert_eq!(annotations[0]["matched"], true);
        // Body annotations should be nested inside
        let body = annotations[0]["body"]
            .as_array()
            .expect("body should be array");
        assert_eq!(body.len(), 1);
        assert_eq!(body[0]["type"], "fact_query");
    }

    #[test]
    fn ann_to_json_var_ref_unmatched() {
        let var_doc = list_ann(
            Ann::VarRef {
                name: "build-mode".into(),
                matched: false,
            },
            vec![atom("build-mode"), atom("child")],
        );

        let mut annotations = Vec::new();
        collect_json_annotations(&var_doc, &mut annotations);

        assert_eq!(annotations.len(), 1);
        assert_eq!(annotations[0]["type"], "var_ref");
        assert_eq!(annotations[0]["matched"], false);
        // Body should be present (empty since child has no annotations)
        assert!(annotations[0]["body"].is_array());
    }

    #[test]
    fn doc_to_json_atom() {
        let json = doc_to_json(&atom("hello"));
        assert_eq!(json, "hello");
    }

    #[test]
    fn doc_to_json_list() {
        let doc = list(vec![atom("a"), atom("b")]);
        let json = doc_to_json(&doc);
        assert!(json.is_array());
        assert_eq!(json[0], "a");
        assert_eq!(json[1], "b");
    }

    #[test]
    fn doc_to_json_vector() {
        let doc = vec_doc(vec![atom("x"), atom("y")]);
        let json = doc_to_json(&doc);
        assert_eq!(json["type"], "vector");
        assert_eq!(json["children"][0], "x");
    }

    #[test]
    fn collect_json_annotations_recurses() {
        let inner = atom_ann("cmd", Ann::CommandMatch { matched: true });
        let outer = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(1),
            },
            vec![inner],
        );
        let mut out = Vec::new();
        collect_json_annotations(&outer, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["type"], "rule_match");
        assert_eq!(out[1]["type"], "command_match");
    }

    #[test]
    fn trace_to_json_rule_entry() {
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(5),
            },
            vec![atom_ann("\"git\"", Ann::CommandMatch { matched: true })],
        );
        let entries = vec![TraceEntry::Rule {
            doc,
            line: Some(5),
            pre_migration_doc: None,
            facts: vec![],
            inner_command: None,
            combine_role: None,
        }];
        let json = trace_to_json(&entries);
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["type"], "rule");
        assert_eq!(json[0]["line"], 5);
        assert!(!json[0]["annotations"].as_array().unwrap().is_empty());
    }
}
