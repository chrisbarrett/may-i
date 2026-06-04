//! Elm-style rendering of shape mismatches (design D6), built on miette.
//!
//! The engine's [`ShapeMismatch`] carries the raw facts (operator, found
//! shape, both spans). This module turns them into user-facing
//! diagnostics: a plain-English header, both source excerpts with
//! carets, a "but `#name` is …, declared here" framing, and a hint when
//! a single-step rewrite is identifiable.
//!
//! The user-facing vocabulary discipline (D5) lives here: the words
//! "shape" and "type" and the internal shape names never appear in
//! rendered text — only the phrases from [`Shape::user_phrase`].

use may_i_engine::shape::{DeclKind, Shape};
use may_i_engine::shape_check::{Operator, ShapeMismatch};
use miette::{NamedSource, SourceSpan};

/// One rendered shape mismatch: header + two labelled excerpts + hint.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("{header}")]
struct ShapeDiagnostic {
    header: String,
    #[source_code]
    src: NamedSource<String>,
    #[label("{use_label}")]
    use_span: SourceSpan,
    use_label: String,
    #[label("{decl_label}")]
    decl_span: Option<SourceSpan>,
    decl_label: String,
    #[help]
    help: Option<String>,
}

/// Aggregate report: every mismatch in the config, rendered in source
/// order (no deduplication — the `binding-shapes` spec requires all).
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("found {} value-usage problem(s) in the configuration", .problems.len())]
struct ShapeReport {
    #[related]
    problems: Vec<ShapeDiagnostic>,
}

/// The phrase describing what an operator expects, in user vocabulary.
fn operator_expectation(op: Operator) -> &'static str {
    match op {
        Operator::Authorise => "a command line",
        Operator::Matches => "a single value or a command line",
        Operator::Every | Operator::Some => "a list of values",
    }
}

/// The header line, naming the operator and what it needs.
fn header_for(op: Operator) -> String {
    format!("`{}` needs {}", op.verb(), operator_expectation(op))
}

/// The label sitting under the rule-body `#var` reference.
fn use_label_for(op: Operator) -> String {
    match op {
        Operator::Authorise => "this runs a command line".to_string(),
        Operator::Matches => "this matches a single value".to_string(),
        Operator::Every => "this looks at every value in a list".to_string(),
        Operator::Some => "this looks for a value in a list".to_string(),
    }
}

/// The "But `#name` is …" label sitting under the parser declaration.
fn decl_label_for(m: &ShapeMismatch) -> String {
    format!(
        "but `#{}` is {}, declared here",
        m.binding.as_str(),
        m.found.user_phrase()
    )
}

/// Per-mismatch hint, keyed by `(operator, found shape, declaration
/// kind)` (decision D2). Dispatching on the declaration kind keeps every
/// proposed rewrite applicable to how the binding was actually declared:
/// a `Positional`/`Rest` binding never sees a `(parameter NAME …)`
/// suggestion. Returns `None` when no single-step remedy is identifiable.
fn hint_for(m: &ShapeMismatch) -> Option<String> {
    let bind = m.binding.as_str();
    match (m.operator, m.found, &m.decl_kind) {
        // `every?`/`some?` over a single value, declared by a parameter →
        // collect occurrences into a list.
        (Operator::Every | Operator::Some, Shape::Token, DeclKind::Parameter { name }) => {
            Some(format!(
                "To match every occurrence, collect them into a list: \
                 declare the parser as (parameter \"{name}\" (set #{bind}))."
            ))
        }
        // `every?`/`some?` over a single value, declared by a positional →
        // widen the quantifier (the binding has no parameter to redeclare).
        (Operator::Every | Operator::Some, Shape::Token, DeclKind::Positional) => Some(format!(
            "To match every positional, widen the quantifier: \
             (positional #{bind} +) for one-or-more or \
             (positional #{bind} *) for zero-or-more."
        )),
        // `every?`/`some?` over a count → a count is not a list.
        (Operator::Every | Operator::Some, Shape::Count, DeclKind::Flag { name }) => Some(format!(
            "The -{name} count is not a list. {}",
            count_presence_fallback(bind)
        )),
        // `every?`/`some?` over a command line carried by a parameter →
        // declare it a list if the parameter repeats.
        (Operator::Every | Operator::Some, Shape::Command, DeclKind::Parameter { name }) => {
            Some(format!(
                "This carries a command line, not a list. If -{name} repeats, \
                 declare it (parameter \"{name}\" (set #{bind}))."
            ))
        }
        // `every?`/`some?` over a command line captured by `(rest …)` →
        // rest captures the whole tail; recurse with `authorise`.
        (Operator::Every | Operator::Some, Shape::Command, DeclKind::Rest) => Some(format!(
            "(rest #{bind}) captures the whole command tail, not a list. \
             To check that command, recurse with (authorise #{bind})."
        )),
        // `authorise` over a list, declared by a parameter → iterate, or
        // mark the parameter as carrying a single command line.
        (Operator::Authorise, Shape::CollectionToken, DeclKind::Parameter { name }) => {
            Some(format!(
                "Did you mean to inspect each value? Try (some? #{bind} PRED) or \
                 (every? #{bind} PRED). Or, if -{name} carries a single command line, \
                 declare it (parameter \"{name}\" (command #{bind}))."
            ))
        }
        // `authorise` over a list, declared by a positional → iteration
        // only; positionals have no parameter name and no `(command …)`.
        (Operator::Authorise, Shape::CollectionToken, DeclKind::Positional) => Some(format!(
            "Did you mean to inspect each value? Try (some? #{bind} PRED) or \
             (every? #{bind} PRED)."
        )),
        // `matches?` over a count → counts aren't patterns.
        (Operator::Matches, Shape::Count, DeclKind::Flag { name }) => Some(format!(
            "The -{name} count compares to numbers, not patterns. {}",
            count_presence_fallback(bind)
        )),
        // `authorise` over a count → counts aren't command lines.
        (Operator::Authorise, Shape::Count, DeclKind::Flag { name }) => Some(format!(
            "A count is not a command line — review the (flag \"{name}\" (count #{bind})) \
             declaration."
        )),
        _ => None,
    }
}

/// Shared trailing guidance for count mismatches: counts have no list or
/// pattern form yet, so every count hint falls back to a presence check.
fn count_presence_fallback(bind: &str) -> String {
    format!("Check presence with (bound? #{bind}) until count comparisons are available.")
}

fn to_source_span(span: may_i_core::Span) -> SourceSpan {
    SourceSpan::from((span.start, span.end.saturating_sub(span.start)))
}

/// Build a renderable report from the checker's mismatches, or `None`
/// when there are none. `source` is the config text; `path` is shown in
/// the excerpt header.
pub fn build_report(
    mismatches: &[ShapeMismatch],
    source: &str,
    path: &str,
) -> Option<miette::Report> {
    if mismatches.is_empty() {
        return None;
    }
    let problems = mismatches
        .iter()
        .map(|m| ShapeDiagnostic {
            header: header_for(m.operator),
            src: NamedSource::new(path, source.to_string()).with_language("lisp"),
            use_span: to_source_span(m.use_span),
            use_label: use_label_for(m.operator),
            decl_span: m.decl_span.map(to_source_span),
            decl_label: decl_label_for(m),
            help: hint_for(m),
        })
        .collect();
    Some(miette::Report::new(ShapeReport { problems }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_config::parse_config;
    use may_i_engine::shape_check::check_config;

    fn render(src: &str) -> String {
        let config = parse_config(src).expect("parses");
        let mismatches = check_config(&config);
        let report = build_report(&mismatches, src, "config.lisp").expect("a report");
        // Render via the same graphical handler used in production, with
        // colour disabled for stable assertions.
        let mut out = String::new();
        let handler =
            miette::GraphicalReportHandler::new_themed(miette::GraphicalTheme::unicode_nocolor());
        handler.render_report(&mut out, report.as_ref()).unwrap();
        out
    }

    #[test]
    fn every_on_token_renders_list_expected_with_hint() {
        let out = render(
            "(parser \"xargs\" (style gnu) (flags posix) (parameter \"n\" #procs) (rest #cmd))\n\
             (rule \"xargs\" (when (every? #procs (regex \"^[0-9]+$\")) (allow)))",
        );
        assert!(out.contains("`every?` needs a list of values"), "{out}");
        assert!(out.contains("but `#procs` is a single value"), "{out}");
        assert!(out.contains("(parameter \"n\" (set #procs))"), "{out}");
    }

    #[test]
    fn rendered_text_never_leaks_internal_vocabulary() {
        let configs = [
            "(parser \"ssh\" (style gnu) (flags posix) (parameter \"o\" (set #opts)))\n\
             (rule \"ssh\" (authorise #opts))",
            "(parser \"xargs\" (style gnu) (flags posix) (parameter \"n\" #procs) (rest #cmd))\n\
             (rule \"xargs\" (when (every? #procs (regex \"x\")) (allow)))",
            "(parser \"bash\" (style gnu) (flags posix) (parameter \"c\" (command #cmd)))\n\
             (rule \"bash\" (when (some? #cmd (regex \"rm\")) (deny)))",
        ];
        for src in configs {
            let out = render(src).to_lowercase();
            for banned in [
                "shape",
                "type",
                "ast",
                "token",
                "collectiontoken",
                "predicate",
            ] {
                assert!(
                    !out.contains(banned),
                    "rendered text leaked `{banned}`:\n{out}"
                );
            }
        }
    }

    #[test]
    fn hints_without_a_parameter_name() {
        // Positional bindings carry no parameter NAME, so their hints must
        // never propose a (parameter …) rewrite — they route to the
        // declaration-kind that actually applies.

        // every? over a single-token positional → widen the quantifier.
        let widen = render(
            "(parser \"rm\" (style gnu) (flags posix) (positional #ps *))\n\
             (rule \"rm\" (when (every? #ps (regex \"^/tmp/\")) (allow)))",
        );
        assert!(widen.contains("(positional #ps"), "{widen}");
        assert!(!widen.contains("(parameter"), "{widen}");

        // authorise over a collection positional → iteration arm only.
        let iterate = render(
            "(parser \"rm\" (style gnu) (flags posix) (positional #ps * *))\n\
             (rule \"rm\" (authorise #ps))",
        );
        assert!(
            iterate.contains("`authorise` needs a command line"),
            "{iterate}"
        );
        assert!(
            iterate.contains("but `#ps` is a list of values"),
            "{iterate}"
        );
        assert!(iterate.contains("(every? #ps"), "{iterate}");
        assert!(!iterate.contains("(parameter"), "{iterate}");
        assert!(!iterate.contains("(command"), "{iterate}");
    }

    #[test]
    fn positional_token_hint_widens_quantifier() {
        // (every? …) over a single-token positional: the remedy is to
        // widen the positional's quantifier, not to declare a parameter.
        let out = render(
            "(parser \"rm\" (style gnu) (flags posix) (positional #v *))\n\
             (rule \"rm\" (when (every? #v (regex \"^/tmp/\")) (allow)))",
        );
        assert!(out.contains("(positional #"), "{out}");
        assert!(!out.contains("(parameter"), "{out}");
    }

    #[test]
    fn positional_collection_authorise_omits_command_arm() {
        // authorise over a collection positional: iteration is the only
        // applicable arm — no (command …) rewrite (positionals have none).
        let out = render(
            "(parser \"rm\" (style gnu) (flags posix) (positional #v * +))\n\
             (rule \"rm\" (authorise #v))",
        );
        assert!(out.contains("(every? #"), "{out}");
        assert!(!out.contains("(command"), "{out}");
    }

    #[test]
    fn rest_iteration_hint_routes_to_authorise() {
        // (every? …) over a (rest …) binding: rest captures the whole
        // tail, so the remedy is to recurse with authorise.
        let out = render(
            "(parser \"sudo\" (style gnu) (flags posix) (rest #rest))\n\
             (rule \"sudo\" (when (every? #rest (regex \"rm\")) (allow)))",
        );
        assert!(out.contains("(authorise #rest)"), "{out}");
        assert!(!out.contains("(parameter"), "{out}");
    }

    #[test]
    fn authorise_on_collection_hints_iteration() {
        let out = render(
            "(parser \"ssh\" (style gnu) (flags posix) (parameter \"o\" (set #opts)))\n\
             (rule \"ssh\" (authorise #opts))",
        );
        assert!(out.contains("`authorise` needs a command line"), "{out}");
        assert!(out.contains("but `#opts` is a list of values"), "{out}");
        assert!(out.contains("(every? #opts"), "{out}");
    }
}
