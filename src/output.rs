// Shared display helpers for trace output.
//
// Trace-specific rendering built on top of the `may_i_layout` crate's
// declarative Layout primitives.

use std::io::Write;

use colored::Colorize;
use may_i_core::doc::{Doc, DocF, LayoutHint};
use may_i_pp::{Format, colorize_atom, pretty, visible_len};

pub use may_i_layout::{
    ColAlign, ColContent, ColItem, ColRow, HRuleLabel, Layout, Terminal, strip_ansi, write_layout,
};

use crate::annotation::{Ann, TraceEntry};

// ── Column geometry (trace-specific) ──────────────────────────────

const MIN_TERM_WIDTH: usize = 40;

struct ColumnGeometry {
    left_width: usize,
}

fn detect_column_geometry(term: &Terminal) -> ColumnGeometry {
    let usable = term.width.saturating_sub(2).max(MIN_TERM_WIDTH);
    ColumnGeometry {
        left_width: usable / 2,
    }
}

// ── Facts rows (2-column layout) ──────────────────────────────────

fn facts_rows(facts: &[(String, String)]) -> Vec<ColRow> {
    let items: Vec<ColItem> = facts
        .iter()
        .map(|(key, value)| {
            let quoted = format!("\"{value}\"");
            let colored = format!(
                "{} {}",
                colorize_atom(key, true),
                colorize_atom(&quoted, true)
            );
            let width = key.len() + 1 + quoted.len();
            ColItem::new(colored, width)
        })
        .collect();

    let label = "facts";
    vec![ColRow {
        left: label.dimmed().to_string(),
        left_width: label.len(),
        left_align: ColAlign::Right,
        right: ColContent::Breakable {
            items,
            separator: ", ".dimmed().to_string(),
            separator_width: 2,
        },
    }]
}

fn command_row(cmd: &str, _geom: &ColumnGeometry) -> Vec<ColRow> {
    let label = "command";
    let label_colored = label.dimmed().to_string();
    let mut row = ColRow::new(label_colored, label.len(), cmd.bold().to_string());
    row.left_align = ColAlign::Right;
    vec![row]
}

// ── Separator (public convenience for cmd_check) ──────────────────

pub fn print_separator(indent: &str, label: Option<(&str, usize)>, term: &Terminal) {
    let hrule_label = label.map(|(text, w)| HRuleLabel {
        text: text.to_string(),
        visible_width: w,
    });
    let layout = Layout::HRule(hrule_label);
    let indented = Layout::Indent(indent.len(), Box::new(layout));
    write_layout(&mut std::io::stdout(), &indented, term);
}

// ── Public convenience for cmd_check ──────────────────────────────

pub fn render_elements(indent: &str, elements: &[Layout], term: &Terminal) {
    let layout = Layout::Indent(indent.len(), Box::new(Layout::Stack(elements.to_vec())));
    write_layout(&mut std::io::stdout(), &layout, term);
}

// ── Trace rendering ────────────────────────────────────────────────

pub fn print_trace(entries: &[TraceEntry], command: &str, indent: &str, term: &Terminal) {
    write_trace(&mut std::io::stdout(), entries, command, indent, term);
}

pub fn write_trace(
    w: &mut impl Write,
    entries: &[TraceEntry],
    command: &str,
    indent: &str,
    term: &Terminal,
) {
    let layout = trace_to_layout(entries, command, indent.len(), term);
    write_layout(w, &layout, term);
}

/// Convert trace entries into a declarative layout tree.
pub fn trace_to_layout(
    entries: &[TraceEntry],
    command: &str,
    indent: usize,
    term: &Terminal,
) -> Layout {
    let geom = detect_column_geometry(term);
    let mut children: Vec<Layout> = Vec::new();
    let mut first = true;

    // Determine if trace has segment headers (compound commands).
    let has_segments = entries
        .iter()
        .any(|e| matches!(e, TraceEntry::SegmentHeader { .. }));

    // Show the command on the first rule of each section.
    // For compound commands, this gets reset from each segment header.
    let mut pending_command: Option<&str> = if !has_segments { Some(command) } else { None };

    // Accumulate rows for consecutive rules that share a command context.
    let mut current_rows: Vec<ColRow> = Vec::new();
    // Track last-shown facts within a group to skip identical repeats.
    let mut last_shown_facts: Option<&Vec<(String, String)>> = None;

    // Flush accumulated rows into a Columns layout.
    let flush_rows = |rows: &mut Vec<ColRow>, children: &mut Vec<Layout>| {
        if !rows.is_empty() {
            children.push(Layout::Columns(std::mem::take(rows)));
        }
    };

    for entry in entries {
        match entry {
            TraceEntry::SegmentHeader { command, decision } => {
                flush_rows(&mut current_rows, &mut children);
                if !first {
                    children.push(Layout::Blank);
                    children.push(Layout::Blank);
                }
                children.push(segment_header_layout(command, *decision));
                pending_command = Some(command);
            }
            TraceEntry::Rule {
                doc,
                line,
                pre_migration_doc: _,
                facts,
                inner_command,
            } => {
                if inner_command.is_some() || pending_command.is_some() {
                    // Flush previous group before starting a new command context.
                    flush_rows(&mut current_rows, &mut children);
                    last_shown_facts = None;
                    if !first {
                        children.push(Layout::Blank);
                    }
                } else if !current_rows.is_empty() {
                    // Visual separator between consecutive rules in the same group.
                    current_rows.push(ColRow::new(" ", 1, ""));
                }

                // Show the command being evaluated (only at start of group).
                if let Some(cmd) = pending_command.take() {
                    current_rows.extend(command_row(cmd, &geom));
                } else if let Some(cmd) = inner_command {
                    current_rows.extend(command_row(cmd, &geom));
                }
                // Show facts, but skip if identical to the previous rule in this group.
                if !facts.is_empty() && last_shown_facts.as_ref() != Some(&facts) {
                    current_rows.extend(facts_rows(facts));
                }
                last_shown_facts = Some(facts);
                current_rows.extend(render_annotated_rule(doc, *line, &geom));
            }
            TraceEntry::DefaultAsk { .. } => {
                let label = "No matching rule".italic().yellow().to_string();
                let label_visible = "No matching rule".len();
                let mut row = ColRow::new(label, label_visible, colorize_right("→ :ask (default)"));
                row.left_align = ColAlign::Right;
                current_rows.push(row);
            }
        }
        first = false;
    }
    flush_rows(&mut current_rows, &mut children);

    Layout::Indent(indent, Box::new(Layout::Stack(children)))
}

fn segment_header_layout(command: &str, decision: may_i_core::Decision) -> Layout {
    use may_i_core::Decision;
    let icon = match decision {
        Decision::Allow => "✓".green().bold().to_string(),
        Decision::Ask => "?".yellow().bold().to_string(),
        Decision::Deny => "✗".red().bold().to_string(),
    };
    let label = format!("{icon} {}", command.bold());
    let label_width = 2 + command.len();
    Layout::HRule(Some(HRuleLabel {
        text: label,
        visible_width: label_width,
    }))
}

// ── Annotated Doc renderer ─────────────────────────────────────────

fn render_annotated_rule(
    doc: &Doc<Option<Ann>>,
    line: Option<usize>,
    geom: &ColumnGeometry,
) -> Vec<ColRow> {
    let doc = dim_unevaluated(truncate_unevaluated(&truncate_matched_anywhere(doc), 2));
    let fmt = Format {
        width: geom.left_width,
        color: true,
        line_number: line,
    };
    let rendered = pretty(&doc, 0, &fmt);

    let annotations = collect_annotations(&doc);
    let outcome = extract_outcome(&doc);
    let matched = has_match(&doc);

    let rendered_lines: Vec<&str> = rendered.lines().collect();
    let stripped_lines: Vec<String> = rendered_lines.iter().map(|l| strip_ansi(l)).collect();

    let mut line_annotations: Vec<String> = vec![String::new(); rendered_lines.len()];
    let mut overflow: Vec<String> = Vec::new();
    let mut search_from = 0;

    for (needle, right_text) in &annotations {
        if needle.is_empty() {
            overflow.push(right_text.clone());
        } else if let Some(idx) = find_line(&stripped_lines, needle, &mut search_from) {
            line_annotations[idx] = right_text.clone();
        } else {
            overflow.push(right_text.clone());
        }
    }

    // Place outcome annotation on a "(effect" line only if collect_annotations
    // didn't already place the same EffectDecision annotation somewhere.
    let already_has_effect_decision = annotations.iter().any(|(_, text)| text.starts_with("→ :"));
    if let Some(out) = outcome
        && matched
        && !already_has_effect_decision
    {
        let mut placed = false;
        for (i, stripped) in stripped_lines.iter().enumerate() {
            if stripped.contains("(effect") && line_annotations[i].is_empty() {
                line_annotations[i] = out.clone();
                placed = true;
                break;
            }
        }
        if !placed {
            overflow.push(out);
        }
    }

    // Pre-colorize right column text before building ColRows.
    let mut rows: Vec<ColRow> = rendered_lines
        .iter()
        .enumerate()
        .map(|(i, sline)| {
            ColRow::new(
                sline.to_string(),
                visible_len(sline),
                colorize_right(&line_annotations[i]),
            )
        })
        .collect();

    for ann in &overflow {
        rows.push(ColRow::new("", 0, colorize_right(ann)));
    }

    rows
}

/// Collect (search_needle, right_column_text) pairs from annotated Doc nodes.
fn collect_annotations(doc: &Doc<Option<Ann>>) -> Vec<(String, String)> {
    let mut result = Vec::new();
    collect_annotations_inner(doc, &mut result);
    result
}

fn collect_annotations_inner(doc: &Doc<Option<Ann>>, out: &mut Vec<(String, String)>) {
    if let Some(ann) = &doc.ann {
        // Generate per-token annotations for anywhere/forbidden patterns.
        if let Ann::ArgMatch {
            search_tokens,
            arg_set,
            matched,
        } = ann
        {
            // Generate positional comparison annotations.
            if search_tokens.is_empty() && !arg_set.is_empty() {
                let positional = extract_positional_args(arg_set);
                collect_positional_annotations(doc, &positional, out);
                // Don't return — still recurse for child annotations
            }
            if !search_tokens.is_empty() {
                let quoted_set = quote_arg_set(arg_set);
                // Determine if this is a "forbidden" pattern.
                // For forbidden: matched=true means "no forbidden args found"
                // so each token should show "→ no". For anywhere: matched=true
                // means "at least one token was found in args".
                let is_forbidden = is_forbidden_pattern(doc);
                if is_forbidden {
                    if *matched {
                        // Forbidden passed: no forbidden tokens found → show all "→ no"
                        for token in search_tokens {
                            let arrow = "→ no";
                            out.push((
                                token.clone(),
                                format!("{token} ∈ {{{quoted_set}}} {arrow}"),
                            ));
                        }
                    } else {
                        // Forbidden failed: at least one token found.
                        // After truncation, only first matching token remains in doc.
                        // Show only that token's annotation.
                        for token in search_tokens {
                            let found = arg_set.iter().any(|a| {
                                let unquoted = token.trim_matches('"');
                                a == unquoted
                            });
                            if found {
                                out.push((
                                    token.clone(),
                                    format!("{token} ∈ {{{quoted_set}}} → yes"),
                                ));
                                break;
                            }
                        }
                    }
                } else if *matched {
                    // Anywhere: when matched, show only the first matching token.
                    let first_token = &search_tokens[0];
                    let arrow = "→ yes";
                    out.push((
                        first_token.clone(),
                        format!("{first_token} ∈ {{{quoted_set}}} {arrow}"),
                    ));
                } else {
                    // Anywhere: when not matched, show each token individually
                    for token in search_tokens {
                        let arrow = "→ no";
                        out.push((token.clone(), format!("{token} ∈ {{{quoted_set}}} {arrow}")));
                    }
                }
                // Don't recurse into children for annotated arg patterns
                return;
            }
        }
        if let Some(pair) = format_annotation(doc, ann) {
            out.push(pair);
        }
    }
    if let DocF::List(children) = &doc.node {
        for child in children {
            collect_annotations_inner(child, out);
        }
    }
}

/// Format an annotation into (search_needle, right_column_text).
fn format_annotation(doc: &Doc<Option<Ann>>, ann: &Ann) -> Option<(String, String)> {
    match ann {
        Ann::CommandMatch { matched } => {
            // Only annotate non-matching commands; matching is implied
            // since skipped rules are not shown.
            if !matched && matches!(doc.node, DocF::Atom(_)) {
                let needle = node_text(doc);
                Some((needle, verdict(false)))
            } else {
                None
            }
        }
        Ann::RuleMatch { .. } => None,
        Ann::Combinator { .. } => None,

        Ann::MayI {
            inner_command,
            decision,
            reason,
        } => {
            let keyword = format!(":{decision}");
            let right = match reason {
                Some(r) => format!("`{inner_command}` → {keyword} \"{r}\""),
                None => format!("`{inner_command}` → {keyword}"),
            };
            Some((node_text(doc), right))
        }

        Ann::BindMatch { key, value } => {
            let right = match value {
                Some(v) => format!("facts += {key} \"{v}\""),
                None => format!("{key} — no match"),
            };
            Some((node_text(doc), right))
        }

        Ann::RegexMatch {
            pattern,
            actual,
            matched,
        } => {
            let arrow = if *matched { "→ yes" } else { "→ no" };
            let right = format!("\"{actual}\" ~ (regex \"{pattern}\") {arrow}");
            Some((node_text(doc), right))
        }

        Ann::EffectDecision { decision, reason } => {
            let keyword = format!(":{decision}");
            let right = match reason {
                Some(r) => format!("→ {keyword} \"{r}\""),
                None => format!("→ {keyword}"),
            };
            Some((node_text(doc), right))
        }

        Ann::ArgMatch { .. } => {
            // Arg match annotations are handled by collect_annotations_inner
            // which generates per-token annotations for anywhere/forbidden patterns.
            None
        }

        Ann::FactQuery {
            query_source: _,
            matched,
            observed,
            failure_reason: _,
        } => {
            let needle = node_text(doc);
            match observed {
                Some(values) if !values.is_empty() => {
                    let observed_str = render_observed_value(&values[0]);
                    let arrow = if *matched { "yes" } else { "no" };
                    Some((needle, format!("{observed_str} → {arrow}")))
                }
                _ => Some((needle, verdict(*matched))),
            }
        }
    }
}

fn verdict(matched: bool) -> String {
    if matched { "yes".into() } else { "no".into() }
}

fn render_observed_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped.push('"');

    let char_count = escaped.chars().count();
    if char_count <= 40 {
        escaped
    } else {
        let inner = escaped.chars().skip(1).take(35).collect::<String>();
        let mut truncated = String::from("\"");
        truncated.push_str(&inner);
        truncated.push('…');
        truncated.push('"');
        truncated
    }
}

fn node_text(doc: &Doc<Option<Ann>>) -> String {
    doc.fold(&|node, _ann: &Option<Ann>| match node {
        DocF::Atom(s) => s,
        DocF::List(cs) => format!("({})", cs.join(" ")),
        DocF::Vector(cs) => format!("[{}]", cs.join(" ")),
    })
}

/// Extract the rule-level outcome annotation (EffectDecision on an effect node).
fn extract_outcome(doc: &Doc<Option<Ann>>) -> Option<String> {
    // Look for EffectDecision in direct children of the rule.
    if let DocF::List(children) = &doc.node {
        for child in children {
            if let Some(Ann::EffectDecision { decision, reason }) = &child.ann {
                let keyword = format!(":{decision}");
                return Some(match reason {
                    Some(r) => format!("→ {keyword} \"{r}\""),
                    None => format!("→ {keyword}"),
                });
            }
        }
    }
    None
}

/// Check if the rule matched (has a RuleMatch { matched: true } annotation).
fn has_match(doc: &Doc<Option<Ann>>) -> bool {
    if let Some(Ann::RuleMatch { matched: true, .. }) = &doc.ann {
        return true;
    }
    if let DocF::List(children) | DocF::Vector(children) = &doc.node {
        children.iter().any(has_match)
    } else {
        false
    }
}

fn find_line(stripped_lines: &[String], needle: &str, search_from: &mut usize) -> Option<usize> {
    for (i, line) in stripped_lines.iter().enumerate().skip(*search_from) {
        if line.contains(needle) {
            *search_from = i + 1;
            return Some(i);
        }
    }
    let first_token = needle.split_whitespace().next().unwrap_or(needle);
    if first_token != needle && first_token.len() >= 2 {
        for (i, line) in stripped_lines.iter().enumerate().skip(*search_from) {
            if line.contains(first_token) {
                *search_from = i + 1;
                return Some(i);
            }
        }
    }
    None
}

// ── Tree manipulation ──────────────────────────────────────────────

/// For `(anywhere ...)` / `(forbidden ...)` patterns with a successful ArgMatch,
/// truncate to only the first matching token.
fn truncate_matched_anywhere(doc: &Doc<Option<Ann>>) -> Doc<Option<Ann>> {
    if let Some(Ann::ArgMatch {
        matched: true,
        search_tokens,
        ..
    }) = &doc.ann
        && !search_tokens.is_empty()
        && !is_forbidden_pattern(doc)
        && let DocF::List(children) = &doc.node
    {
        // Check if head is "anywhere"
        let head = children.first().and_then(|c| c.as_atom());
        if matches!(head, Some("anywhere")) && children.len() > 2 {
            // Keep head + first matching token only
            let truncated = vec![children[0].clone(), children[1].clone()];
            return Doc {
                ann: doc.ann.clone(),
                node: DocF::List(truncated),
                layout: doc.layout,
                dimmed: doc.dimmed,
            };
        }
    }
    // Recurse into children
    match &doc.node {
        DocF::List(children) => Doc {
            ann: doc.ann.clone(),
            node: DocF::List(children.iter().map(truncate_matched_anywhere).collect()),
            layout: doc.layout,
            dimmed: doc.dimmed,
        },
        DocF::Vector(children) => Doc {
            ann: doc.ann.clone(),
            node: DocF::Vector(children.iter().map(truncate_matched_anywhere).collect()),
            layout: doc.layout,
            dimmed: doc.dimmed,
        },
        DocF::Atom(_) => doc.clone(),
    }
}

fn truncate_unevaluated(doc: &Doc<Option<Ann>>, keep: usize) -> Doc<Option<Ann>> {
    // Don't truncate inside anywhere/forbidden patterns — their children
    // are individual search tokens that should all be visible.
    if let Some(Ann::ArgMatch { search_tokens, .. }) = &doc.ann
        && !search_tokens.is_empty()
    {
        return doc.clone();
    }
    match &doc.node {
        DocF::Atom(_) => doc.clone(),
        DocF::List(children) => {
            let children: Vec<Doc<Option<Ann>>> = children
                .iter()
                .map(|c| truncate_unevaluated(c, keep))
                .collect();
            let head = children.first().and_then(|c| c.as_atom());
            let has_head = head.is_some();
            let args_unevaluated =
                has_head && children[1..].iter().all(|c| !has_any_visible_annotation(c));
            if args_unevaluated && children.len() > keep + 2 {
                let mut truncated = Vec::with_capacity(keep + 3);
                truncated.push(children[0].clone());
                truncated.extend(children[1..=keep].iter().cloned());
                truncated.push(Doc {
                    ann: None,
                    node: DocF::Atom("…".into()),
                    layout: LayoutHint::Auto,
                    dimmed: true,
                });
                truncated.push(children.last().unwrap().clone());
                Doc {
                    ann: doc.ann.clone(),
                    node: DocF::List(truncated),
                    layout: doc.layout,
                    dimmed: doc.dimmed,
                }
            } else {
                Doc {
                    ann: doc.ann.clone(),
                    node: DocF::List(children),
                    layout: doc.layout,
                    dimmed: doc.dimmed,
                }
            }
        }
        DocF::Vector(children) => Doc {
            ann: doc.ann.clone(),
            node: DocF::Vector(
                children
                    .iter()
                    .map(|c| truncate_unevaluated(c, keep))
                    .collect(),
            ),
            layout: doc.layout,
            dimmed: doc.dimmed,
        },
    }
}

fn dim_unevaluated(doc: Doc<Option<Ann>>) -> Doc<Option<Ann>> {
    dim_unevaluated_inner(doc, false).0
}

/// Recursively dim nodes that were never evaluated.
///
/// `ancestor_annotated` is true when a parent node carries an annotation,
/// meaning this subtree is part of an evaluated expression and should stay
/// syntax-highlighted even if the children themselves have no annotations.
fn dim_unevaluated_inner(
    doc: Doc<Option<Ann>>,
    ancestor_annotated: bool,
) -> (Doc<Option<Ann>>, usize) {
    let self_score = usize::from(doc.ann.is_some());
    let children_inherit = ancestor_annotated || self_score > 0;
    match doc.node {
        DocF::Atom(_) => (doc, self_score),
        DocF::List(children) => {
            let mut total = self_score;
            let children: Vec<_> = children
                .into_iter()
                .map(|c| {
                    let (c, n) = dim_unevaluated_inner(c, children_inherit);
                    total += n;
                    c
                })
                .collect();
            let dimmed = doc.dimmed || (!ancestor_annotated && total == 0);
            (
                Doc {
                    ann: doc.ann,
                    node: DocF::List(children),
                    layout: doc.layout,
                    dimmed,
                },
                total,
            )
        }
        DocF::Vector(children) => {
            let mut total = self_score;
            let children: Vec<_> = children
                .into_iter()
                .map(|c| {
                    let (c, n) = dim_unevaluated_inner(c, children_inherit);
                    total += n;
                    c
                })
                .collect();
            let dimmed = doc.dimmed || (!ancestor_annotated && total == 0);
            (
                Doc {
                    ann: doc.ann,
                    node: DocF::Vector(children),
                    layout: doc.layout,
                    dimmed,
                },
                total,
            )
        }
    }
}

fn has_any_visible_annotation(doc: &Doc<Option<Ann>>) -> bool {
    if let Some(ann) = &doc.ann
        && !matches!(ann, Ann::RuleMatch { .. })
    {
        return true;
    }
    if let DocF::List(children) | DocF::Vector(children) = &doc.node {
        children.iter().any(has_any_visible_annotation)
    } else {
        false
    }
}

/// Extract positional (non-flag) arguments from the argument list.
/// Mirrors `eval::positional_args` logic.
fn extract_positional_args(args: &[String]) -> Vec<&str> {
    let mut result = Vec::new();
    let mut iter = args.iter().peekable();
    let mut past_terminator = false;

    while let Some(arg) = iter.next() {
        if past_terminator {
            result.push(arg.as_str());
        } else if arg == "--" {
            result.push(arg.as_str());
            past_terminator = true;
        } else if arg.starts_with("--") {
            if !arg.contains('=') {
                iter.next();
            }
        } else if arg.starts_with('-') {
            // Short flag — skip
        } else {
            result.push(arg.as_str());
        }
    }
    result
}

/// Generate positional comparison annotations for a positional/exact pattern doc.
/// Walks the doc's child pattern atoms and generates `"actual" = "pattern" → yes/no`.
fn collect_positional_annotations(
    doc: &Doc<Option<Ann>>,
    positional_args: &[&str],
    out: &mut Vec<(String, String)>,
) {
    if let DocF::List(children) = &doc.node {
        let head = children.first().and_then(|c| c.as_atom());
        if !matches!(head, Some("positional" | "exact")) {
            return;
        }
        // For positional patterns, the first positional arg is compared against
        // each pattern element in sequence. Walk the pattern children (skip head atom).
        if let Some(first_arg) = positional_args.first() {
            for child in children.iter().skip(1) {
                collect_pattern_comparisons(child, first_arg, out);
            }
        }
    }
}

/// Generate comparison annotations for a pattern element within a positional match.
fn collect_pattern_comparisons(
    pattern_doc: &Doc<Option<Ann>>,
    actual_arg: &str,
    out: &mut Vec<(String, String)>,
) {
    match &pattern_doc.node {
        DocF::Atom(s) => {
            // String literal pattern — compare against actual arg.
            if s.starts_with('"') && s.ends_with('"') {
                let pattern_text = &s[1..s.len() - 1];
                let matched = actual_arg == pattern_text;
                let arrow = if matched { "→ yes" } else { "→ no" };
                out.push((s.clone(), format!("\"{}\" = {} {arrow}", actual_arg, s)));
            }
        }
        DocF::List(children) => {
            // Check for (or "a" "b" ...) or (? pattern)
            let head = children.first().and_then(|c| c.as_atom());
            match head {
                Some("or") => {
                    // Generate comparison for each alternative
                    for child in children.iter().skip(1) {
                        collect_pattern_comparisons(child, actual_arg, out);
                    }
                }
                Some("?" | "+" | "*") => {
                    // Quantifier — compare against inner pattern
                    if let Some(inner) = children.get(1) {
                        collect_pattern_comparisons(inner, actual_arg, out);
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
}

fn is_forbidden_pattern(doc: &Doc<Option<Ann>>) -> bool {
    if let DocF::List(children) = &doc.node
        && let Some(head) = children.first().and_then(|c| c.as_atom())
    {
        if head == "forbidden" {
            return true;
        }
        // Forbidden is rendered as (not (anywhere ...))
        if head == "not"
            && let Some(inner) = children.get(1)
            && let DocF::List(inner_children) = &inner.node
            && let Some(inner_head) = inner_children.first().and_then(|c| c.as_atom())
        {
            return inner_head == "anywhere";
        }
    }
    false
}

fn quote_arg_set(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| format!("\"{}\"", s)).collect();
    truncate_list(&quoted, 4)
}

fn truncate_list(items: &[String], max: usize) -> String {
    if items.len() <= max {
        items.join(", ")
    } else {
        let mut parts: Vec<&str> = items[..2].iter().map(|s| s.as_str()).collect();
        parts.push("…");
        parts.push(items.last().unwrap());
        parts.join(", ")
    }
}

// ── Right-column colorization ──────────────────────────────────────

fn colorize_right(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }

    if s.starts_with("(effect ") || s.starts_with("(default ") {
        return colorize_effect_sexpr(s);
    }

    if s == "yes" {
        return "yes".green().bold().to_string();
    }
    if s == "no" {
        return "no".yellow().to_string();
    }

    if let Some(arrow_pos) = s.find("→") {
        let before = &s[..arrow_pos];
        let after = s[arrow_pos + "→".len()..].trim();
        let colored_result = match after {
            "yes" => "yes".green().bold().to_string(),
            "no" => "no".yellow().to_string(),
            "missing" => "missing".yellow().to_string(),
            other if other.starts_with(':') => {
                if let Some(space) = other.find(' ') {
                    let keyword = &other[..space];
                    let rest = other[space..].trim();
                    format!(
                        "{} {}",
                        colorize_decision_keyword(keyword),
                        colorize_atom(rest, true)
                    )
                } else {
                    colorize_decision_keyword(other)
                }
            }
            other => other.to_string(),
        };
        format!("{}{} {colored_result}", before.dimmed(), "→".dimmed())
    } else if let Some(rest) = s.strip_prefix("facts += ") {
        // Bind annotation: facts += :key "value"
        // Colorize keyword and string to match expression syntax colors
        if let Some(space_pos) = rest.find(' ') {
            let keyword = &rest[..space_pos];
            let value = &rest[space_pos + 1..];
            format!(
                "{} {} {}",
                "facts +=".dimmed(),
                colorize_atom(keyword, true),
                colorize_atom(value, true),
            )
        } else {
            s.dimmed().to_string()
        }
    } else if s.contains("~") {
        // Regex match annotation: "actual" ~ (regex "pattern") → yes/no
        if let Some(arrow_pos) = s.find("→") {
            let before = &s[..arrow_pos];
            let after = s[arrow_pos + "→".len()..].trim();
            let colored_result = match after {
                "yes" => "yes".green().bold().to_string(),
                "no" => "no".yellow().to_string(),
                other => other.to_string(),
            };
            format!("{}{} {colored_result}", before.dimmed(), "→".dimmed())
        } else {
            s.dimmed().to_string()
        }
    } else if s.contains("∈") {
        // Arg match annotations: pattern ∈ {args} → yes/no
        if let Some(arrow_pos) = s.find("→") {
            let before = &s[..arrow_pos];
            let after = s[arrow_pos + "→".len()..].trim();
            let colored_result = match after {
                "yes" => "yes".green().bold().to_string(),
                "no" => "no".yellow().to_string(),
                other => other.to_string(),
            };
            format!("{}{} {colored_result}", before.dimmed(), "→".dimmed())
        } else {
            s.dimmed().to_string()
        }
    } else {
        s.dimmed().to_string()
    }
}

pub fn colorize_decision_keyword(s: &str) -> String {
    if s == ":allow" {
        s.green().bold().to_string()
    } else if s == ":ask" {
        s.yellow().bold().to_string()
    } else if s == ":deny" {
        s.red().bold().to_string()
    } else {
        s.to_string()
    }
}

fn colorize_effect_sexpr(s: &str) -> String {
    s.replace(":allow", &":allow".green().bold().to_string())
        .replace(":ask", &":ask".yellow().bold().to_string())
        .replace(":deny", &":deny".red().bold().to_string())
}

// ── Path display ───────────────────────────────────────────────────

pub fn shorten_home(path: &std::path::Path) -> String {
    if let Ok(home) = std::env::var("HOME")
        && let Ok(rest) = path.strip_prefix(&home)
    {
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

// ── JSON output ────────────────────────────────────────────────────

pub fn trace_to_json(entries: &[TraceEntry]) -> Vec<serde_json::Value> {
    entries
        .iter()
        .map(|entry| match entry {
            TraceEntry::SegmentHeader { command, decision } => serde_json::json!({
                "type": "segment_header",
                "command": command,
                "decision": decision.to_string(),
            }),
            TraceEntry::DefaultAsk { reason } => serde_json::json!({
                "type": "default_ask",
                "reason": reason,
            }),
            TraceEntry::Rule { doc, line, .. } => {
                let mut annotations = Vec::new();
                collect_json_annotations(doc, &mut annotations);
                serde_json::json!({
                    "type": "rule",
                    "line": line,
                    "structure": doc_to_json(doc),
                    "annotations": annotations,
                })
            }
        })
        .collect()
}

fn collect_json_annotations(doc: &Doc<Option<Ann>>, out: &mut Vec<serde_json::Value>) {
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
        Ann::RuleMatch { matched, line } => serde_json::json!({
            "type": "rule_match",
            "matched": matched,
            "line": line,
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
    use may_i_core::doc::LayoutHint;
    use proptest::prelude::*;

    fn atom(s: &str) -> Doc<Option<Ann>> {
        Doc {
            ann: None,
            node: DocF::Atom(s.into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    fn atom_ann(s: &str, ann: Ann) -> Doc<Option<Ann>> {
        Doc {
            ann: Some(ann),
            node: DocF::Atom(s.into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    fn list(children: Vec<Doc<Option<Ann>>>) -> Doc<Option<Ann>> {
        Doc {
            ann: None,
            node: DocF::List(children),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    fn list_ann(ann: Ann, children: Vec<Doc<Option<Ann>>>) -> Doc<Option<Ann>> {
        Doc {
            ann: Some(ann),
            node: DocF::List(children),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    fn vec_doc(children: Vec<Doc<Option<Ann>>>) -> Doc<Option<Ann>> {
        Doc {
            ann: None,
            node: DocF::Vector(children),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    // ── find_line ──────────────────────────────────────────────────

    #[test]
    fn find_line_exact_match() {
        let lines = vec!["foo bar".into(), "baz".into()];
        let mut from = 0;
        assert_eq!(find_line(&lines, "baz", &mut from), Some(1));
        assert_eq!(from, 2);
    }

    #[test]
    fn find_line_fallback_to_first_token() {
        let lines = vec!["hello world".into(), "other".into()];
        let mut from = 0;
        // "hello xyz" doesn't match, but first token "hello" does
        assert_eq!(find_line(&lines, "hello xyz", &mut from), Some(0));
    }

    #[test]
    fn find_line_returns_none_when_not_found() {
        let lines = vec!["foo".into()];
        let mut from = 0;
        assert_eq!(find_line(&lines, "missing", &mut from), None);
    }

    // ── truncate_list ──────────────────────────────────────────────

    #[test]
    fn truncate_list_short() {
        let items: Vec<String> = vec!["a".into(), "b".into()];
        assert_eq!(truncate_list(&items, 4), "a, b");
    }

    #[test]
    fn truncate_list_long() {
        let items: Vec<String> = (0..6).map(|i| format!("item{i}")).collect();
        let result = truncate_list(&items, 4);
        assert!(result.contains("…"));
        assert!(result.starts_with("item0"));
        assert!(result.ends_with("item5"));
    }

    // ── render_observed_value ──────────────────────────────────────

    #[test]
    fn render_observed_value_short() {
        assert_eq!(render_observed_value("hello"), "\"hello\"");
    }

    #[test]
    fn render_observed_value_escapes() {
        let v = render_observed_value("a\"b\\c\nd");
        assert_eq!(v, r#""a\"b\\c\nd""#);
    }

    #[test]
    fn render_observed_value_truncates_long() {
        let long = "a".repeat(100);
        let rendered = render_observed_value(&long);
        assert!(rendered.len() < 100);
        assert!(rendered.contains("…"));
    }

    // ── node_text ─────────────────────────────────────────────────

    #[test]
    fn node_text_atom() {
        assert_eq!(node_text(&atom("hello")), "hello");
    }

    #[test]
    fn node_text_list() {
        let doc = list(vec![atom("a"), atom("b")]);
        assert_eq!(node_text(&doc), "(a b)");
    }

    #[test]
    fn node_text_vector() {
        let doc = vec_doc(vec![atom("x"), atom("y")]);
        assert_eq!(node_text(&doc), "[x y]");
    }

    // ── extract_outcome ───────────────────────────────────────────

    #[test]
    fn extract_outcome_finds_effect_decision() {
        let child = atom_ann(
            ":allow",
            Ann::EffectDecision {
                decision: may_i_core::Decision::Allow,
                reason: None,
            },
        );
        let doc = list(vec![atom("rule"), child]);
        let outcome = extract_outcome(&doc);
        assert!(outcome.is_some());
        assert!(outcome.unwrap().contains(":allow"));
    }

    #[test]
    fn extract_outcome_none_without_annotation() {
        let doc = list(vec![atom("rule"), atom("body")]);
        assert!(extract_outcome(&doc).is_none());
    }

    // ── has_match ─────────────────────────────────────────────────

    #[test]
    fn has_match_true() {
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(1),
            },
            vec![atom("rule")],
        );
        assert!(has_match(&doc));
    }

    #[test]
    fn has_match_false() {
        let doc = list(vec![atom("rule")]);
        assert!(!has_match(&doc));
    }

    // ── has_any_visible_annotation ────────────────────────────────

    #[test]
    fn visible_annotation_ignores_rule_match() {
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: None,
            },
            vec![atom("x")],
        );
        assert!(!has_any_visible_annotation(&doc));
    }

    #[test]
    fn visible_annotation_detects_effect_decision() {
        let doc = atom_ann(
            "x",
            Ann::EffectDecision {
                decision: may_i_core::Decision::Allow,
                reason: None,
            },
        );
        assert!(has_any_visible_annotation(&doc));
    }

    // ── is_forbidden_pattern ──────────────────────────────────────

    #[test]
    fn is_forbidden_direct() {
        let doc = list(vec![atom("forbidden"), atom("x")]);
        assert!(is_forbidden_pattern(&doc));
    }

    #[test]
    fn is_forbidden_via_not_anywhere() {
        let inner = list(vec![atom("anywhere"), atom("x")]);
        let doc = list(vec![atom("not"), inner]);
        assert!(is_forbidden_pattern(&doc));
    }

    #[test]
    fn not_forbidden_for_anywhere() {
        let doc = list(vec![atom("anywhere"), atom("x")]);
        assert!(!is_forbidden_pattern(&doc));
    }

    // ── dim_unevaluated ───────────────────────────────────────────

    #[test]
    fn dim_unevaluated_dims_unannotated() {
        let doc = list(vec![atom("rule"), atom("body")]);
        let dimmed = dim_unevaluated(doc);
        assert!(dimmed.dimmed);
    }

    #[test]
    fn dim_unevaluated_preserves_annotated() {
        let child = atom_ann(
            "x",
            Ann::EffectDecision {
                decision: may_i_core::Decision::Allow,
                reason: None,
            },
        );
        let doc = list(vec![atom("rule"), child]);
        let dimmed = dim_unevaluated(doc);
        assert!(!dimmed.dimmed);
    }

    // ── truncate_matched_anywhere ─────────────────────────────────

    #[test]
    fn truncate_anywhere_keeps_first_match() {
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec!["a".into(), "b".into(), "c".into()],
                arg_set: vec!["a".into()],
                matched: true,
            },
            vec![atom("anywhere"), atom("a"), atom("b"), atom("c")],
        );
        let truncated = truncate_matched_anywhere(&doc);
        if let DocF::List(children) = &truncated.node {
            assert_eq!(children.len(), 2); // head + first match
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn truncate_anywhere_preserves_unmatched() {
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec!["a".into()],
                arg_set: vec![],
                matched: false,
            },
            vec![atom("anywhere"), atom("a"), atom("b")],
        );
        let truncated = truncate_matched_anywhere(&doc);
        if let DocF::List(children) = &truncated.node {
            assert_eq!(children.len(), 3); // unchanged
        } else {
            panic!("expected list");
        }
    }

    // ── extract_positional_args ───────────────────────────────────

    #[test]
    fn extract_positional_args_basic() {
        let args = vec!["cmd".into(), "--flag".into(), "val".into(), "pos".into()];
        let result = extract_positional_args(&args);
        assert_eq!(result, vec!["cmd", "pos"]);
    }

    #[test]
    fn extract_positional_args_with_terminator() {
        let args = vec!["--opt".into(), "v".into(), "--".into(), "--not-flag".into()];
        let result = extract_positional_args(&args);
        assert_eq!(result, vec!["--", "--not-flag"]);
    }

    // ── colorize_right ────────────────────────────────────────────

    #[test]
    fn colorize_right_empty() {
        assert_eq!(colorize_right(""), "");
    }

    #[test]
    fn colorize_right_yes() {
        let result = colorize_right("yes");
        let stripped = strip_ansi(&result);
        assert_eq!(stripped, "yes");
    }

    #[test]
    fn colorize_right_no() {
        let result = colorize_right("no");
        let stripped = strip_ansi(&result);
        assert_eq!(stripped, "no");
    }

    #[test]
    fn colorize_right_arrow_keyword() {
        let result = colorize_right("→ :allow");
        let stripped = strip_ansi(&result);
        assert!(stripped.contains(":allow"));
    }

    #[test]
    fn colorize_right_arrow_keyword_with_reason() {
        let result = colorize_right("→ :deny \"reason\"");
        let stripped = strip_ansi(&result);
        assert!(stripped.contains(":deny"));
        assert!(stripped.contains("reason"));
    }

    #[test]
    fn colorize_right_effect_sexpr() {
        let result = colorize_right("(effect :allow)");
        let stripped = strip_ansi(&result);
        assert!(stripped.contains(":allow"));
    }

    #[test]
    fn colorize_right_facts_bind() {
        let result = colorize_right("facts += :key \"value\"");
        let stripped = strip_ansi(&result);
        assert!(stripped.contains(":key"));
        assert!(stripped.contains("value"));
    }

    #[test]
    fn colorize_right_regex() {
        let result = colorize_right("\"val\" ~ (regex \"pat\") → yes");
        let stripped = strip_ansi(&result);
        assert!(stripped.contains("yes"));
    }

    #[test]
    fn colorize_right_arg_match() {
        let result = colorize_right("\"t\" ∈ {\"a\", \"b\"} → no");
        let stripped = strip_ansi(&result);
        assert!(stripped.contains("no"));
    }

    // ── colorize_decision_keyword ─────────────────────────────────

    #[test]
    fn colorize_decision_keywords() {
        assert!(strip_ansi(&colorize_decision_keyword(":allow")).contains(":allow"));
        assert!(strip_ansi(&colorize_decision_keyword(":ask")).contains(":ask"));
        assert!(strip_ansi(&colorize_decision_keyword(":deny")).contains(":deny"));
        assert_eq!(colorize_decision_keyword(":other"), ":other");
    }

    // ── format_annotation ─────────────────────────────────────────

    #[test]
    fn format_annotation_command_mismatch() {
        let ann = Ann::CommandMatch { matched: false };
        let doc = atom("git");
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
        let (needle, text) = result.unwrap();
        assert_eq!(needle, "git");
        assert_eq!(text, "no");
    }

    #[test]
    fn format_annotation_command_match_returns_none() {
        let ann = Ann::CommandMatch { matched: true };
        let doc = atom("git");
        assert!(format_annotation(&doc, &ann).is_none());
    }

    #[test]
    fn format_annotation_may_i() {
        let ann = Ann::MayI {
            inner_command: "rm -rf /".into(),
            decision: may_i_core::Decision::Deny,
            reason: Some("dangerous".into()),
        };
        let doc = atom("(may-i *)");
        let result = format_annotation(&doc, &ann).unwrap();
        assert!(result.1.contains("rm -rf /"));
        assert!(result.1.contains(":deny"));
        assert!(result.1.contains("dangerous"));
    }

    #[test]
    fn format_annotation_bind_match() {
        let ann = Ann::BindMatch {
            key: ":host".into(),
            value: Some("prod".into()),
        };
        let doc = atom("[:host]");
        let result = format_annotation(&doc, &ann).unwrap();
        assert!(result.1.contains("facts +="));
        assert!(result.1.contains(":host"));
    }

    #[test]
    fn format_annotation_regex_match() {
        let ann = Ann::RegexMatch {
            pattern: "^prod".into(),
            actual: "prod-01".into(),
            matched: true,
        };
        let doc = atom("(regex)");
        let result = format_annotation(&doc, &ann).unwrap();
        assert!(result.1.contains("prod-01"));
        assert!(result.1.contains("yes"));
    }

    #[test]
    fn format_annotation_fact_query_with_observed() {
        let ann = Ann::FactQuery {
            query_source: "test".into(),
            matched: true,
            observed: Some(vec!["val".into()]),
            failure_reason: None,
        };
        let doc = atom("(fact?)");
        let result = format_annotation(&doc, &ann).unwrap();
        assert!(result.1.contains("val"));
        assert!(result.1.contains("yes"));
    }

    #[test]
    fn format_annotation_fact_query_without_observed() {
        let ann = Ann::FactQuery {
            query_source: "test".into(),
            matched: false,
            observed: None,
            failure_reason: None,
        };
        let doc = atom("(fact?)");
        let result = format_annotation(&doc, &ann).unwrap();
        assert_eq!(result.1, "no");
    }

    // ── JSON output ───────────────────────────────────────────────

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
        }];
        let json = trace_to_json(&entries);
        assert_eq!(json[0]["type"], "rule");
        assert_eq!(json[0]["line"], 1);
    }

    // ── trace_to_layout ───────────────────────────────────────────

    #[test]
    fn trace_to_layout_empty() {
        let term = Terminal::new(80);
        let layout = trace_to_layout(&[], "ls", 0, &term);
        // Should produce a layout without panicking
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
    }

    #[test]
    fn trace_to_layout_with_default_ask() {
        let term = Terminal::new(80);
        let entries = vec![TraceEntry::DefaultAsk {
            reason: "no rules".into(),
        }];
        let layout = trace_to_layout(&entries, "unknown", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        let output = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("No matching rule"));
    }

    #[test]
    fn trace_to_layout_with_segment_header() {
        let term = Terminal::new(80);
        let entries = vec![TraceEntry::SegmentHeader {
            command: "ls".into(),
            decision: may_i_core::Decision::Allow,
        }];
        let layout = trace_to_layout(&entries, "ls && echo done", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        let output = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("ls"));
    }

    #[test]
    fn write_trace_produces_output() {
        let term = Terminal::new(80);
        let entries = vec![TraceEntry::DefaultAsk {
            reason: "test".into(),
        }];
        let mut buf = Vec::new();
        write_trace(&mut buf, &entries, "cmd", "  ", &term);
        assert!(!buf.is_empty());
    }

    // ── shorten_home ──────────────────────────────────────────────

    #[test]
    fn shorten_home_replaces_home_prefix() {
        if let Ok(home) = std::env::var("HOME") {
            let path = std::path::PathBuf::from(&home).join("foo/bar");
            assert_eq!(shorten_home(&path), "~/foo/bar");
        }
    }

    #[test]
    fn shorten_home_preserves_non_home_path() {
        let path = std::path::Path::new("/tmp/other");
        assert_eq!(shorten_home(path), "/tmp/other");
    }

    // ── Property tests ────────────────────────────────────────────

    proptest! {
        #[test]
        fn render_observed_value_always_quoted(s in "[ -~]{0,100}") {
            let rendered = render_observed_value(&s);
            prop_assert!(rendered.starts_with('"'));
            prop_assert!(rendered.ends_with('"'));
            prop_assert!(rendered.len() <= 42); // max 40 content + quotes
        }

        #[test]
        fn truncate_list_preserves_short_lists(items in prop::collection::vec("[a-z]{1,5}", 1..4usize)) {
            let result = truncate_list(&items, 4);
            for item in &items {
                prop_assert!(result.contains(item.as_str()));
            }
        }

        #[test]
        fn find_line_returns_valid_index(
            lines in prop::collection::vec("[a-z ]{1,20}", 1..10usize),
        ) {
            if let Some(target) = lines.first() {
                let mut from = 0;
                if let Some(idx) = find_line(&lines, target, &mut from) {
                    prop_assert!(idx < lines.len());
                }
            }
        }

        #[test]
        fn node_text_atom_roundtrip(s in "[a-z]{1,10}") {
            let doc = atom(&s);
            prop_assert_eq!(node_text(&doc), s);
        }

        #[test]
        fn colorize_right_never_panics(s in ".{0,50}") {
            let _ = colorize_right(&s);
        }

        #[test]
        fn colorize_decision_keyword_never_panics(s in ".{0,20}") {
            let _ = colorize_decision_keyword(&s);
        }
    }

    // ── facts_rows / command_row ──────────────────────────────────

    #[test]
    fn facts_rows_creates_breakable_row() {
        let facts = vec![
            (":env".to_string(), "prod".to_string()),
            (":region".to_string(), "us-east".to_string()),
        ];
        let rows = facts_rows(&facts);
        assert_eq!(rows.len(), 1);
        let stripped = strip_ansi(&rows[0].left);
        assert_eq!(stripped, "facts");
    }

    #[test]
    fn command_row_creates_row() {
        let geom = ColumnGeometry { left_width: 40 };
        let rows = command_row("git push", &geom);
        assert_eq!(rows.len(), 1);
        let stripped = strip_ansi(&rows[0].left);
        assert_eq!(stripped, "command");
    }

    // ── render_annotated_rule ─────────────────────────────────────

    #[test]
    fn render_annotated_rule_simple() {
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(5),
            },
            vec![
                atom("rule"),
                atom_ann("git", Ann::CommandMatch { matched: true }),
                atom_ann(
                    ":allow",
                    Ann::EffectDecision {
                        decision: may_i_core::Decision::Allow,
                        reason: None,
                    },
                ),
            ],
        );
        let geom = ColumnGeometry { left_width: 40 };
        let rows = render_annotated_rule(&doc, Some(5), &geom);
        assert!(!rows.is_empty());
    }

    #[test]
    fn render_annotated_rule_with_overflow() {
        // A doc where annotations can't be placed on any line
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(1),
            },
            vec![atom("rule")],
        );
        let geom = ColumnGeometry { left_width: 40 };
        let rows = render_annotated_rule(&doc, Some(1), &geom);
        assert!(!rows.is_empty());
    }

    // ── collect_annotations for arg patterns ──────────────────────

    #[test]
    fn collect_annotations_anywhere_matched() {
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec!["\"rm\"".into()],
                arg_set: vec!["rm".into(), "ls".into()],
                matched: true,
            },
            vec![atom("anywhere"), atom("\"rm\"")],
        );
        let annotations = collect_annotations(&doc);
        assert!(!annotations.is_empty());
        assert!(annotations[0].1.contains("yes"));
    }

    #[test]
    fn collect_annotations_anywhere_not_matched() {
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec!["\"rm\"".into()],
                arg_set: vec!["ls".into()],
                matched: false,
            },
            vec![atom("anywhere"), atom("\"rm\"")],
        );
        let annotations = collect_annotations(&doc);
        assert!(!annotations.is_empty());
        assert!(annotations[0].1.contains("no"));
    }

    #[test]
    fn collect_annotations_forbidden_passed() {
        let inner = list_ann(
            Ann::ArgMatch {
                search_tokens: vec!["\"rm\"".into()],
                arg_set: vec!["ls".into()],
                matched: true,
            },
            vec![atom("anywhere"), atom("\"rm\"")],
        );
        let doc = list(vec![atom("not"), inner]);
        // forbidden wraps in (not (anywhere ...)), set ann on the (not) level
        let doc = Doc {
            ann: Some(Ann::ArgMatch {
                search_tokens: vec!["\"rm\"".into()],
                arg_set: vec!["ls".into()],
                matched: true,
            }),
            node: DocF::List(vec![atom("forbidden"), atom("\"rm\"")]),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let annotations = collect_annotations(&doc);
        assert!(!annotations.is_empty());
        assert!(annotations[0].1.contains("no")); // forbidden passed = no forbidden found
    }

    #[test]
    fn collect_annotations_forbidden_failed() {
        let doc = Doc {
            ann: Some(Ann::ArgMatch {
                search_tokens: vec!["\"rm\"".into()],
                arg_set: vec!["rm".into()],
                matched: false,
            }),
            node: DocF::List(vec![atom("forbidden"), atom("\"rm\"")]),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let annotations = collect_annotations(&doc);
        assert!(!annotations.is_empty());
        assert!(annotations[0].1.contains("yes"));
    }

    #[test]
    fn collect_annotations_positional_pattern() {
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec![],
                arg_set: vec!["push".into()],
                matched: true,
            },
            vec![atom("positional"), atom("\"push\"")],
        );
        let annotations = collect_annotations(&doc);
        assert!(!annotations.is_empty());
    }

    // ── quote_arg_set ─────────────────────────────────────────────

    #[test]
    fn quote_arg_set_short() {
        let items = vec!["a".into(), "b".into()];
        assert_eq!(quote_arg_set(&items), "\"a\", \"b\"");
    }

    #[test]
    fn quote_arg_set_truncates() {
        let items: Vec<String> = (0..6).map(|i| format!("item{i}")).collect();
        let result = quote_arg_set(&items);
        assert!(result.contains("…"));
    }

    // ── trace_to_layout with Rule entry ───────────────────────────

    #[test]
    fn trace_to_layout_with_rule() {
        let term = Terminal::new(80);
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(3),
            },
            vec![
                atom("rule"),
                atom_ann("git", Ann::CommandMatch { matched: true }),
                atom_ann(
                    ":allow",
                    Ann::EffectDecision {
                        decision: may_i_core::Decision::Allow,
                        reason: Some("ok".into()),
                    },
                ),
            ],
        );
        let entries = vec![TraceEntry::Rule {
            doc,
            line: Some(3),
            pre_migration_doc: None,
            facts: vec![(":env".into(), "prod".into())],
            inner_command: None,
        }];
        let layout = trace_to_layout(&entries, "git push", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        let output = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("command"));
        assert!(stripped.contains("git push"));
    }

    #[test]
    fn trace_to_layout_with_inner_command() {
        let term = Terminal::new(80);
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(1),
            },
            vec![atom("rule"), atom("rm")],
        );
        let entries = vec![
            TraceEntry::Rule {
                doc: doc.clone(),
                line: Some(1),
                pre_migration_doc: None,
                facts: vec![],
                inner_command: None,
            },
            TraceEntry::Rule {
                doc,
                line: Some(2),
                pre_migration_doc: None,
                facts: vec![],
                inner_command: Some("rm -rf".into()),
            },
        ];
        let layout = trace_to_layout(&entries, "sudo rm -rf", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        let output = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("rm -rf"));
    }

    #[test]
    fn trace_to_layout_consecutive_rules_get_separator() {
        let term = Terminal::new(80);
        let make_rule = |cmd: &str| TraceEntry::Rule {
            doc: list_ann(
                Ann::RuleMatch {
                    matched: false,
                    line: None,
                },
                vec![atom("rule"), atom(cmd)],
            ),
            line: None,
            pre_migration_doc: None,
            facts: vec![],
            inner_command: None,
        };
        let entries = vec![make_rule("git"), make_rule("hg")];
        let layout = trace_to_layout(&entries, "ls", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        assert!(!buf.is_empty());
    }

    #[test]
    fn trace_to_layout_skips_duplicate_facts() {
        let term = Terminal::new(80);
        let facts = vec![(":env".into(), "prod".into())];
        let make_rule = || TraceEntry::Rule {
            doc: list_ann(
                Ann::RuleMatch {
                    matched: false,
                    line: None,
                },
                vec![atom("rule"), atom("cmd")],
            ),
            line: None,
            pre_migration_doc: None,
            facts: facts.clone(),
            inner_command: None,
        };
        let entries = vec![make_rule(), make_rule()];
        let layout = trace_to_layout(&entries, "cmd", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        let output = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&output);
        // "facts" label should appear only once
        assert_eq!(
            stripped.matches("facts").count(),
            1,
            "facts should appear once: {stripped}"
        );
    }

    // ── collect_pattern_comparisons ───────────────────────────────

    #[test]
    fn collect_pattern_comparisons_literal() {
        let pattern_doc = atom("\"push\"");
        let mut out = Vec::new();
        collect_pattern_comparisons(&pattern_doc, "push", &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].1.contains("yes"));
    }

    #[test]
    fn collect_pattern_comparisons_or() {
        let pattern_doc = list(vec![atom("or"), atom("\"a\""), atom("\"b\"")]);
        let mut out = Vec::new();
        collect_pattern_comparisons(&pattern_doc, "a", &mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn collect_pattern_comparisons_quantifier() {
        let pattern_doc = list(vec![atom("?"), atom("\"opt\"")]);
        let mut out = Vec::new();
        collect_pattern_comparisons(&pattern_doc, "opt", &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].1.contains("yes"));
    }

    // ── segment_header_layout ─────────────────────────────────────

    #[test]
    fn segment_header_layout_variants() {
        use may_i_core::Decision;
        for decision in [Decision::Allow, Decision::Ask, Decision::Deny] {
            let layout = segment_header_layout("cmd", decision);
            let term = Terminal::new(80);
            let mut buf = Vec::new();
            write_layout(&mut buf, &layout, &term);
            assert!(!buf.is_empty());
        }
    }
}
