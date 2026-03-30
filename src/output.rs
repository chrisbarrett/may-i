// Shared display helpers for trace output.
//
// Recovered from v0.0.3 and adapted for the new Ann enum and EvalFold-based
// trace system.

use std::io::Write;

use colored::Colorize;
use may_i_core::doc::{Doc, DocF, LayoutHint};
use may_i_pp::{Format, colorize_atom, pretty, visible_len};

use crate::annotation::{Ann, TraceEntry};

// ── Layout geometry ────────────────────────────────────────────────

const MIN_TERM_WIDTH: usize = 40;
const DIVIDER: &str = "│";

fn term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
        .unwrap_or(80)
}

struct Layout {
    left_width: usize,
}

fn detect_layout() -> Layout {
    let usable = term_width().saturating_sub(2).max(MIN_TERM_WIDTH);
    let left_width = usable / 2;
    Layout { left_width }
}

// ── Document types ─────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
pub enum Align {
    #[default]
    Left,
    Right,
}

pub struct Cell {
    pub content: String,
    pub visible_width: usize,
    pub align: Align,
    pub precolored: bool,
}

impl Cell {
    pub fn new(content: impl Into<String>, visible_width: usize) -> Self {
        Self {
            content: content.into(),
            visible_width,
            align: Align::Left,
            precolored: false,
        }
    }

    fn is_elision(&self) -> bool {
        self.visible_width == 1 && self.content.contains('…')
    }
}

pub struct Row {
    pub left: Cell,
    pub right: Cell,
}

impl Row {
    pub fn trace(left: impl Into<String>, left_visible: usize, right: impl Into<String>) -> Self {
        Self {
            left: Cell::new(left, left_visible),
            right: Cell::new(right, 0),
        }
    }

    pub fn kv(key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let len = key.len();
        Self {
            left: Cell::new(key, len),
            right: Cell {
                content: value.into(),
                visible_width: 0,
                align: Align::Left,
                precolored: true,
            },
        }
    }
}

pub enum Element {
    Blank,
    Separator { label: Option<(String, usize)> },
    Table(Vec<Row>),
}

// ── Rendering ──────────────────────────────────────────────────────

pub fn render_elements(indent: &str, elements: &[Element]) {
    write_elements(&mut std::io::stdout(), indent, elements);
}

pub fn write_elements(w: &mut impl Write, indent: &str, elements: &[Element]) {
    for element in elements {
        match element {
            Element::Blank => {
                let _ = writeln!(w);
            }
            Element::Separator { label } => {
                write_separator(w, indent, label.as_ref().map(|(s, w)| (s.as_str(), *w)));
            }
            Element::Table(rows) => {
                let divider_col = compute_divider_col(rows);
                for row in rows {
                    write_row(w, indent, row, divider_col);
                }
            }
        }
    }
}

fn compute_divider_col(rows: &[Row]) -> usize {
    let max_left = rows
        .iter()
        .filter(|r| !r.left.is_elision() && matches!(r.left.align, Align::Left))
        .map(|r| r.left.visible_width)
        .max()
        .unwrap_or(0);
    max_left + 1
}

fn write_row(w: &mut impl Write, indent: &str, row: &Row, divider_col: usize) {
    if row.left.content.is_empty() && row.right.content.is_empty() {
        return;
    }

    let gap = divider_col.saturating_sub(row.left.visible_width);

    let (lead, trail) = match row.left.align {
        Align::Right => (gap.saturating_sub(1), 1),
        Align::Left => (0, gap),
    };

    let right = if row.right.content.is_empty() {
        String::new()
    } else if row.right.precolored {
        format!(" {}", row.right.content)
    } else {
        format!(" {}", colorize_right(&row.right.content))
    };

    let _ = writeln!(
        w,
        "{indent}{:lead$}{}{:trail$}{}{}",
        "",
        row.left.content,
        "",
        DIVIDER.dimmed(),
        right,
    );
}

// ── Separator ──────────────────────────────────────────────────────

pub fn print_separator(indent: &str, label: Option<(&str, usize)>) {
    write_separator(&mut std::io::stdout(), indent, label);
}

pub fn write_separator(w: &mut impl Write, indent: &str, label: Option<(&str, usize)>) {
    let usable = term_width().saturating_sub(indent.len());

    match label {
        Some((colored_label, label_width)) => {
            let prefix = "─── ";
            let mid = " ";
            let used = visible_len(prefix) + label_width + visible_len(mid);
            let remaining = usable.saturating_sub(used);
            let suffix = "─".repeat(remaining);
            let _ = writeln!(
                w,
                "{indent}{}{}{}{}",
                prefix.dimmed(),
                colored_label,
                mid.dimmed(),
                suffix.dimmed(),
            );
        }
        None => {
            let rule = "─".repeat(usable);
            let _ = writeln!(w, "{indent}{}", rule.dimmed());
        }
    }
}

// ── Trace rendering ────────────────────────────────────────────────

pub fn print_trace(entries: &[TraceEntry], indent: &str) {
    write_trace(&mut std::io::stdout(), entries, indent);
}

pub fn write_trace(w: &mut impl Write, entries: &[TraceEntry], indent: &str) {
    let layout = detect_layout();
    let mut elements: Vec<Element> = Vec::new();
    let mut first = true;

    for entry in entries {
        match entry {
            TraceEntry::SegmentHeader { command, decision } => {
                if !first {
                    elements.push(Element::Blank);
                    elements.push(Element::Blank);
                }
                elements.push(segment_header_element(command, *decision));
            }
            TraceEntry::Rule {
                doc,
                line,
                pre_migration_doc: _,
            } => {
                if !first {
                    elements.push(Element::Blank);
                }
                let rows = render_annotated_rule(doc, *line, &layout);
                if !rows.is_empty() {
                    elements.push(Element::Table(rows));
                }
            }
            TraceEntry::DefaultAsk { .. } => {
                let label = "No matching rule".italic().yellow().to_string();
                let label_visible = "No matching rule".len();
                let mut row = Row::trace(label, label_visible, "→ :ask (default)");
                row.left.align = Align::Right;
                if let Some(Element::Table(rows)) = elements.last_mut() {
                    rows.push(row);
                } else {
                    elements.push(Element::Table(vec![row]));
                }
            }
        }
        first = false;
    }

    write_elements(w, indent, &elements);
}

fn segment_header_element(command: &str, decision: may_i_core::Decision) -> Element {
    use may_i_core::Decision;
    let icon = match decision {
        Decision::Allow => "✓".green().bold().to_string(),
        Decision::Ask => "?".yellow().bold().to_string(),
        Decision::Deny => "✗".red().bold().to_string(),
    };
    let label = format!("{icon} {}", command.bold());
    let label_width = 2 + command.len();
    Element::Separator {
        label: Some((label, label_width)),
    }
}

// ── Annotated Doc renderer ─────────────────────────────────────────

fn render_annotated_rule(doc: &Doc<Option<Ann>>, line: Option<usize>, layout: &Layout) -> Vec<Row> {
    let doc = dim_unevaluated(truncate_unevaluated(&truncate_matched_anywhere(doc), 2));
    let fmt = Format {
        width: layout.left_width,
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

    let mut rows: Vec<Row> = rendered_lines
        .iter()
        .enumerate()
        .map(|(i, sline)| {
            Row::trace(
                sline.to_string(),
                visible_len(sline),
                line_annotations[i].clone(),
            )
        })
        .collect();

    for ann in &overflow {
        rows.push(Row::trace("", 0, ann.clone()));
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
                    Some((needle, format!("{observed_str} -> {arrow}")))
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

pub fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch == 'm' {
                in_escape = false;
            }
        } else if ch == '\x1b' {
            in_escape = true;
        } else {
            result.push(ch);
        }
    }
    result
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
    dim_unevaluated_inner(doc).0
}

fn dim_unevaluated_inner(doc: Doc<Option<Ann>>) -> (Doc<Option<Ann>>, usize) {
    let self_score = usize::from(doc.ann.is_some());
    match doc.node {
        DocF::Atom(_) => (doc, self_score),
        DocF::List(children) => {
            let mut total = self_score;
            let children: Vec<_> = children
                .into_iter()
                .map(|c| {
                    let (c, n) = dim_unevaluated_inner(c);
                    total += n;
                    c
                })
                .collect();
            let dimmed = doc.dimmed || total == 0;
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
                    let (c, n) = dim_unevaluated_inner(c);
                    total += n;
                    c
                })
                .collect();
            let dimmed = doc.dimmed || total == 0;
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
    } else if s.contains("->") {
        // Fact query annotations use "->" instead of "→"
        if let Some(arrow_pos) = s.find("->") {
            let before = &s[..arrow_pos];
            let after = s[arrow_pos + 2..].trim();
            let colored_result = match after {
                "yes" => "yes".green().bold().to_string(),
                "no" => "no".yellow().to_string(),
                other => other.to_string(),
            };
            format!("{}{} {colored_result}", before.dimmed(), "->".dimmed())
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
        Ann::Combinator { result_is_nil } => serde_json::json!({
            "type": "combinator",
            "result_is_nil": result_is_nil,
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
