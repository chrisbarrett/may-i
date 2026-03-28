// Shared display helpers for trace output.
//
// Recovered from v0.0.3 and adapted for the new Ann enum and EvalFold-based
// trace system.

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
    for element in elements {
        match element {
            Element::Blank => println!(),
            Element::Separator { label } => {
                print_separator(indent, label.as_ref().map(|(s, w)| (s.as_str(), *w)));
            }
            Element::Table(rows) => {
                let divider_col = compute_divider_col(rows);
                for row in rows {
                    print_row(indent, row, divider_col);
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

fn print_row(indent: &str, row: &Row, divider_col: usize) {
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

    println!(
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
    let usable = term_width().saturating_sub(indent.len());

    match label {
        Some((colored_label, label_width)) => {
            let prefix = "─── ";
            let mid = " ";
            let used = visible_len(prefix) + label_width + visible_len(mid);
            let remaining = usable.saturating_sub(used);
            let suffix = "─".repeat(remaining);
            println!(
                "{indent}{}{}{}{}",
                prefix.dimmed(),
                colored_label,
                mid.dimmed(),
                suffix.dimmed(),
            );
        }
        None => {
            let rule = "─".repeat(usable);
            println!("{indent}{}", rule.dimmed());
        }
    }
}

// ── Trace rendering ────────────────────────────────────────────────

pub fn print_trace(entries: &[TraceEntry], indent: &str) {
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
            TraceEntry::Rule { doc, line } => {
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

    render_elements(indent, &elements);
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
    let doc = dim_unevaluated(truncate_unevaluated(doc, 2));
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

    // Place outcome annotation on the "(effect" line if possible.
    if let Some(out) = outcome
        && matched
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
    if let Some(ann) = &doc.ann
        && let Some(pair) = format_annotation(doc, ann)
    {
        out.push(pair);
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
        Ann::CommandMatch { .. } => None,
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

        Ann::ArgMatch {
            search_tokens,
            arg_set,
            matched,
        } => {
            let needle = node_text(doc);
            if !search_tokens.is_empty() {
                // Anywhere-style: show set membership
                let pattern = search_tokens.join(", ");
                let truncated = truncate_list(arg_set, 4);
                let arrow = if *matched { "→ yes" } else { "→ no" };
                Some((needle, format!("{pattern} ∈ {{{truncated}}} {arrow}")))
            } else {
                // Predicate arg match — simple verdict
                Some((needle, verdict(*matched)))
            }
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

fn strip_ansi(s: &str) -> String {
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

fn truncate_unevaluated(doc: &Doc<Option<Ann>>, keep: usize) -> Doc<Option<Ann>> {
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
            let is_control_flow =
                matches!(head, Some("cond" | "and" | "or" | "if" | "when" | "unless"));
            if is_control_flow && children.len() > 1 {
                let tail_start = children[1..]
                    .iter()
                    .rposition(has_any_annotation)
                    .map(|i| i + 2)
                    .unwrap_or(1);
                let tail_len = children.len() - tail_start;
                if tail_len >= 1 {
                    let ellipsis = Doc {
                        ann: None,
                        node: DocF::Atom("…".into()),
                        layout: LayoutHint::Auto,
                        dimmed: true,
                    };
                    let mut truncated: Vec<_> = children[..tail_start].to_vec();
                    truncated.push(ellipsis);
                    return Doc {
                        ann: doc.ann.clone(),
                        node: DocF::List(truncated),
                        layout: doc.layout,
                        dimmed: doc.dimmed,
                    };
                }
            }
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

fn has_any_annotation(doc: &Doc<Option<Ann>>) -> bool {
    if doc.ann.is_some() {
        return true;
    }
    if let DocF::List(children) | DocF::Vector(children) = &doc.node {
        children.iter().any(has_any_annotation)
    } else {
        false
    }
}

fn has_any_visible_annotation(doc: &Doc<Option<Ann>>) -> bool {
    if let Some(ann) = &doc.ann
        && !matches!(ann, Ann::CommandMatch { .. } | Ann::RuleMatch { .. })
    {
        return true;
    }
    if let DocF::List(children) | DocF::Vector(children) = &doc.node {
        children.iter().any(has_any_visible_annotation)
    } else {
        false
    }
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
            TraceEntry::Rule { doc, line } => {
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
