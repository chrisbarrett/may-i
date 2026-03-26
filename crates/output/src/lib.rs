// Shared display helpers for trace output.

use colored::Colorize;
use may_i_core::{Doc, DocF, EvalAnn, LayoutHint, TraceEntry};
use may_i_pp::{Format, colorize_atom, pretty, visible_len};

// ── Layout geometry ────────────────────────────────────────────────

/// Minimum usable terminal width before we stop trying to fit two columns.
const MIN_TERM_WIDTH: usize = 40;

/// Unicode box-drawing character used as a column divider.
const DIVIDER: &str = "│";

/// Detect the terminal width from `$COLUMNS`, `terminal_size`, or default 80.
fn term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
        .unwrap_or(80)
}

/// Layout parameters derived from the terminal width.
struct Layout {
    /// Maximum visible width for the left (s-expression) column.
    left_width: usize,
}

fn detect_layout() -> Layout {
    let usable = term_width().saturating_sub(2).max(MIN_TERM_WIDTH);
    let left_width = usable / 2;
    Layout { left_width }
}

// ── Document types ─────────────────────────────────────────────────

/// Horizontal alignment for a cell within its column.
#[derive(Clone, Copy, Default)]
pub enum Align {
    #[default]
    Left,
    Right,
}

/// A single cell in a table row.
pub struct Cell {
    /// Rendered content (may contain ANSI codes).
    pub content: String,
    /// Visible width of content (excluding ANSI).
    pub visible_width: usize,
    /// How to align this cell within its column.
    pub align: Align,
    /// If true, content is already colorized (skip auto-colorization).
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

/// A row in a two-column table with a vertical bar divider.
pub struct Row {
    pub left: Cell,
    pub right: Cell,
}

impl Row {
    /// Create a row with auto-colorized right column (trace style).
    pub fn trace(left: impl Into<String>, left_visible: usize, right: impl Into<String>) -> Self {
        Self {
            left: Cell::new(left, left_visible),
            right: Cell::new(right, 0),
        }
    }

    /// Create a row with a pre-colorized right column (KV style).
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

/// A rendered document element.
pub enum Element {
    /// Empty line.
    Blank,
    /// Full-width horizontal rule with optional label.
    Separator { label: Option<(String, usize)> },
    /// A group of rows sharing a divider column.
    Table(Vec<Row>),
}

// ── Rendering ──────────────────────────────────────────────────────

/// Render elements as a string (for builder pattern).
pub fn render_elements_str(indent: &str, elements: &[Element]) -> String {
    let mut output = String::new();
    for element in elements {
        match element {
            Element::Blank => output.push('\n'),
            Element::Separator { label } => {
                output.push_str(&render_separator_str(
                    indent,
                    label.as_ref().map(|(s, w)| (s.as_str(), *w)),
                ));
            }
            Element::Table(rows) => {
                let divider_col = compute_divider_col(rows);
                for row in rows {
                    output.push_str(&format_row_str(indent, row, divider_col));
                    output.push('\n');
                }
            }
        }
    }
    output
}

fn format_row_str(indent: &str, row: &Row, divider_col: usize) -> String {
    if row.left.content.is_empty() && row.right.content.is_empty() {
        return String::new();
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

    format!(
        "{indent}{:lead$}{}{:trail$}{}{}",
        "",
        row.left.content,
        "",
        DIVIDER.dimmed(),
        right,
    )
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

// ── Separator ──────────────────────────────────────────────────────

/// Render a separator as a string, optionally embedding a label.
pub fn render_separator_str(indent: &str, label: Option<(&str, usize)>) -> String {
    let usable = term_width().saturating_sub(indent.len());

    match label {
        Some((colored_label, label_width)) => {
            let prefix = "─── ";
            let mid = " ";
            let used = visible_len(prefix) + label_width + visible_len(mid);
            let remaining = usable.saturating_sub(used);
            let suffix = "─".repeat(remaining);
            format!(
                "{indent}{}{}{}{}\n",
                prefix.dimmed(),
                colored_label,
                mid.dimmed(),
                suffix.dimmed(),
            )
        }
        None => {
            let rule = "─".repeat(usable);
            format!("{indent}{}\n", rule.dimmed())
        }
    }
}

// ── Trace rendering ────────────────────────────────────────────────

/// Format a trace as a string (for builder pattern).
pub fn format_trace(entries: &[TraceEntry], indent: &str) -> String {
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
                // Append to the previous table if possible, else new table.
                if let Some(Element::Table(rows)) = elements.last_mut() {
                    rows.push(row);
                } else {
                    elements.push(Element::Table(vec![row]));
                }
            }
        }
        first = false;
    }

    render_elements_str(indent, &elements)
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

/// Render an annotated rule Doc into two-column rows.
fn render_annotated_rule(
    doc: &Doc<Option<EvalAnn>>,
    line: Option<usize>,
    layout: &Layout,
) -> Vec<Row> {
    let doc = dim_unevaluated(truncate_unevaluated(doc, 2));
    let fmt = Format {
        width: layout.left_width,
        color: true,
        line_number: line,
    };
    let rendered = pretty(&doc, 0, &fmt);

    // Collect annotations in tree-walk order.
    let annotations = collect_annotations(&doc);

    // Find the outcome (RuleEffect on the top-level node).
    let outcome = extract_outcome(&doc);
    let matched = has_args_match(&doc);

    let rendered_lines: Vec<&str> = rendered.lines().collect();
    let stripped_lines: Vec<String> = rendered_lines.iter().map(|l| strip_ansi(l)).collect();

    // Forward-scan: match each annotation to a rendered line.
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

    // Build rows from rendered lines with aligned annotations.
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

    // Overflow annotations.
    for ann in &overflow {
        rows.push(Row::trace("", 0, ann.clone()));
    }

    rows
}

/// Collect (search_needle, right_column_text) pairs from annotated Doc nodes.
fn collect_annotations(doc: &Doc<Option<EvalAnn>>) -> Vec<(String, String)> {
    let mut result = Vec::new();
    collect_annotations_inner(doc, &mut result);
    result
}

fn collect_annotations_inner(doc: &Doc<Option<EvalAnn>>, out: &mut Vec<(String, String)>) {
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
/// Returns None for annotations that don't produce right-column output.
fn format_annotation(doc: &Doc<Option<EvalAnn>>, ann: &EvalAnn) -> Option<(String, String)> {
    match ann {
        EvalAnn::CommandMatch(_) => None,
        EvalAnn::ContextResult(_) => None,
        EvalAnn::ArgsResult(_) => None,
        EvalAnn::RuleEffect { .. } => None, // handled as outcome
        EvalAnn::DefaultAsk => None,
        EvalAnn::ContextHasPresence { matched, .. } => Some((node_text(doc), verdict(*matched))),
        EvalAnn::ContextHasExact {
            actual,
            matched,
            search_needle,
            ..
        } => Some((
            search_needle.clone(),
            if *matched {
                "yes".into()
            } else if let Some(actual) = actual {
                format!("{} -> no", render_observed_value(actual))
            } else {
                "no".into()
            },
        )),
        EvalAnn::ContextHasPattern {
            actual,
            matched,
            search_needle,
            ..
        } => Some((
            search_needle.clone(),
            if let Some(actual) = actual {
                format!(
                    "{} -> {}",
                    render_observed_value(actual),
                    if *matched { "yes" } else { "no" }
                )
            } else {
                "no".into()
            },
        )),

        EvalAnn::ExprVsArg { arg, matched } => {
            let needle = node_text(doc);
            let op = if is_regex_node(doc) { "~" } else { "=" };
            let arrow = if *matched { "→ yes" } else { "→ no" };
            let right = format!("{arg} {op} {needle} {arrow}");
            Some((needle, right))
        }
        EvalAnn::Quantifier { count, matched } => {
            let needle = node_text(doc);
            if *matched {
                Some((needle, format!("{count} matched → yes")))
            } else {
                Some((needle, "→ no".into()))
            }
        }
        EvalAnn::Missing => Some((node_text(doc), "→ missing".into())),
        EvalAnn::Anywhere { args, matched } => {
            let pattern = node_text(doc);
            let truncated = truncate_list(args, 4);
            let arrow = if *matched { "→ yes" } else { "→ no" };
            Some((
                pattern.clone(),
                format!("{pattern} ∈ {{{truncated}}} {arrow}"),
            ))
        }
        EvalAnn::CondBranch { decision } => {
            let needle = node_text(doc);
            Some((needle, format!("→ :{decision}")))
        }
        EvalAnn::CondElse { decision } => Some(("else".into(), format!("→ :{decision}"))),
        EvalAnn::ExactArgs {
            patterns,
            args,
            matched,
        } => {
            let needle = node_text(doc);
            // Find first mismatch; ellipsize remaining elements in both vectors.
            let mismatch = patterns.iter().zip(args.iter()).position(|(p, a)| p != a);
            let (show_pats, show_args) = match mismatch {
                Some(i) => (ellipsize_after(patterns, i), ellipsize_after(args, i)),
                None => (
                    format!("[{}]", patterns.join(", ")),
                    format!("[{}]", args.join(", ")),
                ),
            };
            let arrow = if *matched { "→ yes" } else { "→ no" };
            Some((needle, format!("{show_args} = {show_pats} {arrow}")))
        }
        EvalAnn::ExactRemainder { count } => Some((String::new(), format!("{count} extra args"))),
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

/// Get the plain text of a Doc node (for search needle matching).
fn node_text(doc: &Doc<Option<EvalAnn>>) -> String {
    doc.fold(&|node, _ann: &Option<EvalAnn>| match node {
        DocF::Atom(s) => s,
        DocF::List(cs) => format!("({})", cs.join(" ")),
        DocF::Vector(cs) => format!("[{}]", cs.join(" ")),
    })
}

/// Check if a Doc node is a regex form like `(regex "...")`.
fn is_regex_node(doc: &Doc<Option<EvalAnn>>) -> bool {
    doc.head_atom() == Some("regex")
}

/// Extract the rule-level outcome annotation.
fn extract_outcome(doc: &Doc<Option<EvalAnn>>) -> Option<String> {
    match &doc.ann {
        Some(EvalAnn::RuleEffect { decision, reason }) => Some(match reason {
            Some(r) => format!("→ :{decision} \"{r}\""),
            None => format!("→ :{decision}"),
        }),
        _ => None,
    }
}

/// Check if the rule's args matched (look for ArgsResult(true) annotation).
fn has_args_match(doc: &Doc<Option<EvalAnn>>) -> bool {
    doc.fold(&|node, ann: &Option<EvalAnn>| {
        if matches!(ann, Some(EvalAnn::ArgsResult(true))) {
            return true;
        }
        // If no ArgsResult at all and there's a RuleEffect, it's a simple rule (always matched).
        if matches!(ann, Some(EvalAnn::RuleEffect { .. })) {
            return true;
        }
        match node {
            DocF::List(children) | DocF::Vector(children) => children.iter().any(|c| *c),
            DocF::Atom(_) => false,
        }
    })
}

/// Forward-scan stripped lines for a needle, advancing the search position.
fn find_line(stripped_lines: &[String], needle: &str, search_from: &mut usize) -> Option<usize> {
    // Try exact substring match.
    for (i, line) in stripped_lines.iter().enumerate().skip(*search_from) {
        if line.contains(needle) {
            *search_from = i + 1;
            return Some(i);
        }
    }
    // For long needles the pp may have broken across lines; try first token.
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

/// Strip ANSI SGR escape codes from a string.
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

/// Truncate unevaluated lists in an annotated Doc tree.
///
/// A list whose args (children after the head atom) all lack annotations
/// is considered unevaluated. If it has more than `keep + 2` children
/// (head + keep args + last), keep the first `keep` args, insert "…",
/// and keep the last arg.
fn truncate_unevaluated(doc: &Doc<Option<EvalAnn>>, keep: usize) -> Doc<Option<EvalAnn>> {
    match &doc.node {
        DocF::Atom(_) => doc.clone(),
        DocF::List(children) => {
            let children: Vec<Doc<Option<EvalAnn>>> = children
                .iter()
                .map(|c| truncate_unevaluated(c, keep))
                .collect();
            let head = children.first().and_then(|c| c.as_atom());
            let has_head = head.is_some();
            // Only truncate if the args (children after head) are all unevaluated.
            let args_unevaluated =
                has_head && children[1..].iter().all(|c| !has_any_visible_annotation(c));
            // Control-flow forms: collapse unevaluated trailing runs to …
            // Use has_any_annotation (not visible-only) so that nodes with
            // invisible annotations like CommandMatch are still considered
            // evaluated and preserved.
            let is_control_flow =
                matches!(head, Some("cond" | "and" | "or" | "if" | "when" | "unless"));
            if is_control_flow && children.len() > 1 {
                // Find where the unevaluated tail begins (after the head).
                let tail_start = children[1..]
                    .iter()
                    .rposition(has_any_annotation)
                    .map(|i| i + 2) // convert to index in children (offset by 1 for head, +1 for past)
                    .unwrap_or(1); // all unevaluated → tail starts right after head
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

/// Mark unevaluated subtrees as dimmed via a bottom-up eval count.
///
/// Each node's score = (1 if it carries an annotation, else 0) + sum of
/// children's scores. A list node with score 0 is entirely unevaluated
/// and gets `dimmed = true`. Atoms are never dimmed directly — they
/// inherit dimming from their parent list via the PP's format-flag stack.
fn dim_unevaluated(doc: Doc<Option<EvalAnn>>) -> Doc<Option<EvalAnn>> {
    dim_unevaluated_inner(doc).0
}

fn dim_unevaluated_inner(doc: Doc<Option<EvalAnn>>) -> (Doc<Option<EvalAnn>>, usize) {
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

/// True if a node or any descendant has any non-None annotation
/// (the evaluator visited it, regardless of visibility in the trace).
fn has_any_annotation(doc: &Doc<Option<EvalAnn>>) -> bool {
    if doc.ann.is_some() {
        return true;
    }
    if let DocF::List(children) | DocF::Vector(children) = &doc.node {
        children.iter().any(has_any_annotation)
    } else {
        false
    }
}

/// True if a node or any descendant has a visible annotation
/// (one that produces right-column output in the trace).
fn has_any_visible_annotation(doc: &Doc<Option<EvalAnn>>) -> bool {
    if let Some(ann) = &doc.ann
        && !matches!(
            ann,
            EvalAnn::CommandMatch(_)
                | EvalAnn::ContextResult(_)
                | EvalAnn::ArgsResult(_)
                | EvalAnn::RuleEffect { .. }
        )
    {
        return true;
    }
    if let DocF::List(children) | DocF::Vector(children) = &doc.node {
        children.iter().any(has_any_visible_annotation)
    } else {
        false
    }
}

/// Format a vector as `[a, b, …]`, keeping elements up to index `i`
/// and ellipsizing the rest if `i` is not the last element.
fn ellipsize_after(items: &[String], i: usize) -> String {
    if i >= items.len().saturating_sub(1) {
        format!("[{}]", items.join(", "))
    } else {
        let mut parts: Vec<&str> = items[..=i].iter().map(|s| s.as_str()).collect();
        parts.push("…");
        format!("[{}]", parts.join(", "))
    }
}

/// Truncate a list for display, keeping first few and last.
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

/// Colorize the right column (evaluation results).
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

    // Split at "→" to colorize the result portion.
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

/// Colorize an effect s-expression like (effect :ask "reason").
fn colorize_effect_sexpr(s: &str) -> String {
    s.replace(":allow", &":allow".green().bold().to_string())
        .replace(":ask", &":ask".yellow().bold().to_string())
        .replace(":deny", &":deny".red().bold().to_string())
}

// ── Path display ───────────────────────────────────────────────────

/// Replace the home directory prefix with `~` for display.
pub fn shorten_home(path: &std::path::Path) -> String {
    if let Ok(home) = std::env::var("HOME")
        && let Ok(rest) = path.strip_prefix(&home)
    {
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

// ── JSON output ────────────────────────────────────────────────────

/// Serialize trace entries for JSON output.
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

/// Collect annotations from a Doc tree for JSON serialization.
fn collect_json_annotations(doc: &Doc<Option<EvalAnn>>, out: &mut Vec<serde_json::Value>) {
    if let Some(ann) = &doc.ann {
        out.push(eval_ann_to_json(ann));
    }
    if let DocF::List(children) = &doc.node {
        for child in children {
            collect_json_annotations(child, out);
        }
    }
}

fn eval_ann_to_json(ann: &EvalAnn) -> serde_json::Value {
    match ann {
        EvalAnn::CommandMatch(matched) => serde_json::json!({
            "type": "command_match",
            "matched": matched,
        }),
        EvalAnn::ContextResult(matched) => serde_json::json!({
            "type": "context_result",
            "matched": matched,
        }),
        EvalAnn::ContextHasPresence {
            key,
            source,
            matched,
        } => serde_json::json!({
            "type": "context_has_presence",
            "key": key,
            "source": source,
            "matched": matched,
        }),
        EvalAnn::ContextHasExact {
            key,
            source,
            expected,
            actual,
            matched,
            reason,
            ..
        } => serde_json::json!({
            "type": "context_has_exact",
            "key": key,
            "source": source,
            "expected": expected,
            "actual": actual,
            "matched": matched,
            "reason": reason.as_ref().map(|reason| reason.as_str()),
        }),
        EvalAnn::ContextHasPattern {
            key,
            source,
            pattern_source,
            pattern,
            pattern_eval,
            actual,
            matched,
            reason,
            ..
        } => serde_json::json!({
            "type": "context_has_pattern",
            "key": key,
            "source": source,
            "pattern_source": pattern_source,
            "pattern": fact_pattern_to_json(pattern),
            "pattern_eval": fact_pattern_eval_to_json(pattern_eval),
            "actual": actual,
            "matched": matched,
            "reason": reason.as_ref().map(|reason| reason.as_str()),
        }),
        EvalAnn::ExprVsArg { arg, matched } => serde_json::json!({
            "type": "expr_vs_arg",
            "arg": arg,
            "matched": matched,
        }),
        EvalAnn::Quantifier { count, matched } => serde_json::json!({
            "type": "quantifier",
            "count": count,
            "matched": matched,
        }),
        EvalAnn::Missing => serde_json::json!({
            "type": "missing",
        }),
        EvalAnn::Anywhere { args, matched } => serde_json::json!({
            "type": "anywhere",
            "args": args,
            "matched": matched,
        }),
        EvalAnn::CondBranch { decision } => serde_json::json!({
            "type": "cond_branch",
            "decision": decision.to_string(),
        }),
        EvalAnn::CondElse { decision } => serde_json::json!({
            "type": "cond_else",
            "decision": decision.to_string(),
        }),
        EvalAnn::ExactArgs {
            patterns,
            args,
            matched,
        } => serde_json::json!({
            "type": "exact_args",
            "patterns": patterns,
            "args": args,
            "matched": matched,
        }),
        EvalAnn::ExactRemainder { count } => serde_json::json!({
            "type": "exact_remainder",
            "count": count,
        }),
        EvalAnn::ArgsResult(matched) => serde_json::json!({
            "type": "args_result",
            "matched": matched,
        }),
        EvalAnn::RuleEffect { decision, reason } => serde_json::json!({
            "type": "effect",
            "decision": decision.to_string(),
            "reason": reason,
        }),
        EvalAnn::DefaultAsk => serde_json::json!({
            "type": "default_ask",
        }),
    }
}

fn fact_pattern_to_json(pattern: &may_i_core::FactPattern) -> serde_json::Value {
    match pattern {
        may_i_core::FactPattern::Literal(value) => serde_json::json!({
            "type": "literal",
            "value": value,
        }),
        may_i_core::FactPattern::Wildcard => serde_json::json!({
            "type": "wildcard",
        }),
        may_i_core::FactPattern::Regex(regex) => serde_json::json!({
            "type": "regex",
            "pattern": regex.as_str(),
        }),
        may_i_core::FactPattern::And(children) => serde_json::json!({
            "type": "and",
            "children": children.iter().map(fact_pattern_to_json).collect::<Vec<_>>(),
        }),
        may_i_core::FactPattern::Or(children) => serde_json::json!({
            "type": "or",
            "children": children.iter().map(fact_pattern_to_json).collect::<Vec<_>>(),
        }),
        may_i_core::FactPattern::Not(child) => serde_json::json!({
            "type": "not",
            "child": fact_pattern_to_json(child),
        }),
    }
}

fn fact_pattern_eval_to_json(eval: &may_i_core::FactPatternEval) -> serde_json::Value {
    match eval {
        may_i_core::FactPatternEval::Literal {
            value,
            evaluated,
            matched,
        } => serde_json::json!({
            "type": "literal",
            "value": value,
            "evaluated": evaluated,
            "matched": matched,
        }),
        may_i_core::FactPatternEval::Wildcard { evaluated, matched } => serde_json::json!({
            "type": "wildcard",
            "evaluated": evaluated,
            "matched": matched,
        }),
        may_i_core::FactPatternEval::Regex {
            pattern,
            evaluated,
            matched,
        } => serde_json::json!({
            "type": "regex",
            "pattern": pattern,
            "evaluated": evaluated,
            "matched": matched,
        }),
        may_i_core::FactPatternEval::And {
            evaluated,
            matched,
            children,
        } => serde_json::json!({
            "type": "and",
            "evaluated": evaluated,
            "matched": matched,
            "children": children.iter().map(fact_pattern_eval_to_json).collect::<Vec<_>>(),
        }),
        may_i_core::FactPatternEval::Or {
            evaluated,
            matched,
            children,
        } => serde_json::json!({
            "type": "or",
            "evaluated": evaluated,
            "matched": matched,
            "children": children.iter().map(fact_pattern_eval_to_json).collect::<Vec<_>>(),
        }),
        may_i_core::FactPatternEval::Not {
            evaluated,
            matched,
            child,
        } => serde_json::json!({
            "type": "not",
            "evaluated": evaluated,
            "matched": matched,
            "child": fact_pattern_eval_to_json(child),
        }),
    }
}

/// Serialize a Doc tree to JSON.
fn doc_to_json(doc: &Doc<Option<EvalAnn>>) -> serde_json::Value {
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
    use may_i_core::{ContextFailureReason, FactPattern, FactPatternEval};

    fn atom_doc(text: &str) -> Doc<Option<EvalAnn>> {
        Doc {
            ann: None,
            node: DocF::Atom(text.into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    fn list_doc(children: Vec<Doc<Option<EvalAnn>>>) -> Doc<Option<EvalAnn>> {
        Doc {
            ann: None,
            node: DocF::List(children),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    #[test]
    fn format_presence_context_annotation_is_plain_verdict() {
        let doc = list_doc(vec![atom_doc("has"), atom_doc(":via/ssh")]);
        let ann = EvalAnn::ContextHasPresence {
            key: ":via/ssh".into(),
            source: "(has :via/ssh)".into(),
            matched: true,
        };
        assert_eq!(
            format_annotation(&doc, &ann),
            Some(("(has :via/ssh)".into(), "yes".into()))
        );
    }

    #[test]
    fn format_exact_context_annotation_reports_observed_value() {
        let doc = list_doc(vec![
            atom_doc("has"),
            atom_doc("[:opencode/agent \"build\"]"),
        ]);
        let ann = EvalAnn::ContextHasExact {
            key: ":opencode/agent".into(),
            source: "(has [:opencode/agent \"build\"])".into(),
            expected: "build".into(),
            actual: Some("plan".into()),
            matched: false,
            reason: Some(ContextFailureReason::ValueMismatch),
            search_needle: "\"build\"".into(),
        };
        assert_eq!(
            format_annotation(&doc, &ann),
            Some(("\"build\"".into(), "\"plan\" -> no".into()))
        );
    }

    #[test]
    fn format_pattern_context_annotation_reports_actual_value() {
        let doc = list_doc(vec![atom_doc("has"), atom_doc("[:ssh/host *]")]);
        let ann = EvalAnn::ContextHasPattern {
            key: ":ssh/host".into(),
            source: "(has [:ssh/host *])".into(),
            pattern_source: "*".into(),
            pattern: FactPattern::Wildcard,
            pattern_eval: FactPatternEval::Wildcard {
                evaluated: true,
                matched: true,
            },
            actual: Some("prod-1".into()),
            matched: true,
            reason: None,
            search_needle: "*".into(),
        };
        assert_eq!(
            format_annotation(&doc, &ann),
            Some(("*".into(), "\"prod-1\" -> yes".into()))
        );
    }

    #[test]
    fn trace_json_serializes_pattern_annotations_with_reason() {
        let doc = Doc {
            ann: Some(EvalAnn::ContextHasPattern {
                key: ":ssh/host".into(),
                source: "(has [:ssh/host (or \"prod-1\" \"prod-2\")])".into(),
                pattern_source: "(or \"prod-1\" \"prod-2\")".into(),
                pattern: FactPattern::Or(vec![
                    FactPattern::Literal("prod-1".into()),
                    FactPattern::Literal("prod-2".into()),
                ]),
                pattern_eval: FactPatternEval::Or {
                    evaluated: false,
                    matched: false,
                    children: vec![
                        FactPatternEval::Literal {
                            value: "prod-1".into(),
                            evaluated: false,
                            matched: false,
                        },
                        FactPatternEval::Literal {
                            value: "prod-2".into(),
                            evaluated: false,
                            matched: false,
                        },
                    ],
                },
                actual: None,
                matched: false,
                reason: Some(ContextFailureReason::PresentWithoutScalar),
                search_needle: ":ssh/host".into(),
            }),
            node: DocF::Atom("test".into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let json = trace_to_json(&[TraceEntry::Rule {
            doc: Box::new(doc),
            line: Some(1),
        }]);
        let annotations = json[0]["annotations"].as_array().unwrap();
        assert_eq!(annotations[0]["type"], "context_has_pattern");
        assert_eq!(annotations[0]["reason"], "present_without_scalar");
    }

    // Tests for Cell, Row, and Element constructors

    #[test]
    fn cell_new_creates_cell_with_defaults() {
        let cell = Cell::new("hello", 5);
        assert_eq!(cell.content, "hello");
        assert_eq!(cell.visible_width, 5);
        assert!(matches!(cell.align, Align::Left));
        assert!(!cell.precolored);
    }

    #[test]
    fn cell_is_elision_detects_ellipsis() {
        let elision = Cell {
            content: "…".to_string(),
            visible_width: 1,
            align: Align::Left,
            precolored: false,
        };
        assert!(elision.is_elision());

        let normal = Cell::new("hello", 5);
        assert!(!normal.is_elision());
    }

    #[test]
    fn row_trace_creates_row_with_auto_colorization() {
        let row = Row::trace("left", 4, "right");
        assert_eq!(row.left.content, "left");
        assert_eq!(row.left.visible_width, 4);
        assert!(!row.left.precolored);
        assert_eq!(row.right.content, "right");
        assert_eq!(row.right.visible_width, 0);
        assert!(!row.right.precolored);
    }

    #[test]
    fn row_kv_creates_row_with_precolored_value() {
        let row = Row::kv("key", "value");
        assert_eq!(row.left.content, "key");
        assert_eq!(row.left.visible_width, 3);
        assert!(!row.left.precolored);
        assert_eq!(row.right.content, "value");
        assert_eq!(row.right.visible_width, 0);
        assert!(row.right.precolored);
    }

    #[test]
    fn term_width_returns_reasonable_value() {
        let width = term_width();
        assert!(width >= 40);
        assert!(width <= 300);
    }

    #[test]
    fn detect_layout_creates_layout() {
        let layout = detect_layout();
        assert!(layout.left_width > 0);
    }

    #[test]
    fn render_separator_str_without_label() {
        let result = render_separator_str("", None);
        assert!(!result.is_empty());
        assert!(result.contains('\n'));
    }

    #[test]
    fn render_separator_str_with_label() {
        let label = "test".to_string();
        let result = render_separator_str("", Some(("test", 4)));
        assert!(!result.is_empty());
        assert!(result.contains(&label));
    }

    #[test]
    fn format_row_str_with_empty_cells() {
        let row = Row {
            left: Cell::new("", 0),
            right: Cell::new("", 0),
        };
        let result = format_row_str("", &row, 0);
        assert!(result.is_empty());
    }

    #[test]
    fn compute_divider_col_calculates_max() {
        let rows = vec![
            Row::trace("short", 5, "right"),
            Row::trace("longer text", 11, "right"),
        ];
        let col = compute_divider_col(&rows);
        assert_eq!(col, 12);
    }

    #[test]
    fn render_elements_str_blank() {
        let elements = vec![Element::Blank];
        let result = render_elements_str("", &elements);
        assert_eq!(result, "\n");
    }

    #[test]
    fn colorize_decision_keyword_allow() {
        let result = colorize_decision_keyword(":allow");
        assert!(!result.is_empty());
    }

    #[test]
    fn colorize_decision_keyword_ask() {
        let result = colorize_decision_keyword(":ask");
        assert!(!result.is_empty());
    }

    #[test]
    fn colorize_decision_keyword_deny() {
        let result = colorize_decision_keyword(":deny");
        assert!(!result.is_empty());
    }

    #[test]
    fn colorize_decision_keyword_other() {
        let result = colorize_decision_keyword(":other");
        assert_eq!(result, ":other");
    }

    #[test]
    fn shorten_home_with_home_dir() {
        if let Ok(home) = std::env::var("HOME") {
            let path = std::path::Path::new(&home).join("test/path");
            let shortened = shorten_home(&path);
            assert!(shortened.starts_with("~/"));
        }
    }

    #[test]
    fn shorten_home_without_home_dir() {
        let path = std::path::Path::new("/usr/local/bin");
        let shortened = shorten_home(path);
        assert!(shortened.contains("/usr/local/bin"));
    }

    #[test]
    fn format_trace_empty_entries() {
        let entries: Vec<TraceEntry> = vec![];
        let result = format_trace(&entries, "");
        assert!(result.is_empty());
    }

    #[test]
    fn format_trace_with_segment_header() {
        let entries = vec![TraceEntry::SegmentHeader {
            command: "git push".to_string(),
            decision: may_i_core::Decision::Allow,
        }];
        let result = format_trace(&entries, "");
        assert!(result.contains("git push"));
    }

    #[test]
    fn format_trace_with_default_ask() {
        let entries = vec![TraceEntry::DefaultAsk {
            reason: "no matching rule".to_string(),
        }];
        let result = format_trace(&entries, "");
        assert!(result.contains("No matching rule") || result.contains(":ask"));
    }

    #[test]
    fn format_trace_with_indent() {
        let entries = vec![TraceEntry::SegmentHeader {
            command: "test".to_string(),
            decision: may_i_core::Decision::Allow,
        }];
        let result = format_trace(&entries, "  ");
        assert!(result.starts_with("  ") || result.contains("  "));
    }

    #[test]
    fn render_elements_str_with_separator() {
        let elements = vec![Element::Separator {
            label: Some(("test".to_string(), 4)),
        }];
        let result = render_elements_str("", &elements);
        assert!(!result.is_empty());
    }

    #[test]
    fn render_elements_str_with_table() {
        let rows = vec![Row::trace("left", 4, "right")];
        let elements = vec![Element::Table(rows)];
        let result = render_elements_str("", &elements);
        assert!(result.contains("left"));
        assert!(result.contains("right"));
    }

    #[test]
    fn trace_to_json_empty() {
        let entries: Vec<TraceEntry> = vec![];
        let json = trace_to_json(&entries);
        assert!(json.is_empty());
    }

    #[test]
    fn trace_to_json_with_segment_header() {
        let entries = vec![TraceEntry::SegmentHeader {
            command: "git push".to_string(),
            decision: may_i_core::Decision::Allow,
        }];
        let json = trace_to_json(&entries);
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["type"], "segment_header");
        assert_eq!(json[0]["command"], "git push");
    }

    #[test]
    fn trace_to_json_with_default_ask() {
        let entries = vec![TraceEntry::DefaultAsk {
            reason: "test reason".to_string(),
        }];
        let json = trace_to_json(&entries);
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["type"], "default_ask");
        assert_eq!(json[0]["reason"], "test reason");
    }

    #[test]
    fn trace_to_json_with_rule() {
        let doc = Doc {
            ann: None,
            node: DocF::Atom("test".into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let entries = vec![TraceEntry::Rule {
            doc: Box::new(doc),
            line: Some(42),
        }];
        let json = trace_to_json(&entries);
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["type"], "rule");
        assert_eq!(json[0]["line"], 42);
    }

    #[test]
    fn colorize_right_with_yes() {
        let result = colorize_right("test → yes");
        assert!(!result.is_empty());
    }

    #[test]
    fn colorize_right_with_no() {
        let result = colorize_right("test → no");
        assert!(!result.is_empty());
    }

    #[test]
    fn colorize_right_with_missing() {
        let result = colorize_right("test → missing");
        assert!(!result.is_empty());
    }

    #[test]
    fn colorize_right_with_allow_keyword() {
        let result = colorize_right("test → :allow");
        assert!(!result.is_empty());
    }

    #[test]
    fn colorize_right_with_ask_keyword() {
        let result = colorize_right("test → :ask");
        assert!(!result.is_empty());
    }

    #[test]
    fn colorize_right_with_deny_keyword() {
        let result = colorize_right("test → :deny");
        assert!(!result.is_empty());
    }

    #[test]
    fn colorize_right_without_arrow() {
        let result = colorize_right("just some text");
        assert!(!result.is_empty());
    }

    #[test]
    fn format_row_str_with_precolored() {
        let row = Row {
            left: Cell::new("key", 3),
            right: Cell {
                content: "value".to_string(),
                visible_width: 0,
                align: Align::Left,
                precolored: true,
            },
        };
        let result = format_row_str("", &row, 5);
        assert!(result.contains("key"));
        assert!(result.contains("value"));
    }

    #[test]
    fn format_row_str_right_aligned() {
        let mut row = Row::trace("label", 5, "content");
        row.left.align = Align::Right;
        let result = format_row_str("", &row, 10);
        assert!(!result.is_empty());
    }

    #[test]
    fn compute_divider_col_with_right_aligned() {
        let mut row1 = Row::trace("short", 5, "right");
        row1.left.align = Align::Right;
        let row2 = Row::trace("longer text", 11, "right");
        let rows = vec![row1, row2];
        let col = compute_divider_col(&rows);
        assert_eq!(col, 12);
    }

    #[test]
    fn compute_divider_col_with_elision() {
        let row = Row {
            left: Cell {
                content: "…".to_string(),
                visible_width: 1,
                align: Align::Left,
                precolored: false,
            },
            right: Cell::new("", 0),
        };
        let rows = vec![row];
        let col = compute_divider_col(&rows);
        assert_eq!(col, 1);
    }

    #[test]
    fn format_annotation_command_match_returns_none() {
        let doc = atom_doc("test");
        let ann = EvalAnn::CommandMatch(true);
        assert!(format_annotation(&doc, &ann).is_none());
    }

    #[test]
    fn format_annotation_context_result_returns_none() {
        let doc = atom_doc("test");
        let ann = EvalAnn::ContextResult(true);
        assert!(format_annotation(&doc, &ann).is_none());
    }

    #[test]
    fn format_annotation_args_result_returns_none() {
        let doc = atom_doc("test");
        let ann = EvalAnn::ArgsResult(true);
        assert!(format_annotation(&doc, &ann).is_none());
    }

    #[test]
    fn format_annotation_rule_effect_returns_none() {
        let doc = atom_doc("test");
        let ann = EvalAnn::RuleEffect {
            decision: may_i_core::Decision::Allow,
            reason: None,
        };
        assert!(format_annotation(&doc, &ann).is_none());
    }

    #[test]
    fn format_annotation_default_ask_returns_none() {
        let doc = atom_doc("test");
        let ann = EvalAnn::DefaultAsk;
        assert!(format_annotation(&doc, &ann).is_none());
    }

    #[test]
    fn format_annotation_expr_vs_arg() {
        let doc = list_doc(vec![atom_doc("regex"), atom_doc("pattern")]);
        let ann = EvalAnn::ExprVsArg {
            arg: "test".to_string(),
            matched: true,
        };
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
    }

    #[test]
    fn format_annotation_expr_vs_arg_not_regex() {
        let doc = list_doc(vec![atom_doc("="), atom_doc("value")]);
        let ann = EvalAnn::ExprVsArg {
            arg: "test".to_string(),
            matched: false,
        };
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
    }

    #[test]
    fn format_annotation_quantifier_matched() {
        let doc = atom_doc("*");
        let ann = EvalAnn::Quantifier {
            count: 5,
            matched: true,
        };
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
        assert!(result.unwrap().1.contains("5 matched"));
    }

    #[test]
    fn format_annotation_quantifier_not_matched() {
        let doc = atom_doc("+");
        let ann = EvalAnn::Quantifier {
            count: 0,
            matched: false,
        };
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
        assert!(result.unwrap().1.contains("→ no"));
    }

    #[test]
    fn format_annotation_missing() {
        let doc = atom_doc("arg");
        let ann = EvalAnn::Missing;
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
        assert!(result.unwrap().1.contains("missing"));
    }

    #[test]
    fn format_annotation_anywhere() {
        let doc = atom_doc("pattern");
        let ann = EvalAnn::Anywhere {
            args: vec!["a".to_string(), "b".to_string()],
            matched: true,
        };
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
    }

    #[test]
    fn format_annotation_anywhere_not_matched() {
        let doc = atom_doc("pattern");
        let ann = EvalAnn::Anywhere {
            args: vec!["x".to_string(), "y".to_string()],
            matched: false,
        };
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
    }

    #[test]
    fn format_annotation_cond_branch() {
        let doc = atom_doc("when");
        let ann = EvalAnn::CondBranch {
            decision: may_i_core::Decision::Allow,
        };
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
        assert!(result.unwrap().1.contains(":allow"));
    }

    #[test]
    fn format_annotation_cond_else() {
        let doc = atom_doc("else");
        let ann = EvalAnn::CondElse {
            decision: may_i_core::Decision::Deny,
        };
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
        assert!(result.unwrap().0.contains("else"));
    }

    #[test]
    fn format_annotation_exact_args_matched() {
        let doc = list_doc(vec![atom_doc("exact"), atom_doc("a"), atom_doc("b")]);
        let ann = EvalAnn::ExactArgs {
            patterns: vec!["a".to_string(), "b".to_string()],
            args: vec!["a".to_string(), "b".to_string()],
            matched: true,
        };
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
    }

    #[test]
    fn format_annotation_exact_args_mismatch() {
        let doc = list_doc(vec![atom_doc("exact"), atom_doc("x"), atom_doc("y")]);
        let ann = EvalAnn::ExactArgs {
            patterns: vec!["a".to_string(), "b".to_string()],
            args: vec!["x".to_string(), "y".to_string()],
            matched: false,
        };
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
    }

    #[test]
    fn format_annotation_exact_remainder() {
        let doc = atom_doc("remainder");
        let ann = EvalAnn::ExactRemainder { count: 3 };
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
        assert!(result.unwrap().1.contains("3 extra args"));
    }

    #[test]
    fn render_observed_value_escapes_quotes() {
        let value = r#"say "hello""#;
        let result = render_observed_value(value);
        assert!(result.contains("\\\""));
    }

    #[test]
    fn render_observed_value_escapes_backslash() {
        let value = r#"path\to\file"#;
        let result = render_observed_value(value);
        assert!(result.contains("\\\\"));
    }

    #[test]
    fn render_observed_value_escapes_newline() {
        let value = "line1\nline2";
        let result = render_observed_value(value);
        assert!(result.contains("\\n"));
    }

    #[test]
    fn render_observed_value_truncates_long() {
        let value = "a".repeat(100);
        let result = render_observed_value(&value);
        assert!(result.contains('…'));
    }

    #[test]
    fn node_text_atom() {
        let doc = atom_doc("test");
        assert_eq!(node_text(&doc), "test");
    }

    #[test]
    fn node_text_list() {
        let doc = list_doc(vec![atom_doc("a"), atom_doc("b")]);
        assert_eq!(node_text(&doc), "(a b)");
    }

    #[test]
    fn node_text_vector() {
        let doc = Doc {
            ann: None,
            node: DocF::Vector(vec![atom_doc("x"), atom_doc("y")]),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        assert_eq!(node_text(&doc), "[x y]");
    }

    #[test]
    fn is_regex_node_with_regex() {
        let doc = list_doc(vec![atom_doc("regex"), atom_doc("pattern")]);
        assert!(is_regex_node(&doc));
    }

    #[test]
    fn is_regex_node_without_regex() {
        let doc = list_doc(vec![atom_doc("="), atom_doc("value")]);
        assert!(!is_regex_node(&doc));
    }

    #[test]
    fn extract_outcome_with_reason() {
        let doc = Doc {
            ann: Some(EvalAnn::RuleEffect {
                decision: may_i_core::Decision::Allow,
                reason: Some("safe command".to_string()),
            }),
            node: DocF::Atom("test".into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let result = extract_outcome(&doc);
        assert!(result.is_some());
        assert!(result.unwrap().contains("safe command"));
    }

    #[test]
    fn extract_outcome_without_reason() {
        let doc = Doc {
            ann: Some(EvalAnn::RuleEffect {
                decision: may_i_core::Decision::Deny,
                reason: None,
            }),
            node: DocF::Atom("test".into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let result = extract_outcome(&doc);
        assert!(result.is_some());
    }

    #[test]
    fn extract_outcome_no_effect() {
        let doc = atom_doc("test");
        let result = extract_outcome(&doc);
        assert!(result.is_none());
    }

    #[test]
    fn has_args_match_with_true_result() {
        let doc = Doc {
            ann: Some(EvalAnn::ArgsResult(true)),
            node: DocF::Atom("test".into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        assert!(has_args_match(&doc));
    }

    #[test]
    fn has_args_match_with_rule_effect() {
        let doc = Doc {
            ann: Some(EvalAnn::RuleEffect {
                decision: may_i_core::Decision::Allow,
                reason: None,
            }),
            node: DocF::Atom("test".into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        assert!(has_args_match(&doc));
    }

    #[test]
    fn has_args_match_without_match() {
        let doc = atom_doc("test");
        assert!(!has_args_match(&doc));
    }

    #[test]
    fn find_line_exact_match() {
        let lines = vec!["first line".to_string(), "second line".to_string()];
        let mut search_from = 0;
        let result = find_line(&lines, "second", &mut search_from);
        assert_eq!(result, Some(1));
        assert_eq!(search_from, 2);
    }

    #[test]
    fn find_line_no_match() {
        let lines = vec!["first".to_string(), "second".to_string()];
        let mut search_from = 0;
        let result = find_line(&lines, "third", &mut search_from);
        assert_eq!(result, None);
    }

    #[test]
    fn find_line_first_token_fallback() {
        let lines = vec!["(effect :allow)".to_string()];
        let mut search_from = 0;
        let result = find_line(&lines, "(effect :allow something)", &mut search_from);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn strip_ansi_with_codes() {
        let input = "\x1b[32mgreen\x1b[0m text";
        let result = strip_ansi(input);
        assert_eq!(result, "green text");
    }

    #[test]
    fn strip_ansi_without_codes() {
        let input = "plain text";
        let result = strip_ansi(input);
        assert_eq!(result, "plain text");
    }

    #[test]
    fn ellipsize_after_at_end() {
        let items = vec!["a".to_string(), "b".to_string()];
        let result = ellipsize_after(&items, 1);
        assert!(!result.contains('…'));
    }

    #[test]
    fn ellipsize_after_before_end() {
        let items = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let result = ellipsize_after(&items, 0);
        assert!(result.contains('…'));
    }

    #[test]
    fn truncate_list_short() {
        let items = vec!["a".to_string(), "b".to_string()];
        let result = truncate_list(&items, 5);
        assert_eq!(result, "a, b");
    }

    #[test]
    fn truncate_list_long() {
        let items = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ];
        let result = truncate_list(&items, 3);
        assert!(result.contains('…'));
    }

    #[test]
    fn colorize_effect_sexpr_replaces_keywords() {
        let input = "(effect :allow) then (effect :ask) then (effect :deny)";
        let result = colorize_effect_sexpr(input);
        assert!(!result.is_empty());
    }

    // Tests for internal helper functions

    #[test]
    fn verdict_true_returns_yes() {
        assert_eq!(verdict(true), "yes");
    }

    #[test]
    fn verdict_false_returns_no() {
        assert_eq!(verdict(false), "no");
    }

    #[test]
    fn collect_annotations_returns_pairs() {
        let doc = Doc {
            ann: Some(EvalAnn::ContextHasPresence {
                key: ":test".into(),
                source: "(has :test)".into(),
                matched: true,
            }),
            node: DocF::Atom("test".into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let result = collect_annotations(&doc);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn collect_annotations_skips_none_annotations() {
        let doc = atom_doc("test");
        let result = collect_annotations(&doc);
        assert!(result.is_empty());
    }

    #[test]
    fn dim_unevaluated_returns_doc() {
        let doc = atom_doc("test");
        let result = dim_unevaluated(doc);
        assert!(matches!(result.node, DocF::Atom(_)));
    }

    #[test]
    fn has_any_annotation_true_when_present() {
        let doc = Doc {
            ann: Some(EvalAnn::CommandMatch(true)),
            node: DocF::Atom("test".into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        assert!(has_any_annotation(&doc));
    }

    #[test]
    fn has_any_annotation_false_when_absent() {
        let doc = atom_doc("test");
        assert!(!has_any_annotation(&doc));
    }

    #[test]
    fn has_any_visible_annotation_true_for_visible() {
        let doc = Doc {
            ann: Some(EvalAnn::ContextHasPresence {
                key: ":test".into(),
                source: "test".into(),
                matched: true,
            }),
            node: DocF::Atom("test".into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        assert!(has_any_visible_annotation(&doc));
    }

    #[test]
    fn has_any_visible_annotation_false_for_invisible() {
        let doc = Doc {
            ann: Some(EvalAnn::CommandMatch(true)),
            node: DocF::Atom("test".into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        assert!(!has_any_visible_annotation(&doc));
    }

    #[test]
    fn truncate_unevaluated_atom_returns_clone() {
        let doc = atom_doc("test");
        let result = truncate_unevaluated(&doc, 2);
        assert!(matches!(result.node, DocF::Atom(_)));
    }

    #[test]
    fn truncate_unevaluated_vector() {
        let doc = Doc {
            ann: None,
            node: DocF::Vector(vec![atom_doc("x"), atom_doc("y")]),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let result = truncate_unevaluated(&doc, 2);
        assert!(matches!(result.node, DocF::Vector(_)));
    }
}
