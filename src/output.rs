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

/// Render a sequence of elements with the given indent prefix.
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

/// Print a full-width horizontal rule, optionally embedding a label.
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

/// Render a trace as two-column output: left = rule structure, right = eval.
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
}
