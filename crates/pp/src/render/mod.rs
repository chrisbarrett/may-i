use colored::Colorize;
use may_i_core::{Doc, DocF, LayoutHint, Trivia, TriviaSource};

use crate::buffer::{EventBuffer, StringBuilder};
use crate::indent_spec;
use crate::output::PrettyOutput;

mod layout;
use layout::*;

thread_local! {
    /// Per-pp-call configuration. Read by the dispatch layer in
    /// `render_node` to decide between fill and trivia-guided layouts.
    /// Threading via thread-local keeps the public render API
    /// signature-stable while the dispatch logic stays a tree of free
    /// functions.
    static PRESERVE_USER_BREAKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) fn preserve_user_breaks_enabled() -> bool {
    PRESERVE_USER_BREAKS.with(|f| f.get())
}

/// Pretty-print a Doc with the given format settings.
pub fn pretty<A: Clone + TriviaSource>(doc: &Doc<A>, indent: usize, fmt: &crate::Format) -> String {
    let prefix_width = fmt.line_number.map_or(0, line_prefix_width);
    let mut sb = StringBuilder::new(fmt.color);
    PRESERVE_USER_BREAKS.with(|f| f.set(fmt.preserve_user_breaks));
    pretty_into(doc, indent + prefix_width, fmt.width, &mut sb);
    PRESERVE_USER_BREAKS.with(|f| f.set(false));
    let content = sb.into_string();

    match fmt.line_number {
        Some(n) => prepend_line_number(&content, n, fmt.color),
        None => content,
    }
}

/// Pretty-print a Doc into any `PrettyOutput` implementation.
pub fn pretty_into<A: Clone + TriviaSource>(
    doc: &Doc<A>,
    indent: usize,
    width: usize,
    out: &mut impl PrettyOutput<A>,
) {
    render_toplevel(doc, indent, width, false, out);
}

pub fn line_prefix_width(n: usize) -> usize {
    format!("{n}").len() + 2
}

fn prepend_line_number(content: &str, n: usize, color: bool) -> String {
    let prefix = format!("{n}: ");
    let mut result = String::new();
    for (i, line) in content.lines().enumerate() {
        if i > 0 {
            result.push('\n');
        }
        if i == 0 {
            if color {
                result.push_str(&prefix.dimmed().to_string());
            } else {
                result.push_str(&prefix);
            }
        }
        result.push_str(line);
    }
    result
}

pub(crate) fn render<A: Clone + TriviaSource>(
    doc: &Doc<A>,
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    render_node(doc, indent, width, dimmed, out);
    let trailing = doc.ann.trailing_trivia();
    if !trailing.is_empty() {
        out.emit_trailing_trivia(trailing);
    }
}

/// Like `render` but also emits leading trivia of the root node.
/// Used for top-level entry points where there's no parent to emit our leading trivia.
fn render_toplevel<A: Clone + TriviaSource>(
    doc: &Doc<A>,
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    let leading = doc.ann.leading_trivia();
    let has_comments = leading.iter().any(|t| matches!(t, Trivia::Comment { .. }));
    if has_comments {
        out.emit_leading_trivia(leading, indent);
    }
    render(doc, indent, width, dimmed, out);
}

fn render_node<A: Clone + TriviaSource>(
    doc: &Doc<A>,
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    let dimmed = dimmed || doc.dimmed;
    match &doc.node {
        DocF::Atom(s) => {
            out.emit_atom(s, &doc.ann, dimmed);
        }
        DocF::List(children) if children.is_empty() => {
            out.emit_delim('(', dimmed);
            out.emit_delim(')', dimmed);
        }
        DocF::List(children) => {
            out.emit_node_ann(&doc.ann);

            // cond always uses its dedicated renderer
            if let Some(head) = children.first().and_then(|c| c.as_atom())
                && head == "cond"
            {
                render_cond(children, indent, width, dimmed, out);
                return;
            }

            // Forms with indent specs: try flat only when all children
            // are special (no body args to break before). Otherwise
            // always use body-indent to force a break after the predicate.
            if let Some(spec) = children
                .first()
                .and_then(|c| c.as_atom())
                .and_then(indent_spec)
            {
                let special_end = (1 + spec as usize).min(children.len());
                let has_body_args = children.len() > special_end;
                if !has_body_args {
                    let has_trivia = children.iter().any(|c| c.ann.forced_break())
                        || children
                            .iter()
                            .any(|c| c.ann.trailing_trivia().iter().any(|t| t.has_newline()));
                    if !has_trivia {
                        let mut buf = EventBuffer::new();
                        render_flat(children, dimmed, &mut buf);
                        if !buf.is_multiline() && buf.max_line_width(indent) <= width {
                            buf.replay(out);
                            return;
                        }
                    }
                }
                render_body_indent(children, indent, width, dimmed, spec, out);
                return;
            }

            let has_trivia_break = children.iter().any(|c| c.ann.forced_break())
                || children
                    .iter()
                    .any(|c| c.ann.trailing_trivia().iter().any(|t| t.has_newline()));

            let must_break = doc.layout == LayoutHint::AlwaysBreak
                || children.iter().any(|c| c.layout == LayoutHint::AlwaysBreak);

            let preserve_user_breaks = preserve_user_breaks_enabled();

            // Fill-eligible forms (and/or/forbidden/anywhere/positional with
            // all-atom args) take precedence over trivia-guided layout —
            // trivia-guided cascades to the column of the last inline atom,
            // which produces deep right-side indents for long atom lists.
            // Fill always aligns wrapped atoms under the first arg.
            //
            // Exception: `preserve_user_breaks` mode (set by `may-i migrate`)
            // suppresses fill when the user wrote explicit line breaks, so
            // unchanged subtrees keep their hand-arranged formatting.
            // Canonical `may-i fmt` leaves the flag off so atom lists pack
            // tightly.
            let suppress_fill = preserve_user_breaks && has_trivia_break;
            if !must_break && is_fill_eligible(children) && !suppress_fill {
                let mut buf = EventBuffer::new();
                render_flat(children, dimmed, &mut buf);
                if !buf.is_multiline() && buf.max_line_width(indent) <= width {
                    buf.replay(out);
                    return;
                }
                render_fill(children, indent, width, dimmed, out);
                return;
            }

            // When trivia forces breaks (and the form isn't fill-eligible,
            // or fill is suppressed), use trivia-guided layout that
            // preserves the author's per-child line break decisions.
            if has_trivia_break {
                render_trivia_guided_delim(children, indent, width, dimmed, '(', ')', out);
                return;
            }

            if !must_break {
                let mut buf = EventBuffer::new();
                render_flat(children, dimmed, &mut buf);
                if !buf.is_multiline() && buf.max_line_width(indent) <= width {
                    buf.replay(out);
                    return;
                }
            }
            if !must_break {
                let mut buf = EventBuffer::new();
                render_broken(children, indent, width, dimmed, &mut buf);
                if buf.max_line_width(indent) <= width {
                    buf.replay(out);
                    return;
                }
            }
            let mut buf = EventBuffer::new();
            render_broken_conservative(children, indent, width, dimmed, &mut buf);
            if buf.max_line_width(indent) <= width {
                buf.replay(out);
                return;
            }
            render_all_drop(children, indent, width, dimmed, out);
        }
        DocF::Vector(children) if children.is_empty() => {
            out.emit_delim('[', dimmed);
            out.emit_delim(']', dimmed);
        }
        DocF::Vector(children) => {
            out.emit_node_ann(&doc.ann);
            let has_trivia_break = children.iter().any(|c| c.ann.forced_break())
                || children
                    .iter()
                    .any(|c| c.ann.trailing_trivia().iter().any(|t| t.has_newline()));
            if has_trivia_break {
                render_trivia_guided_delim(children, indent, width, dimmed, '[', ']', out);
                return;
            }
            let must_break = doc.layout == LayoutHint::AlwaysBreak
                || children.iter().any(|c| c.layout == LayoutHint::AlwaysBreak);
            if !must_break {
                let mut buf = EventBuffer::new();
                render_flat_delim(children, dimmed, '[', ']', &mut buf);
                if !buf.is_multiline() && buf.max_line_width(indent) <= width {
                    buf.replay(out);
                    return;
                }
            }
            if !must_break {
                let mut buf = EventBuffer::new();
                render_broken_delim(children, indent, width, dimmed, '[', ']', &mut buf);
                if buf.max_line_width(indent) <= width {
                    buf.replay(out);
                    return;
                }
            }
            let mut buf = EventBuffer::new();
            render_broken_conservative_delim(children, indent, width, dimmed, '[', ']', &mut buf);
            if buf.max_line_width(indent) <= width {
                buf.replay(out);
                return;
            }
            render_all_drop_delim(children, indent, width, dimmed, '[', ']', out);
        }
    }
}

/// Emit leading trivia from an annotation at the given indent,
/// or fall back to `begin_line(indent)` when there's no trivia.
/// Preserves blank lines from whitespace-only trivia.
pub(crate) fn emit_trivia_or_line<A: TriviaSource>(
    ann: &A,
    indent: usize,
    out: &mut impl PrettyOutput<A>,
) {
    let leading = ann.leading_trivia();
    let has_comments = leading.iter().any(|t| matches!(t, Trivia::Comment { .. }));
    if has_comments {
        out.emit_leading_trivia(leading, indent);
    } else {
        // Check for whitespace trivia containing blank lines
        let newline_count: usize = leading
            .iter()
            .filter_map(|t| match t {
                Trivia::Whitespace(ws) => Some(ws.matches('\n').count()),
                _ => None,
            })
            .sum();

        // Emit blank lines from preserved whitespace.
        // newline_count includes the newline to end the previous line,
        // so extra blank lines = newline_count - 1.
        let extra_blank_lines = newline_count.saturating_sub(1);
        for _ in 0..extra_blank_lines {
            // Blank lines should not have trailing whitespace
            out.begin_line(0);
        }

        // Always emit the final line break with indentation for content
        out.begin_line(indent);
    }
}

/// Emit a child's leading trivia (if any) at the given indent, OR fall back to
/// `begin_line(indent)` when there's no trivia. Then render the child content
/// and its trailing trivia.
pub(crate) fn render_child_on_line<A: Clone + TriviaSource>(
    child: &Doc<A>,
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    emit_trivia_or_line(&child.ann, indent, out);
    render(child, indent, width, dimmed, out);
}
