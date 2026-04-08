use may_i_core::{Doc, DocF, TriviaSource};

use crate::buffer::EventBuffer;
use crate::color::visible_len;
use crate::output::PrettyOutput;
use crate::render::{emit_trivia_or_line, render, render_child_on_line};
use crate::{indent_spec, FILL_ELIGIBLE_HEADS};

pub(super) fn render_flat_delim<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    dimmed: bool,
    open: char,
    close: char,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim(open, dimmed);
    for (i, child) in children.iter().enumerate() {
        if i > 0 {
            out.emit_space();
        }
        render(child, 0, usize::MAX, dimmed, out);
    }
    out.emit_delim(close, dimmed);
}

/// Trivia-guided layout: makes per-child break decisions based on source trivia.
/// Children with forced breaks (newline in leading trivia) go to new lines.
/// Children without forced breaks try to fit on the current line.
/// Keywords (atoms starting with `:`) keep their following value on the same line.
pub(super) fn render_trivia_guided_delim<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    open: char,
    close: char,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim(open, dimmed);

    // Render head (using render, which handles trailing trivia)
    let mut head_buf = EventBuffer::new();
    render(&children[0], indent + 1, width, dimmed, &mut head_buf);
    let head_width = head_buf.first_line_width();
    head_buf.replay(out);

    if children.len() == 1 {
        out.emit_delim(close, dimmed);
        return;
    }

    // Cascade indent: starts at a base value and updates when a child
    // is placed inline, so that subsequent breaks align under it.
    //   - Indent-spec forms: body indent (+2), fixed (not updated)
    //   - Default forms: column after the opening paren (+1), updated
    //     to align under the first inline child
    let has_indent_spec = children[0].as_atom().and_then(indent_spec).is_some();
    let mut cascade_col = if has_indent_spec {
        indent + 2
    } else {
        indent + 1
    };

    let mut col = indent + 1 + head_width;
    let mut prev_was_keyword = false;
    let mut has_broken = children[0]
        .ann
        .trailing_trivia()
        .iter()
        .any(|t| t.has_newline());

    for child in &children[1..] {
        let forced = child.ann.forced_break();
        let has_source_trivia = !child.ann.leading_trivia().is_empty();
        // Cascade: constructed children (no source trivia) inherit the broken state.
        // Source children decide individually based on their own trivia.
        let should_break = forced || (has_broken && !has_source_trivia);

        if prev_was_keyword {
            // Keep value on same line as preceding keyword
            out.emit_space();
            let mut size_buf = EventBuffer::new();
            render(child, col + 1, width, dimmed, &mut size_buf);
            let child_width = size_buf.first_line_width();
            size_buf.replay(out);
            col += 1 + child_width;
        } else if should_break {
            emit_trivia_or_line(&child.ann, cascade_col, out);
            let mut size_buf = EventBuffer::new();
            render(child, cascade_col, width, dimmed, &mut size_buf);
            col = cascade_col + size_buf.first_line_width();
            size_buf.replay(out);
            has_broken = true;
        } else {
            // Try to fit on current line
            let mut size_buf = EventBuffer::new();
            render(child, col + 1, width, dimmed, &mut size_buf);
            let child_width = size_buf.first_line_width();

            if col + 1 + child_width > width && col > cascade_col {
                // Doesn't fit, break
                emit_trivia_or_line(&child.ann, cascade_col, out);
                render(child, cascade_col, width, dimmed, out);
                col = cascade_col;
                has_broken = true;
            } else {
                out.emit_space();
                size_buf.replay(out);
                let child_start = col + 1;
                col += 1 + child_width;
                // Update cascade to track the last inline arg on the
                // head line (before any break).  After the first break,
                // cascade stays fixed to prevent staircase drift.
                // Indent-spec forms keep their fixed body indent.
                if !has_broken && !has_indent_spec {
                    cascade_col = child_start;
                }
            }
        }
        prev_was_keyword = child.as_atom().is_some_and(|s| s.starts_with(':'));
    }
    out.emit_delim(close, dimmed);
}

/// Greedy broken layout: fit as many args as possible on the first
/// line (after the head), then cascade remaining args under the last
/// inline arg.
pub(super) fn render_broken_delim<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    open: char,
    close: char,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim(open, dimmed);

    let mut head_buf = EventBuffer::new();
    render(&children[0], indent + 1, width, dimmed, &mut head_buf);
    let head_width = head_buf.first_line_width();
    head_buf.replay(out);

    if children.len() == 1 {
        out.emit_delim(close, dimmed);
        return;
    }

    // Greedily fit children on the head line.
    let mut col = indent + 1 + head_width;
    let cascade_col = match children[0].as_atom() {
        Some(_) => indent + head_width + 2, // under first arg
        None => indent + 1,
    };
    let mut n_inline = 0;

    let remaining_count = children.len() - 1;
    for (i, child) in children[1..].iter().enumerate() {
        let mut buf = EventBuffer::new();
        render(child, col + 1, width, dimmed, &mut buf);
        // Don't inline a multiline child if there are more children
        // after it, or if other children are already on the head line.
        // A multiline child as the sole arg after the head is fine
        // (e.g. `(anywhere (regex ...))`, `(has [:key "val"])`), but
        // after other inlined args it reads poorly (e.g.
        // `(and (positional "fmt") (when ...)`).
        if buf.is_multiline() && (i + 1 < remaining_count || n_inline > 0) {
            break;
        }
        let child_width = buf.first_line_width();
        if col + 1 + child_width > width {
            break;
        }
        n_inline += 1;
        col += 1 + child_width;

        // Keywords keep their value on the same line.
        if child.as_atom().is_some_and(|s| s.starts_with(':'))
            && let Some(next) = children.get(1 + n_inline)
        {
            let mut vbuf = EventBuffer::new();
            render(next, col + 1, width, dimmed, &mut vbuf);
            let vw = vbuf.first_line_width();
            if !vbuf.is_multiline() && col + 1 + vw <= width {
                n_inline += 1;
                col += 1 + vw;
            }
        }
    }

    // When nothing was inlined, cascade at indent+1 (like all-drop)
    // rather than under the would-be first arg position.
    let cascade_col = if n_inline == 0 {
        indent + 1
    } else {
        cascade_col
    };

    // Emit inline children.
    for child in &children[1..1 + n_inline] {
        out.emit_space();
        render(child, cascade_col, width, dimmed, out);
    }

    // Emit remaining children on new lines at cascade_col.
    let mut prev_was_keyword = children
        .get(n_inline)
        .and_then(|c| c.as_atom())
        .is_some_and(|s| s.starts_with(':'));
    for child in &children[1 + n_inline..] {
        if prev_was_keyword {
            out.emit_space();
            render(child, cascade_col, width, dimmed, out);
        } else {
            render_child_on_line(child, cascade_col, width, dimmed, out);
        }
        prev_was_keyword = child.as_atom().is_some_and(|s| s.starts_with(':'));
    }
    out.emit_delim(close, dimmed);
}

/// Conservative broken layout: only the first arg goes on the head
/// line; all remaining args align under it.  Used as a fallback when
/// the greedy broken layout produces lines that exceed width.
pub(super) fn render_broken_conservative_delim<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    open: char,
    close: char,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim(open, dimmed);

    let mut head_buf = EventBuffer::new();
    render(&children[0], indent + 1, width, dimmed, &mut head_buf);
    let head_width = head_buf.first_line_width();
    head_buf.replay(out);

    if children.len() == 1 {
        out.emit_delim(close, dimmed);
        return;
    }

    let align = match children[0].as_atom() {
        Some(_) => indent + head_width + 2,
        None => indent + 1,
    };

    // First child inline.
    out.emit_space();
    render(&children[1], align, width, dimmed, out);

    // Rest on new lines at align.
    let mut prev_was_keyword = children[1].as_atom().is_some_and(|s| s.starts_with(':'));
    for child in &children[2..] {
        if prev_was_keyword {
            out.emit_space();
            render(child, align, width, dimmed, out);
        } else {
            render_child_on_line(child, align, width, dimmed, out);
        }
        prev_was_keyword = child.as_atom().is_some_and(|s| s.starts_with(':'));
    }
    out.emit_delim(close, dimmed);
}

pub(super) fn render_all_drop_delim<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    open: char,
    close: char,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim(open, dimmed);
    render(&children[0], indent + 1, width, dimmed, out);

    if children.len() == 1 {
        out.emit_delim(close, dimmed);
        return;
    }

    let child_indent = indent + 1;
    let mut prev_was_keyword = false;
    for (i, child) in children[1..].iter().enumerate() {
        let is_last = i == children.len() - 2;
        if prev_was_keyword {
            out.emit_space();
            render(child, child_indent, width, dimmed, out);
        } else {
            render_child_on_line(child, child_indent, width, dimmed, out);
        }
        if is_last {
            out.emit_delim(close, dimmed);
        }
        prev_was_keyword = child.as_atom().is_some_and(|s| s.starts_with(':'));
    }
}

pub(super) fn render_flat<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    render_flat_delim(children, dimmed, '(', ')', out);
}

pub(super) fn render_broken<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    render_broken_delim(children, indent, width, dimmed, '(', ')', out);
}

pub(super) fn render_broken_conservative<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    render_broken_conservative_delim(children, indent, width, dimmed, '(', ')', out);
}

pub(super) fn render_all_drop<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    render_all_drop_delim(children, indent, width, dimmed, '(', ')', out);
}

pub(super) fn render_cond<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim('(', dimmed);
    render(&children[0], indent + 1, width, dimmed, out);
    let body_indent = indent + 2;

    for (i, clause) in children[1..].iter().enumerate() {
        let is_last = i == children.len() - 2;
        let clause_dimmed = dimmed || clause.dimmed;
        match &clause.node {
            DocF::List(parts) if parts.len() >= 2 => {
                emit_trivia_or_line(&clause.ann, body_indent, out);
                out.emit_node_ann(&clause.ann);
                out.emit_delim('(', clause_dimmed);
                render(&parts[0], body_indent + 1, width, clause_dimmed, out);

                let body_col = body_indent + 1;
                for (j, body_part) in parts[1..].iter().enumerate() {
                    let is_last_part = j == parts.len() - 2;
                    render_child_on_line(body_part, body_col, width, clause_dimmed, out);
                    if is_last_part && is_last {
                        out.emit_delim(')', clause_dimmed);
                        out.emit_delim(')', dimmed);
                    } else if is_last_part {
                        out.emit_delim(')', clause_dimmed);
                    }
                }
            }
            _ => {
                render_child_on_line(clause, body_indent, width, clause_dimmed, out);
                if is_last {
                    out.emit_delim(')', dimmed);
                }
            }
        }
    }

    if children.len() == 1 {
        out.emit_delim(')', dimmed);
    }
}

/// Returns true when `children` is a form that can use fill layout.
/// Fill layout is used for forms with atom args that should pack
/// tightly across lines (and/or, forbidden, anywhere, positional, etc).
pub(super) fn is_fill_eligible<A: Clone>(children: &[Doc<A>]) -> bool {
    let Some(head) = children.first().and_then(|c| c.as_atom()) else {
        return false;
    };
    if !FILL_ELIGIBLE_HEADS.contains(&head) {
        return false;
    }
    // All args must be atoms — render_fill relies on this for width tracking.
    children.len() > 1 && children[1..].iter().all(|c| c.as_atom().is_some())
}

/// Fill layout: atoms flow across lines, wrapping at the column of the
/// first arg (indent + 1 + head_width + 1). Multiple items may appear
/// on each line, unlike the greedy broken layout which puts one per line.
pub(super) fn render_fill<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim('(', dimmed);

    let head = children[0].as_atom().unwrap();
    let head_width = visible_len(head);
    out.emit_atom(head, &children[0].ann, dimmed);

    if children.len() == 1 {
        out.emit_delim(')', dimmed);
        return;
    }

    // Column where first arg would be (head col + space + head + space).
    // Fill layout only applies to all-atom children, so there's no
    // risk of recursive nesting — always align under the first arg.
    let align = indent + 1 + head_width + 1;
    let mut col = indent + 1 + head_width; // column after head

    let last = children.len() - 1;
    for (i, child) in children[1..].iter().enumerate() {
        let atom = child.as_atom().unwrap();
        let atom_width = visible_len(atom);
        let is_last = i + 1 == last;

        if col + 1 + atom_width <= width {
            out.emit_space();
            out.emit_atom(atom, &child.ann, dimmed);
            col += 1 + atom_width;
        } else {
            out.begin_line(align);
            out.emit_atom(atom, &child.ann, dimmed);
            col = align + atom_width;
        }

        if is_last {
            out.emit_delim(')', dimmed);
        }
    }
}

pub(super) fn render_body_indent<A: Clone + TriviaSource>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    spec: u8,
    out: &mut impl PrettyOutput<A>,
) {
    let spec = spec as usize;
    let body_indent = indent + 2;

    out.emit_delim('(', dimmed);

    // Render head atom.
    let mut head_buf = EventBuffer::new();
    render(&children[0], indent + 1, width, dimmed, &mut head_buf);
    let head_width = head_buf.first_line_width();
    head_buf.replay(out);

    if children.len() == 1 {
        out.emit_delim(')', dimmed);
        return;
    }

    // Render "special" args (the first `spec` children after the head).
    // Only the FIRST special arg can stay inline with the head (if it fits).
    // All subsequent special args always drop to a new line aligned under the
    // first arg. This ensures forms like `(if COND THEN ELSE)` never pack
    // COND and THEN together on the same line when the form is broken.
    let special_end = (1 + spec).min(children.len());
    let special_align = indent + 1 + head_width + 1;
    let mut col = indent + 1 + head_width;

    for (i, child) in children[1..special_end].iter().enumerate() {
        let mut buf = EventBuffer::new();
        render(child, col + 1, width, dimmed, &mut buf);
        let child_width = buf.first_line_width();

        // Only the first special arg may stay inline, and only if it fits.
        let keep_inline = i == 0 && col + 1 + child_width <= width;

        if keep_inline {
            out.emit_space();
            buf.replay(out);
            col += 1 + child_width;
        } else {
            render_child_on_line(child, special_align, width, dimmed, out);
            col = special_align + child_width;
        }
    }

    // Render body args at body indent.
    // Keywords (atoms starting with `:`) keep their following value inline.
    let mut prev_was_keyword = false;
    for (i, child) in children[special_end..].iter().enumerate() {
        let is_last = i == children.len() - special_end - 1;
        if prev_was_keyword {
            out.emit_space();
            render(child, body_indent, width, dimmed, out);
        } else {
            render_child_on_line(child, body_indent, width, dimmed, out);
        }
        if is_last {
            out.emit_delim(')', dimmed);
        }
        prev_was_keyword = child.as_atom().is_some_and(|s| s.starts_with(':'));
    }

    if children.len() <= special_end {
        out.emit_delim(')', dimmed);
    }
}
