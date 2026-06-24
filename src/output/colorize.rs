use may_i_output::Styled;
use may_i_pp::Style;

/// Colourise a trace right-column annotation string into styled spans.
///
/// The annotation is producer-generated text describing a match/decision; its
/// shape (`→ keyword`, `actual ~ regex → yes`, `facts += :k "v"`, …) drives
/// which spans get which role. Input-derived fragments are escaped by `Styled`.
pub(super) fn colorize_right(s: &str) -> Styled {
    if s.is_empty() {
        return Styled::new();
    }

    if s.starts_with("(effect ") || s.starts_with("(default ") {
        return colorize_effect_sexpr(s);
    }

    if s == "yes" {
        return Styled::span("yes", Style::Allow);
    }
    if s == "no" {
        return Styled::span("no", Style::AskSoft);
    }

    if s.contains('~') || s.contains('∈') {
        if let Some(arrow_pos) = s.find('→') {
            let before = &s[..arrow_pos];
            let after = s[arrow_pos + "→".len()..].trim();
            let mut out = Styled::span(before, Style::Dimmed).with("→", Style::Dimmed);
            out.push(" ", Style::Plain);
            out.extend(verdict_span(after));
            out
        } else {
            Styled::span(s, Style::Dimmed)
        }
    } else if let Some(arrow_pos) = s.find('→') {
        let before = &s[..arrow_pos];
        let after = s[arrow_pos + "→".len()..].trim();
        let mut out = Styled::span(before, Style::Dimmed).with("→", Style::Dimmed);
        out.push(" ", Style::Plain);
        out.extend(arrow_target_span(after));
        out
    } else if let Some(rest) = s.strip_prefix("facts += ") {
        if let Some(space_pos) = rest.find(' ') {
            let keyword = &rest[..space_pos];
            let value = &rest[space_pos + 1..];
            Styled::span("facts +=", Style::Dimmed)
                .with(" ", Style::Plain)
                .with(keyword, may_i_pp::atom_style(keyword))
                .with(" ", Style::Plain)
                .with(value, may_i_pp::atom_style(value))
        } else {
            Styled::span(s, Style::Dimmed)
        }
    } else {
        Styled::span(s, Style::Dimmed)
    }
}

/// Colourise a target appearing after `→` in a non-regex annotation.
fn arrow_target_span(after: &str) -> Styled {
    match after {
        "yes" => Styled::span("yes", Style::Allow),
        "no" => Styled::span("no", Style::AskSoft),
        "missing" => Styled::span("missing", Style::AskSoft),
        other if other.starts_with(':') => {
            if let Some(space) = other.find(' ') {
                let keyword = &other[..space];
                let rest = other[space..].trim();
                colorize_decision_keyword(keyword)
                    .with(" ", Style::Plain)
                    .with(rest, may_i_pp::atom_style(rest))
            } else {
                colorize_decision_keyword(other)
            }
        }
        other => Styled::plain(other),
    }
}

/// Colourise a regex/set-membership verdict (`yes`/`no` or plain text).
fn verdict_span(after: &str) -> Styled {
    match after {
        "yes" => Styled::span("yes", Style::Allow),
        "no" => Styled::span("no", Style::AskSoft),
        other => Styled::plain(other),
    }
}

pub fn colorize_decision_keyword(s: &str) -> Styled {
    match s {
        ":allow" => Styled::span(s, Style::Allow),
        ":ask" => Styled::span(s, Style::Ask),
        ":deny" => Styled::span(s, Style::Deny),
        _ => Styled::plain(s),
    }
}

fn colorize_effect_sexpr(s: &str) -> Styled {
    // Split on the decision keywords, styling each occurrence by decision and
    // leaving the surrounding text plain.
    let mut out = Styled::new();
    let mut rest = s;
    let keywords = [
        (":allow", Style::Allow),
        (":ask", Style::Ask),
        (":deny", Style::Deny),
    ];
    'outer: while !rest.is_empty() {
        // Find the earliest keyword occurrence.
        let mut best: Option<(usize, &str, Style)> = None;
        for (kw, style) in keywords {
            if let Some(pos) = rest.find(kw)
                && best.is_none_or(|(b, _, _)| pos < b)
            {
                best = Some((pos, kw, style));
            }
        }
        match best {
            Some((pos, kw, style)) => {
                if pos > 0 {
                    out.push(&rest[..pos], Style::Plain);
                }
                out.push(kw, style);
                rest = &rest[pos + kw.len()..];
            }
            None => {
                out.push(rest, Style::Plain);
                break 'outer;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(s: &Styled) -> String {
        s.to_plain_string()
    }

    #[test]
    fn colorize_right_empty() {
        assert_eq!(plain(&colorize_right("")), "");
    }

    #[test]
    fn colorize_right_yes() {
        assert_eq!(plain(&colorize_right("yes")), "yes");
    }

    #[test]
    fn colorize_right_no() {
        assert_eq!(plain(&colorize_right("no")), "no");
    }

    #[test]
    fn colorize_right_arrow_keyword() {
        assert!(plain(&colorize_right("→ :allow")).contains(":allow"));
    }

    #[test]
    fn colorize_right_arrow_keyword_with_reason() {
        let p = plain(&colorize_right("→ :deny \"reason\""));
        assert!(p.contains(":deny"));
        assert!(p.contains("reason"));
    }

    #[test]
    fn colorize_right_effect_sexpr() {
        assert!(plain(&colorize_right("(effect :allow)")).contains(":allow"));
    }

    #[test]
    fn colorize_right_facts_bind() {
        let p = plain(&colorize_right("facts += :key \"value\""));
        assert!(p.contains(":key"));
        assert!(p.contains("value"));
    }

    #[test]
    fn colorize_right_regex() {
        assert!(plain(&colorize_right("\"val\" ~ (regex \"pat\") → yes")).contains("yes"));
    }

    #[test]
    fn colorize_right_arg_match() {
        assert!(plain(&colorize_right("\"t\" ∈ {\"a\", \"b\"} → no")).contains("no"));
    }

    #[test]
    fn colorize_decision_keywords() {
        assert!(plain(&colorize_decision_keyword(":allow")).contains(":allow"));
        assert!(plain(&colorize_decision_keyword(":ask")).contains(":ask"));
        assert!(plain(&colorize_decision_keyword(":deny")).contains(":deny"));
        assert_eq!(plain(&colorize_decision_keyword(":other")), ":other");
    }

    #[test]
    fn colorize_right_facts_add() {
        assert!(plain(&colorize_right("facts += :key value")).contains("facts"));
    }

    proptest::proptest! {
        #[test]
        fn colorize_right_never_panics(s in ".{0,50}") {
            let _ = colorize_right(&s);
        }

        #[test]
        fn colorize_decision_keyword_never_panics(s in ".{0,20}") {
            let _ = colorize_decision_keyword(&s);
        }
    }
}
