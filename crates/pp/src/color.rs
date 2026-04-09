use colored::Colorize;

const COLORED_FORMS: &[&str] = &[
    "rule",
    "command",
    "args",
    "effect",
    "cond",
    "if",
    "when",
    "unless",
    "else",
    "positional",
    "exact",
    "anywhere",
    "define",
    "check",
    "with-facts",
];

pub(crate) fn is_keyword(s: &str) -> bool {
    s.starts_with(':')
}
pub(crate) fn is_string(s: &str) -> bool {
    s.starts_with('"')
}
pub(crate) fn is_regex(s: &str) -> bool {
    s.starts_with("#\"")
}
fn is_colored_form(s: &str) -> bool {
    COLORED_FORMS.contains(&s)
}

/// Colorize an atom value based on its content.
pub fn colorize_atom(s: &str, color: bool) -> String {
    if !color {
        return s.to_string();
    }
    if is_keyword(s) {
        s.truecolor(120, 120, 255).to_string()
    } else if is_string(s) || is_regex(s) {
        s.green().to_string()
    } else if is_colored_form(s) {
        s.blue().to_string()
    } else {
        s.to_string()
    }
}

/// Strip ANSI SGR escape sequences from a string.
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

/// Visible length of a string, ignoring ANSI SGR escape sequences.
pub fn visible_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else if ch == '\x1b' {
            in_escape = true;
        } else {
            len += 1;
        }
    }
    len
}
