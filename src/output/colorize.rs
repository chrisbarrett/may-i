use colored::Colorize;
use may_i_pp::colorize_atom;

pub(super) fn colorize_right(s: &str) -> String {
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

    if s.contains("~") || s.contains("∈") {
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
    } else if let Some(arrow_pos) = s.find("→") {
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

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_layout::strip_ansi;

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

    #[test]
    fn colorize_decision_keywords() {
        assert!(strip_ansi(&colorize_decision_keyword(":allow")).contains(":allow"));
        assert!(strip_ansi(&colorize_decision_keyword(":ask")).contains(":ask"));
        assert!(strip_ansi(&colorize_decision_keyword(":deny")).contains(":deny"));
        assert_eq!(colorize_decision_keyword(":other"), ":other");
    }

    #[test]
    fn colorize_right_regex_match() {
        let s = r#""actual" ~ (regex "pat") → yes"#;
        let result = colorize_right(s);
        assert!(result.contains("yes"));
    }

    #[test]
    fn colorize_right_regex_no_match() {
        let s = r#""actual" ~ (regex "pat") → no"#;
        let result = colorize_right(s);
        assert!(result.contains("no"));
    }

    #[test]
    fn colorize_right_arg_in_set() {
        let s = r#""t" ∈ {a, b} → yes"#;
        let result = colorize_right(s);
        assert!(result.contains("yes"));
    }

    #[test]
    fn colorize_right_arg_not_in_set() {
        let s = r#""t" ∈ {a, b} → no"#;
        let result = colorize_right(s);
        assert!(result.contains("no"));
    }

    #[test]
    fn colorize_right_regex_without_arrow() {
        let s = r#""actual" ~ (regex "pat")"#;
        let result = colorize_right(s);
        assert!(!result.is_empty());
    }

    #[test]
    fn colorize_right_set_without_arrow() {
        let s = r#""t" ∈ {a, b}"#;
        let result = colorize_right(s);
        assert!(!result.is_empty());
    }

    #[test]
    fn colorize_right_facts_add() {
        let s = "facts += :key value";
        let result = colorize_right(s);
        assert!(result.contains("facts"));
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
