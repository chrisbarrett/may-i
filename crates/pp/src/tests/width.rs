use crate::*;

#[test]
fn test_detect_column_width_empty_source() {
    // Empty source should default to 100
    assert_eq!(detect_column_width(""), 100);
    assert_eq!(detect_column_width("   \n  \n"), 100);
}

#[test]
fn test_detect_column_width_only_comments() {
    // Comment-only source should default to 100
    let source = ";; comment\n; another comment\n";
    assert_eq!(detect_column_width(source), 100);
}

#[test]
fn test_detect_column_width_snap_to_80() {
    // Lines around 75-85 columns should snap to 80
    let line_75 = "(rule ".to_string() + &"x".repeat(70) + ")\n";
    assert_eq!(detect_column_width(&line_75), 80);

    let line_85 = "(rule ".to_string() + &"x".repeat(80) + ")\n";
    assert_eq!(detect_column_width(&line_85), 80);
}

#[test]
fn test_detect_column_width_snap_to_100() {
    // Lines around 91-110 columns should snap to 100
    let line_91 = "(rule ".to_string() + &"x".repeat(84) + ")\n";
    assert_eq!(detect_column_width(&line_91), 100);

    // 91 chars: "(rule " (7) + 84 x's + ")" (1) = 92 chars, snap to 100
    let line_110 = "(rule ".to_string() + &"x".repeat(103) + ")\n";
    assert_eq!(detect_column_width(&line_110), 100);
}

#[test]
fn test_detect_column_width_snap_to_120() {
    // Lines around 115-135 columns should snap to 120
    let line_115 = "(rule ".to_string() + &"x".repeat(110) + ")\n";
    assert_eq!(detect_column_width(&line_115), 120);

    let line_135 = "(rule ".to_string() + &"x".repeat(130) + ")\n";
    assert_eq!(detect_column_width(&line_135), 120);
}

#[test]
fn test_detect_column_width_snap_to_200() {
    // Lines above 170 columns should snap to 200
    let line_170 = "(rule ".to_string() + &"x".repeat(165) + ")\n";
    assert_eq!(detect_column_width(&line_170), 200);

    let line_250 = "(rule ".to_string() + &"x".repeat(245) + ")\n";
    assert_eq!(detect_column_width(&line_250), 200);
}

#[test]
fn test_detect_column_width_excludes_trailing_comments() {
    // Trailing comments should not be counted in line length
    let line = "(rule git :effect :allow)    ;; this is a comment\n";
    // Code portion is only ~27 chars, should snap to 80
    assert_eq!(detect_column_width(line), 80);
}

#[test]
fn test_detect_column_width_ignores_semicolons_in_strings() {
    // Semicolons inside strings should not be treated as comments
    let line = r#"(rule "some;value" :effect :allow)"#;
    // Should measure full line, not stop at the semicolon in the string
    let width = detect_column_width(line);
    assert!(
        width > 30,
        "Should count past the semicolon in string, got {}",
        width
    );
}

#[test]
fn test_detect_column_width_95th_percentile() {
    // Mix of short and long lines - should use 95th percentile
    let mut source = String::new();
    // 95 short lines (~27 chars)
    for _ in 0..95 {
        source.push_str("(rule git :effect :allow)\n");
    }
    // 5 very long lines (~202 chars: "(rule " + 195 x's + ")")
    for _ in 0..5 {
        source.push_str(&("(rule ".to_string() + &"x".repeat(195) + ")\n"));
    }
    // With 100 lines, 95th percentile is at index 95 (0-indexed)
    // Index 95 is the first long line (202 chars), which snaps to 200
    assert_eq!(detect_column_width(&source), 200);
}
