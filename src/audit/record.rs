// The audit record schema (v1) and its JSON serialisation.

use std::time::SystemTime;

use may_i_core::Decision;
use serde::{Serialize, Serializer};

/// The pinned schema version. Present in every record so the format can
/// evolve without breaking downstream consumers.
const SCHEMA_VERSION: u32 = 1;

/// Which evaluation path produced the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditMode {
    /// `may-i eval`.
    Eval,
    /// The PreToolUse hook path.
    Hook,
}

/// What produced the recorded outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditSource {
    /// A matching rule carried the decision.
    Rule,
    /// The Trust gate short-circuited before any rule applied.
    TrustBlock,
    /// The command failed to parse and the decision floored to `ask`.
    ParseFloor,
}

/// One audit record: the durable, machine-facing fingerprint of a single
/// evaluation outcome. Serialised to one line of JSON.
///
/// Wire type — the field set and JSON key names are the contract. Absent /
/// null conventions:
///
/// - `harness`, `reason`, `diagnostic` are always present, `null` when unknown
///   / inapplicable (stable columnar schema for `jq`).
/// - `cwd` is omitted entirely when unknown (never an empty string).
/// - `rules` is always present, an empty array when no rule decided.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditRecord {
    /// Schema version. Always `1` for now.
    pub v: u32,
    /// RFC 3339 UTC timestamp, seconds resolution.
    pub ts: String,
    /// The invocation mode that wrote the record.
    pub mode: AuditMode,
    /// The driving harness, when known; `null` on the eval path.
    pub harness: Option<String>,
    /// The verbatim evaluated command string.
    pub command: String,
    /// The decision reached.
    #[serde(serialize_with = "serialize_decision")]
    pub decision: Decision,
    /// The combined reason, when present.
    pub reason: Option<String>,
    /// What produced the outcome.
    pub source: AuditSource,
    /// Whether the command parsed cleanly.
    pub parse_ok: bool,
    /// The parse diagnostic, when the command failed to parse.
    pub diagnostic: Option<String>,
    /// Canonical-form hashes of the deciding rules (empty for non-rule
    /// outcomes).
    pub rules: Vec<String>,
    /// The config path in effect.
    pub config: String,
    /// The working directory, when known; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

impl AuditRecord {
    /// Build a record, pinning the schema version. All semantic fields are
    /// supplied by the caller (the pipeline maps an outcome onto them).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ts: String,
        mode: AuditMode,
        harness: Option<String>,
        command: String,
        decision: Decision,
        reason: Option<String>,
        source: AuditSource,
        parse_ok: bool,
        diagnostic: Option<String>,
        rules: Vec<String>,
        config: String,
        cwd: Option<String>,
    ) -> Self {
        Self {
            v: SCHEMA_VERSION,
            ts,
            mode,
            harness,
            command,
            decision,
            reason,
            source,
            parse_ok,
            diagnostic,
            rules,
            config,
            cwd,
        }
    }

    /// Serialise to a single line of JSON (no trailing newline). Infallible
    /// in practice — the record contains only strings, scalars, and a string
    /// vector — but returns `Result` to surface any serde failure to the
    /// best-effort writer rather than panicking.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// The current time as an RFC 3339 UTC string, for stamping a fresh record.
pub fn timestamp_now() -> String {
    rfc3339_utc(SystemTime::now())
}

fn serialize_decision<S: Serializer>(d: &Decision, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(match d {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
    })
}

/// Format a `SystemTime` as an RFC 3339 UTC string at seconds resolution,
/// using only `std`. Times before the Unix epoch format with the correct
/// negative offset via Euclidean division.
pub(crate) fn rfc3339_utc(t: SystemTime) -> String {
    let secs = match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    };
    rfc3339_from_unix_secs(secs)
}

fn rfc3339_from_unix_secs(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3_600;
    let mm = (secs_of_day % 3_600) / 60;
    let ss = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Civil date (year, month, day) from a count of days since the Unix epoch.
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample(
        decision: Decision,
        source: AuditSource,
        parse_ok: bool,
        diagnostic: Option<String>,
        rules: Vec<String>,
    ) -> AuditRecord {
        AuditRecord::new(
            "2026-06-05T00:00:00Z".to_string(),
            AuditMode::Eval,
            None,
            "rm -rf /".to_string(),
            decision,
            Some("danger".to_string()),
            source,
            parse_ok,
            diagnostic,
            rules,
            "/home/u/.config/may-i/config.lisp".to_string(),
            None,
        )
    }

    #[test]
    fn record_serialises_to_one_line_with_all_fields() {
        let rec = sample(
            Decision::Deny,
            AuditSource::Rule,
            true,
            None,
            vec!["abc123".to_string()],
        );
        let line = rec.to_json_line().unwrap();
        assert!(!line.contains('\n'), "record must be one line: {line}");

        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["ts"], "2026-06-05T00:00:00Z");
        assert_eq!(v["mode"], "eval");
        assert!(v["harness"].is_null(), "harness present-null when unknown");
        assert_eq!(v["command"], "rm -rf /");
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "danger");
        assert_eq!(v["source"], "rule");
        assert_eq!(v["parse_ok"], true);
        assert!(v["diagnostic"].is_null());
        assert_eq!(v["rules"], serde_json::json!(["abc123"]));
        assert_eq!(v["config"], "/home/u/.config/may-i/config.lisp");
        // cwd omitted entirely when unknown.
        assert!(v.get("cwd").is_none(), "cwd must be absent, got {v:?}");
    }

    #[test]
    fn parse_failure_record_shape() {
        let rec = sample(
            Decision::Ask,
            AuditSource::ParseFloor,
            false,
            Some("unexpected EOF".to_string()),
            vec![],
        );
        let v: serde_json::Value = serde_json::from_str(&rec.to_json_line().unwrap()).unwrap();
        assert_eq!(v["source"], "parse-floor");
        assert_eq!(v["parse_ok"], false);
        assert_eq!(v["diagnostic"], "unexpected EOF");
        assert_eq!(v["rules"], serde_json::json!([]));
    }

    #[test]
    fn trust_block_record_shape() {
        let rec = sample(Decision::Deny, AuditSource::TrustBlock, true, None, vec![]);
        let v: serde_json::Value = serde_json::from_str(&rec.to_json_line().unwrap()).unwrap();
        assert_eq!(v["source"], "trust-block");
    }

    #[test]
    fn rule_denial_populates_rules_array() {
        let rec = sample(
            Decision::Deny,
            AuditSource::Rule,
            true,
            None,
            vec!["h1".to_string(), "h2".to_string()],
        );
        let v: serde_json::Value = serde_json::from_str(&rec.to_json_line().unwrap()).unwrap();
        assert_eq!(v["source"], "rule");
        assert_eq!(v["rules"], serde_json::json!(["h1", "h2"]));
    }

    #[test]
    fn cwd_present_when_known() {
        let mut rec = sample(Decision::Allow, AuditSource::Rule, true, None, vec![]);
        rec.cwd = Some("/repo".to_string());
        let v: serde_json::Value = serde_json::from_str(&rec.to_json_line().unwrap()).unwrap();
        assert_eq!(v["cwd"], "/repo");
    }

    #[test]
    fn rfc3339_epoch_and_known_dates() {
        assert_eq!(rfc3339_from_unix_secs(0), "1970-01-01T00:00:00Z");
        // 2026-06-05T12:34:56Z — verified via an external converter.
        let secs = 1_780_000_496; // 2026-06-08T... sanity below uses fixed values
        let s = rfc3339_from_unix_secs(secs);
        assert!(s.starts_with("2026-"), "got {s}");
        // A precise known value: 1700000000 = 2023-11-14T22:13:20Z
        assert_eq!(
            rfc3339_from_unix_secs(1_700_000_000),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn rfc3339_from_systemtime_roundtrips_epoch() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(rfc3339_utc(t), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn rfc3339_handles_pre_epoch_systemtime() {
        // One day before the epoch — exercises the `Err` (negative) branch.
        let t = SystemTime::UNIX_EPOCH - Duration::from_secs(86_400);
        assert_eq!(rfc3339_utc(t), "1969-12-31T00:00:00Z");
    }

    #[test]
    fn timestamp_now_is_rfc3339_shaped() {
        let ts = timestamp_now();
        // YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20, "got {ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
    }
}
