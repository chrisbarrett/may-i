// Trust-store integration tests: approve/deny/rehash flows and the audit
// log end to end.

#[path = "../common/mod.rs"]
mod common;

mod audit_integration;
mod trust_integration;
mod trust_rehash;
