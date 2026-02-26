pub mod engine;
pub mod check;
pub mod var_env;

pub use engine::evaluate;
pub use check::{run_checks, CheckResult};
pub use var_env::{VarEnv, VarState};
