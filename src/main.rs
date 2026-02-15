mod cli;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("error: {e}");
        // Exit code 2 signals a blocking error to Claude Code hooks.
        // stderr is fed back to Claude so it can adjust its plan.
        std::process::exit(2);
    }
}
