use std::io::{self, Write};
use std::process::ExitCode;

use thorax_frontend::FrontendError;

use crate::args::UpdateArgs;
use crate::CliContext;

/// Handle `thorax update [--check] [--yes]`.
pub fn cmd_update(_ctx: &CliContext, args: UpdateArgs) -> Result<ExitCode, FrontendError> {
    let repo_opt = args.repo.as_deref();

    if args.check {
        // Check-only mode: fetch version, report, exit.
        return match thorax_update::update(true, repo_opt) {
            Ok(outcome) => {
                eprintln!("{}", outcome);
                Ok(ExitCode::SUCCESS)
            }
            Err(e) => {
                eprintln!("Update check failed: {e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    // First check if an update is available.
    let current = thorax_update::Version::current();
    let repo = repo_opt.unwrap_or(thorax_update::REPO);
    let latest = match thorax_update::fetch_latest_version(repo) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Update check failed: {e}");
            return Ok(ExitCode::FAILURE);
        }
    };

    if latest <= current {
        eprintln!("Already up to date ({})", current);
        return Ok(ExitCode::SUCCESS);
    }

    eprint!(
        "Update available: {} → {}. Proceed? [Y/n] ",
        current, latest
    );
    io::stderr().flush().ok();

    if !args.yes {
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        let trimmed = input.trim().to_lowercase();
        if !trimmed.is_empty() && trimmed != "y" && trimmed != "yes" {
            eprintln!("Cancelled");
            return Ok(ExitCode::SUCCESS);
        }
    }

    // Proceed with the full update.
    match thorax_update::update(false, Some(repo)) {
        Ok(outcome) => {
            eprintln!("{}", outcome);
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("Update failed: {e}");
            Ok(ExitCode::FAILURE)
        }
    }
}
