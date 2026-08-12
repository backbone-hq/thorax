//! The single `thorax` binary.
//!
//! One executable fans out to three peer frontends, all of which sit over `thorax-ops` through the
//! shared `thorax-frontend` glue:
//!
//! - bare `thorax`        → the interactive TUI editor (when attached to a terminal);
//! - `thorax run …`       → the environment-injection child-process runner;
//! - `thorax <command> …` → every other CLI command.
//!
//! This file is only the top-level parser and dispatch. The CLI subcommand surface is flattened in
//! from `thorax-cli` so `thorax --help` lists everything in one place.

use std::io::{self, stdin, stdout, IsTerminal};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use thorax_frontend::GlobalArgs;

const QUICKSTART: &str = "\
Examples:
  thorax                                       open the interactive editor (TUI)
  thorax init                                  create a vault here
  printf '%s' \"$SECRET\" | thorax set app/prod/db  store a secret without argv exposure
  thorax get app/prod/db                       read it back
  thorax run app/prod -- ./serve               run ./serve with app/prod/* injected
  thorax list                                  see all secrets and your access
  thorax user invite alice --read app \\
         --invite-file alice.thrx              invite a teammate (read on app/*)
  thorax claim alice.thrx                      join a vault you were invited to
  thorax status                                health view: what needs attention

References:
  user    @handle  or a short id prefix (e.g. 30deda91)
  group   %name    or a short id prefix (e.g. %devs)
  Full ids and machine output: add --json to most commands.";

#[derive(Parser)]
#[command(
    name = "thorax",
    version,
    about = "Local-first encrypted secrets",
    after_help = QUICKSTART
)]
struct Thorax {
    #[command(flatten)]
    global: GlobalArgs,
    #[command(subcommand)]
    command: Option<TopCommand>,
}

#[derive(Subcommand)]
enum TopCommand {
    /// Run a command with selected secrets injected into its environment.
    Run(thorax_run::RunArgs),
    /// Every other Thorax command (init, set, get, user, grant, …).
    #[command(flatten)]
    Cli(thorax_cli::Command),
    /// Generate shell completion scripts. Pipe the output to a completion file.
    Completions(thorax_cli::CompletionsArgs),
}

fn main() -> ExitCode {
    let thorax = Thorax::parse();
    let json = thorax.global.json;
    let result = match thorax.command {
        // Bare `thorax`: launch the editor when interactive; otherwise a TUI makes no sense, so
        // print help and exit cleanly (e.g. piped output, CI).
        None => {
            if stdin().is_terminal() && stdout().is_terminal() {
                thorax_tui::run_tui(thorax.global)
            } else {
                let mut help = Thorax::command();
                let _ = help.print_long_help();
                return ExitCode::SUCCESS;
            }
        }
        Some(TopCommand::Run(args)) => thorax_run::run_inject(thorax.global, args),
        Some(TopCommand::Completions(args)) => {
            let mut cmd = Thorax::command();
            clap_complete::generate(args.shell, &mut cmd, "thorax", &mut io::stdout());
            Ok(ExitCode::SUCCESS)
        }
        Some(TopCommand::Cli(command)) => thorax_cli::run_cli(thorax.global, command),
    };
    match result {
        Ok(code) => code,
        Err(error) => thorax_frontend::emit(&error, json),
    }
}
