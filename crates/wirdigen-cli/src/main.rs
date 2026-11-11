//! The `wirdigen` command (spec §9, ADR 0013).

mod color;
mod placement;

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand};
use wirdigen::{Diagnostic, RenderOptions, Severity, Source};

use crate::color::ColorChoice;
use crate::placement::{Input, Output, Placement};

/// Generate Wireshark Lua dissectors from YAML protocol descriptions.
#[derive(Parser)]
#[command(name = "wirdigen", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// When to colour Diagnostics on stderr.
    #[arg(long, value_enum, default_value_t, global = true)]
    color: ColorChoice,
}

#[derive(Subcommand)]
enum Command {
    /// Validate Protocol Descriptions; write nothing.
    Validate(Inputs),
    /// Validate Protocol Descriptions and write their Dissectors.
    Generate(GenerateArgs),
}

#[derive(clap::Args)]
struct Inputs {
    /// Protocol Description files; `-` reads standard input.
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
}

#[derive(clap::Args)]
struct GenerateArgs {
    #[command(flatten)]
    inputs: Inputs,

    /// Write the Dissector of the only input to this file, or to standard output for `-`.
    #[arg(short = 'o', value_name = "FILE|-", conflicts_with = "out_dir")]
    output: Option<PathBuf>,

    /// Write each Dissector into this directory instead of next to its input.
    #[arg(long, value_name = "DIR")]
    out_dir: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let color = color::use_color(
        cli.color,
        std::env::var_os("NO_COLOR").as_deref(),
        std::env::var_os("CLICOLOR_FORCE").as_deref(),
        std::io::stderr().is_terminal(),
    );
    let mut options = RenderOptions::default();
    options.color = color;
    let (subcommand, args, placement) = match cli.command {
        Command::Validate(Inputs { inputs }) => ("validate", inputs, None),
        Command::Generate(GenerateArgs { inputs: Inputs { inputs }, output, out_dir }) => {
            ("generate", inputs, Some(Placement::from_args(output, out_dir)))
        }
    };
    let inputs = placement::inputs(args).unwrap_or_else(|message| usage_error(subcommand, &message));
    let outputs: Vec<Option<Output>> = match &placement {
        None => vec![None; inputs.len()],
        Some(placement) => {
            let cwd = std::env::current_dir().unwrap_or_default();
            placement::outputs(&inputs, placement, &cwd)
                .unwrap_or_else(|message| usage_error(subcommand, &message))
                .into_iter()
                .map(Some)
                .collect()
        }
    };

    let mut run = Run { options, failed: false, errors: 0, warnings: 0, files_with_diagnostics: 0 };
    for (input, output) in inputs.iter().zip(&outputs) {
        run.process(input, output.as_ref());
    }
    run.print_summary(inputs.len());
    if run.failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

/// Exits with clap's usage error (code 2) for a mistake clap cannot see on its own.
fn usage_error(subcommand: &str, message: &str) -> ! {
    let mut command = Cli::command();
    command.build();
    let command = command.find_subcommand_mut(subcommand).expect("the subcommand exists");
    command.error(ErrorKind::ArgumentConflict, message).exit()
}

/// The state of one `validate` or `generate` run across its inputs.
struct Run {
    options: RenderOptions,
    failed: bool,
    errors: usize,
    warnings: usize,
    files_with_diagnostics: usize,
}

impl Run {
    /// Validates one input and, under `generate`, writes its Dissector to `output`.
    fn process(&mut self, input: &Input, output: Option<&Output>) {
        let name = input.name();
        let text = match input {
            Input::Stdin => io::read_to_string(io::stdin()),
            Input::File(path) => fs::read_to_string(path),
        };
        let text = match text {
            Ok(text) => text,
            Err(err) => return self.fail(&format!("cannot read `{name}`: {err}")),
        };
        let source = Source::new(name.as_ref(), text);
        let valid = wirdigen::validate(&source);
        let diagnostics = match &valid {
            Ok(valid) => valid.warnings(),
            Err(diagnostics) => diagnostics.iter().as_slice(),
        };
        self.report(&source, diagnostics);
        match valid {
            Err(_) => self.failed = true,
            Ok(valid) => {
                if let Some(output) = output {
                    if let Err(message) = write(output, &valid.generate()) {
                        self.fail(&message);
                    }
                }
            }
        }
    }

    /// Renders one input's Diagnostics to stderr, each block separated from the previous one.
    fn report(&mut self, source: &Source, diagnostics: &[Diagnostic]) {
        if diagnostics.is_empty() {
            return;
        }
        for diagnostic in diagnostics {
            if self.errors + self.warnings > 0 {
                eprintln!();
            }
            eprint!("{}", diagnostic.render(source, &self.options));
            match diagnostic.severity() {
                Severity::Error => self.errors += 1,
                Severity::Warning => self.warnings += 1,
            }
        }
        self.files_with_diagnostics += 1;
    }

    fn fail(&mut self, message: &str) {
        eprintln!("error: {message}");
        self.failed = true;
    }

    /// The `error: 2 errors, 1 warning in 1 of 3 files` line, only when there were Diagnostics.
    fn print_summary(&self, files: usize) {
        if self.errors + self.warnings == 0 {
            return;
        }
        let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
        let counts: Vec<String> = [(self.errors, "error"), (self.warnings, "warning")]
            .into_iter()
            .filter(|&(n, _)| n > 0)
            .map(|(n, word)| plural(n, word))
            .collect();
        let level = if self.errors > 0 { "error" } else { "warning" };
        eprintln!("\n{level}: {} in {} of {}", counts.join(", "), self.files_with_diagnostics, plural(files, "file"));
    }
}

/// Writes a Dissector to its output, creating missing parent directories of a file.
fn write(output: &Output, lua: &str) -> Result<(), String> {
    match output {
        Output::Stdout => {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(lua.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|err| format!("cannot write to standard output: {err}"))
        }
        Output::File(path) => {
            let created = match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => fs::create_dir_all(parent),
                _ => Ok(()),
            };
            created
                .and_then(|()| fs::write(path, lua))
                .map_err(|err| format!("cannot write `{}`: {err}", path.display()))
        }
    }
}
