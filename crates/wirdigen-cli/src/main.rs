//! The `wirdigen` command (spec §9, ADR 0013).

mod color;

use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use wirdigen::{Diagnostic, RenderOptions, Severity, Source};

use crate::color::ColorChoice;

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
    /// Validate Protocol Descriptions and write each Dissector next to its input.
    Generate(Inputs),
}

#[derive(clap::Args)]
struct Inputs {
    /// Protocol Description files.
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
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
    let (inputs, write) = match cli.command {
        Command::Validate(Inputs { inputs }) => (inputs, false),
        Command::Generate(Inputs { inputs }) => (inputs, true),
    };

    let mut run = Run { options, write, failed: false, errors: 0, warnings: 0, files_with_diagnostics: 0 };
    for input in &inputs {
        run.process(input);
    }
    run.print_summary(inputs.len());
    if run.failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

/// The state of one `validate` or `generate` run across its inputs.
struct Run {
    options: RenderOptions,
    /// Whether valid inputs get their Dissector written (`generate`).
    write: bool,
    failed: bool,
    errors: usize,
    warnings: usize,
    files_with_diagnostics: usize,
}

impl Run {
    fn process(&mut self, input: &Path) {
        let name = input.to_string_lossy();
        let text = match fs::read_to_string(input) {
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
            Ok(valid) if self.write => {
                let output = output_path(input);
                if let Err(err) = fs::write(&output, valid.generate()) {
                    self.fail(&format!("cannot write `{}`: {err}", output.display()));
                }
            }
            Ok(_) => {}
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

/// The Dissector path next to `input`: `foo.wirdigen.yaml` gives `foo.lua`, any other name has
/// its last extension replaced (spec §9.3).
fn output_path(input: &Path) -> PathBuf {
    match input.file_name().and_then(|name| name.to_str()).and_then(|name| name.strip_suffix(".wirdigen.yaml")) {
        Some(stem) => input.with_file_name(format!("{stem}.lua")),
        None => input.with_extension("lua"),
    }
}
