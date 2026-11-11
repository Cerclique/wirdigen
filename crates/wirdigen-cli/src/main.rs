//! The `wirdigen` command (spec §9, ADR 0013).

mod color;
mod placement;

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
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

    /// Hide warnings and the summary line; errors are still shown.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,

    /// List each Dissector as written or unchanged.
    #[arg(short, long, global = true)]
    verbose: bool,
}

/// How much `validate` and `generate` say on stderr besides errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verbosity {
    /// `-q`: errors only.
    Quiet,
    /// Diagnostics and the summary line.
    Normal,
    /// `-v`: also each Dissector written or unchanged.
    Verbose,
}

impl Verbosity {
    fn from_flags(quiet: bool, verbose: bool) -> Self {
        match (quiet, verbose) {
            (true, _) => Verbosity::Quiet,
            (false, true) => Verbosity::Verbose,
            (false, false) => Verbosity::Normal,
        }
    }

    /// Whether warnings and the summary line are shown.
    fn shows_warnings(self) -> bool {
        self != Verbosity::Quiet
    }
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
    let verbosity = Verbosity::from_flags(cli.quiet, cli.verbose);
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

    let mut run = Run {
        options,
        verbosity,
        failed: false,
        rendered_any: false,
        errors: 0,
        warnings: 0,
        files_with_diagnostics: 0,
    };
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
    verbosity: Verbosity,
    failed: bool,
    /// Whether a Diagnostic was rendered yet, so the next one is set apart by a blank line.
    rendered_any: bool,
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
                    match write(output, &valid.generate()) {
                        Ok(outcome) => self.report_outcome(output, outcome),
                        Err(message) => self.fail(&message),
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
            let shown = diagnostic.severity() == Severity::Error || self.verbosity.shows_warnings();
            if shown {
                if self.rendered_any {
                    eprintln!();
                }
                eprint!("{}", diagnostic.render(source, &self.options));
                self.rendered_any = true;
            }
            match diagnostic.severity() {
                Severity::Error => self.errors += 1,
                Severity::Warning => self.warnings += 1,
            }
        }
        self.files_with_diagnostics += 1;
    }

    /// Under `-v`, the line saying what happened to one Dissector.
    fn report_outcome(&self, output: &Output, outcome: WriteOutcome) {
        if self.verbosity != Verbosity::Verbose {
            return;
        }
        let status = match outcome {
            WriteOutcome::Written => "written",
            WriteOutcome::Unchanged => "unchanged",
        };
        match output {
            Output::Stdout => eprintln!("{status} to standard output"),
            Output::File(path) => eprintln!("{status} `{}`", path.display()),
        }
    }

    fn fail(&mut self, message: &str) {
        eprintln!("error: {message}");
        self.failed = true;
    }

    /// The `error: 2 errors, 1 warning in 1 of 3 files` line, only when there were Diagnostics
    /// and not under `-q`.
    fn print_summary(&self, files: usize) {
        if self.errors + self.warnings == 0 || !self.verbosity.shows_warnings() {
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

/// What writing a Dissector did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteOutcome {
    /// New bytes went to the output.
    Written,
    /// The file already held these bytes and was left untouched.
    Unchanged,
}

/// Writes a Dissector to its output, creating missing parent directories of a file.
fn write(output: &Output, lua: &str) -> Result<WriteOutcome, String> {
    match output {
        Output::Stdout => {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(lua.as_bytes())
                .and_then(|()| stdout.flush())
                .map(|()| WriteOutcome::Written)
                .map_err(|err| format!("cannot write to standard output: {err}"))
        }
        Output::File(path) => {
            write_file(path, lua.as_bytes()).map_err(|err| format!("cannot write `{}`: {err}", path.display()))
        }
    }
}

/// Replaces `path` atomically with `bytes`, through a temporary file in the same directory, unless
/// it already holds them. A replaced file keeps its permissions, and a symlink is followed so the
/// link itself stays in place.
fn write_file(path: &Path, bytes: &[u8]) -> io::Result<WriteOutcome> {
    let resolved;
    let path = if path.is_symlink() {
        resolved = fs::canonicalize(path)?;
        resolved.as_path()
    } else {
        path
    };
    let existing = match fs::read(path) {
        Ok(existing) => Some(existing),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };
    if existing.as_deref() == Some(bytes) {
        return Ok(WriteOutcome::Unchanged);
    }
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::create_dir_all(dir)?;
    let mut builder = tempfile::Builder::new();
    builder.prefix(".wirdigen-").suffix(".tmp");
    // tempfile creates its files 0600; ask for 0666 so a new Dissector follows the umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o666));
    }
    let mut temp = builder.tempfile_in(dir)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    if existing.is_some() {
        fs::set_permissions(temp.path(), fs::metadata(path)?.permissions())?;
    }
    temp.persist(path).map_err(|err| err.error)?;
    Ok(WriteOutcome::Written)
}
