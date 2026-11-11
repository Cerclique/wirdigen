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
    Validate(ValidateArgs),
    /// Validate Protocol Descriptions and write their Dissectors.
    Generate(GenerateArgs),
}

#[derive(clap::Args)]
struct ValidateArgs {
    /// Protocol Description files; `-` reads standard input.
    #[arg(required = true)]
    inputs: Vec<PathBuf>,

    /// Treat warnings as errors, so a file with warnings fails and is not written.
    #[arg(long)]
    deny_warnings: bool,
}

#[derive(clap::Args)]
struct GenerateArgs {
    #[command(flatten)]
    validate: ValidateArgs,

    /// Write the Dissector of the only input to this file, or to standard output for `-`.
    #[arg(short = 'o', value_name = "FILE|-", conflicts_with = "out_dir")]
    output: Option<PathBuf>,

    /// Write each Dissector into this directory instead of next to its input.
    #[arg(long, value_name = "DIR")]
    out_dir: Option<PathBuf>,

    /// Write nothing; fail if a Dissector on disk differs from what would be written.
    #[arg(long)]
    check: bool,
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
    let (subcommand, validate_args, placement, check) = match cli.command {
        Command::Validate(validate_args) => ("validate", validate_args, None, false),
        Command::Generate(GenerateArgs { validate, output, out_dir, check }) => {
            ("generate", validate, Some(Placement::from_args(output, out_dir)), check)
        }
    };
    let ValidateArgs { inputs: args, deny_warnings } = validate_args;
    let mut options = RenderOptions::default();
    options.color = color;
    options.deny_warnings = deny_warnings;
    let inputs = placement::inputs(args).unwrap_or_else(|message| usage_error(subcommand, &message));
    let actions = match &placement {
        None => vec![Action::Validate; inputs.len()],
        Some(placement) => {
            actions(&inputs, placement, check).unwrap_or_else(|message| usage_error(subcommand, &message))
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
    for (input, action) in inputs.iter().zip(&actions) {
        run.process(input, action);
    }
    run.print_summary(inputs.len());
    if run.failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

/// What happens to one input once it is valid.
#[derive(Debug, Clone)]
enum Action {
    /// `validate`: nothing more.
    Validate,
    /// `generate`: write its Dissector.
    Write(Output),
    /// `generate --check`: compare its Dissector with this file.
    Check(PathBuf),
}

/// The `generate` action of each input, in order, from where its Dissector goes.
fn actions(inputs: &[Input], placement: &Placement, check: bool) -> Result<Vec<Action>, String> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let outputs = placement::outputs(inputs, placement, &cwd)?;
    Ok(if check {
        placement::output_files(inputs, placement, outputs)?.into_iter().map(Action::Check).collect()
    } else {
        outputs.into_iter().map(Action::Write).collect()
    })
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
    /// Validates one input and, if it is valid, carries out its `action`.
    fn process(&mut self, input: &Input, action: &Action) {
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
            Ok(valid) if self.options.deny_warnings && !valid.warnings().is_empty() => self.failed = true,
            Ok(valid) => match action {
                Action::Validate => {}
                Action::Write(output) => match write(output, &valid.generate()) {
                    Ok(outcome) => self.report_outcome(output, outcome),
                    Err(message) => self.fail(&message),
                },
                Action::Check(path) => {
                    let display = path.display();
                    match check(path, &valid.generate()) {
                        Ok(Freshness::Fresh) => self.report_verbose(&format!("unchanged `{display}`")),
                        Ok(Freshness::Stale) => self.fail(&format!("`{display}` is stale")),
                        Ok(Freshness::Missing) => self.fail(&format!("`{display}` is stale (missing)")),
                        Err(err) => self.fail(&format!("cannot read `{display}`: {err}")),
                    }
                }
            },
        }
    }

    /// Renders one input's Diagnostics to stderr, each block separated from the previous one.
    fn report(&mut self, source: &Source, diagnostics: &[Diagnostic]) {
        if diagnostics.is_empty() {
            return;
        }
        for diagnostic in diagnostics {
            let is_error = diagnostic.severity() == Severity::Error || self.options.deny_warnings;
            if is_error || self.verbosity.shows_warnings() {
                if self.rendered_any {
                    eprintln!();
                }
                eprint!("{}", diagnostic.render(source, &self.options));
                self.rendered_any = true;
            }
            if is_error {
                self.errors += 1;
            } else {
                self.warnings += 1;
            }
        }
        self.files_with_diagnostics += 1;
    }

    /// Under `-v`, the line saying what happened to one Dissector.
    fn report_outcome(&self, output: &Output, outcome: WriteOutcome) {
        let status = match outcome {
            WriteOutcome::Written => "written",
            WriteOutcome::Unchanged => "unchanged",
        };
        match output {
            Output::Stdout => self.report_verbose(&format!("{status} to standard output")),
            Output::File(path) => self.report_verbose(&format!("{status} `{}`", path.display())),
        }
    }

    /// Prints `line` to stderr under `-v` only.
    fn report_verbose(&self, line: &str) {
        if self.verbosity == Verbosity::Verbose {
            eprintln!("{line}");
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

/// What `--check` found in the file a Dissector would be written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Freshness {
    /// The file holds the Dissector's bytes.
    Fresh,
    /// The file holds other bytes.
    Stale,
    /// There is no file, which counts as stale.
    Missing,
}

/// Compares a Dissector with the file at `path`, writing nothing.
fn check(path: &Path, lua: &str) -> io::Result<Freshness> {
    Ok(match read_existing(path)? {
        Some(existing) if existing == lua.as_bytes() => Freshness::Fresh,
        Some(_) => Freshness::Stale,
        None => Freshness::Missing,
    })
}

/// The bytes of the file at `path`, or `None` when there is none.
fn read_existing(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(existing) => Ok(Some(existing)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
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
    let existing = read_existing(path)?;
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
