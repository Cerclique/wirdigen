//! The `wirdigen` command (spec §9, ADR 0013).

mod color;
mod json;
mod placement;

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand};
use wirdigen::{Diagnostic, RenderOptions, Severity, Source};

use crate::color::ColorChoice;
use crate::json::FileStatus;
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

    /// How to report Diagnostics and results: `human` on stderr, or `json` Lines on stdout.
    #[arg(long, value_enum, default_value_t, global = true)]
    message_format: MessageFormat,
}

/// Where and how `validate` and `generate` report (spec §9.7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
enum MessageFormat {
    /// Rendered Diagnostics and status lines on stderr.
    #[default]
    Human,
    /// One JSON object per line on stdout: `diagnostic`, `file` and `summary` records.
    Json,
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
    Validate(ValidationArgs),
    /// Validate Protocol Descriptions and write their Dissectors.
    Generate(GenerateArgs),
    /// Print the JSON Schema of Protocol Descriptions, for editor completion.
    Schema(SchemaArgs),
}

#[derive(clap::Args)]
struct ValidationArgs {
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
    validation: ValidationArgs,

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

#[derive(clap::Args)]
struct SchemaArgs {
    /// Write the JSON Schema to this file instead of standard output (`-`).
    #[arg(short = 'o', value_name = "FILE|-")]
    output: Option<PathBuf>,
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
    let (subcommand, validation, placement, check) = match cli.command {
        Command::Schema(SchemaArgs { output }) => return schema(output),
        Command::Validate(validation) => ("validate", validation, None, false),
        Command::Generate(GenerateArgs { validation, output, out_dir, check }) => {
            ("generate", validation, Some(Placement::from_args(output, out_dir)), check)
        }
    };
    let ValidationArgs { inputs: paths, deny_warnings } = validation;
    let mut options = RenderOptions::default();
    options.color = color;
    options.deny_warnings = deny_warnings;
    let inputs = placement::inputs(paths).unwrap_or_else(|message| usage_error(subcommand, &message));
    let actions = match &placement {
        None => vec![Action::Validate; inputs.len()],
        Some(placement) => {
            actions(&inputs, placement, check).unwrap_or_else(|message| usage_error(subcommand, &message))
        }
    };
    if cli.message_format == MessageFormat::Json {
        if let Some(input) = inputs
            .iter()
            .zip(&actions)
            .find_map(|(input, action)| matches!(action, Action::Write(Output::Stdout)).then_some(input))
        {
            let message = if matches!(placement, Some(Placement::Single(_))) {
                "`--message-format json` writes to standard output, so it cannot be used with `-o -`".to_owned()
            } else {
                format!(
                    "`--message-format json` writes to standard output, but so does the Dissector of `{}`; \
                     give `-o <FILE>`",
                    input.name()
                )
            };
            usage_error(subcommand, &message);
        }
    }

    let mut run = Run {
        options,
        verbosity,
        format: cli.message_format,
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

/// `wirdigen schema`: writes the JSON Schema to `output`, standard output by default.
fn schema(output: Option<PathBuf>) -> ExitCode {
    let output = output.map_or(Output::Stdout, Output::from_arg);
    match write(&output, &wirdigen::json_schema()) {
        Ok(_) => ExitCode::SUCCESS,
        Err(message) => {
            report_error(&message);
            ExitCode::FAILURE
        }
    }
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

impl Action {
    /// The file or `-` its Dissector goes to, as the `output` of a `file` record.
    fn output_name(&self) -> Option<String> {
        match self {
            Action::Validate => None,
            Action::Write(Output::Stdout) => Some("-".to_owned()),
            Action::Write(Output::File(path)) | Action::Check(path) => Some(path.to_string_lossy().into_owned()),
        }
    }
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
    format: MessageFormat,
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
        let status = self.run_action(input, action);
        if status.is_failure() {
            self.failed = true;
        }
        if self.format == MessageFormat::Json {
            println!("{}", json::file(&input.name(), action.output_name().as_deref(), status));
        }
    }

    /// The part of [`Run::process`] that does the work, saying how it went.
    fn run_action(&mut self, input: &Input, action: &Action) -> FileStatus {
        let name = input.name();
        let text = match input {
            Input::Stdin => io::read_to_string(io::stdin()),
            Input::File(path) => fs::read_to_string(path),
        };
        let text = match text {
            Ok(text) => text,
            Err(err) => {
                report_error(&format!("cannot read `{name}`: {err}"));
                return FileStatus::Failed;
            }
        };
        let source = Source::new(name.as_ref(), text.as_str());
        let valid = wirdigen::validate(&source);
        let diagnostics = match &valid {
            Ok(valid) => valid.warnings(),
            Err(diagnostics) => diagnostics.iter().as_slice(),
        };
        self.report(&source, &text, diagnostics);
        match valid {
            Err(_) => FileStatus::Failed,
            Ok(valid) if self.options.deny_warnings && !valid.warnings().is_empty() => FileStatus::Failed,
            Ok(valid) => match action {
                Action::Validate => FileStatus::Valid,
                Action::Write(output) => match write(output, &valid.generate()) {
                    Ok(outcome) => {
                        self.report_outcome(output, outcome);
                        match outcome {
                            WriteOutcome::Written => FileStatus::Written,
                            WriteOutcome::Unchanged => FileStatus::Unchanged,
                        }
                    }
                    Err(message) => {
                        report_error(&message);
                        FileStatus::Failed
                    }
                },
                Action::Check(path) => {
                    let display = path.display();
                    match check(path, &valid.generate()) {
                        Ok(Freshness::Fresh) => {
                            self.report_verbose(&format!("unchanged `{display}`"));
                            FileStatus::Unchanged
                        }
                        Ok(Freshness::Stale) => {
                            report_error(&format!("`{display}` is stale"));
                            FileStatus::Stale
                        }
                        Ok(Freshness::Missing) => {
                            report_error(&format!("`{display}` is stale (missing)"));
                            FileStatus::Stale
                        }
                        Err(err) => {
                            report_error(&format!("cannot read `{display}`: {err}"));
                            FileStatus::Failed
                        }
                    }
                }
            },
        }
    }

    /// Reports one input's Diagnostics: rendered to stderr, each block separated from the previous
    /// one, or as `diagnostic` records on stdout.
    fn report(&mut self, source: &Source, text: &str, diagnostics: &[Diagnostic]) {
        if diagnostics.is_empty() {
            return;
        }
        for diagnostic in diagnostics {
            let is_error = diagnostic.severity() == Severity::Error || self.options.deny_warnings;
            match self.format {
                MessageFormat::Json => {
                    let mut plain = self.options.clone();
                    plain.color = false;
                    let rendered = diagnostic.render(source, &plain);
                    let denied = self.options.deny_warnings && diagnostic.severity() == Severity::Warning;
                    println!("{}", json::diagnostic(source.name(), text, diagnostic, &rendered, denied));
                }
                MessageFormat::Human if is_error || self.verbosity.shows_warnings() => {
                    if self.rendered_any {
                        eprintln!();
                    }
                    eprint!("{}", diagnostic.render(source, &self.options));
                    self.rendered_any = true;
                }
                MessageFormat::Human => {}
            }
            // The JSON summary counts by severity, as its records keep a denied warning's.
            let counts_as_error = match self.format {
                MessageFormat::Json => diagnostic.severity() == Severity::Error,
                MessageFormat::Human => is_error,
            };
            if counts_as_error {
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

    /// Prints `line` to stderr under `-v` only, in the human format.
    fn report_verbose(&self, line: &str) {
        if self.format == MessageFormat::Human && self.verbosity == Verbosity::Verbose {
            eprintln!("{line}");
        }
    }

    /// The `error: 2 errors, 1 warning in 1 of 3 files` line, only when there were Diagnostics
    /// and not under `-q`.
    ///
    /// In the JSON format, the `summary` record instead, always.
    fn print_summary(&self, files: usize) {
        if self.format == MessageFormat::Json {
            println!("{}", json::summary(self.errors, self.warnings, u8::from(self.failed)));
            return;
        }
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

/// Prints why an input failed to stderr, in either message format.
fn report_error(message: &str) {
    eprintln!("error: {message}");
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
