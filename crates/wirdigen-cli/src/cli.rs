//! The command line's clap definitions (spec §9.1).
//!
//! Self-contained so that `build.rs` can include this file and generate completions and man pages
//! from the same definitions the binary parses.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Generate Wireshark Lua dissectors from YAML protocol descriptions.
#[derive(Parser)]
#[command(name = "wirdigen", bin_name = "wirdigen", version)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,

    /// When to colour Diagnostics on stderr.
    #[arg(long, value_enum, default_value_t, global = true)]
    pub(crate) color: ColorChoice,

    /// Hide warnings and the summary line; errors are still shown.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub(crate) quiet: bool,

    /// List each Dissector as written or unchanged.
    #[arg(short, long, global = true)]
    pub(crate) verbose: bool,

    /// How to report Diagnostics and results: `human` on stderr, or `json` Lines on stdout.
    #[arg(long, value_enum, default_value_t, global = true)]
    pub(crate) message_format: MessageFormat,
}

/// Where and how `validate` and `generate` report (spec §9.7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum MessageFormat {
    /// Rendered Diagnostics and status lines on stderr.
    #[default]
    Human,
    /// One JSON object per line on stdout: `diagnostic`, `file` and `summary` records.
    Json,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Validate Protocol Descriptions; write nothing.
    Validate(ValidationArgs),
    /// Validate Protocol Descriptions and write their Dissectors.
    Generate(GenerateArgs),
    /// Print the JSON Schema of Protocol Descriptions, for editor completion.
    Schema(SchemaArgs),
}

#[derive(clap::Args)]
pub(crate) struct ValidationArgs {
    /// Protocol Description files; `-` reads standard input.
    #[arg(required = true)]
    pub(crate) inputs: Vec<PathBuf>,

    /// Treat warnings as errors, so a file with warnings fails and is not written.
    #[arg(long)]
    pub(crate) deny_warnings: bool,
}

#[derive(clap::Args)]
pub(crate) struct GenerateArgs {
    #[command(flatten)]
    pub(crate) validation: ValidationArgs,

    /// Write the Dissector of the only input to this file, or to standard output for `-`.
    #[arg(short = 'o', value_name = "FILE|-", conflicts_with = "out_dir")]
    pub(crate) output: Option<PathBuf>,

    /// Write each Dissector into this directory instead of next to its input.
    #[arg(long, value_name = "DIR")]
    pub(crate) out_dir: Option<PathBuf>,

    /// Write nothing; fail if a Dissector on disk differs from what would be written.
    #[arg(long)]
    pub(crate) check: bool,
}

#[derive(clap::Args)]
pub(crate) struct SchemaArgs {
    /// Write the JSON Schema to this file instead of standard output (`-`).
    #[arg(short = 'o', value_name = "FILE|-")]
    pub(crate) output: Option<PathBuf>,
}

/// The `--color` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub(crate) enum ColorChoice {
    /// Colour when stderr is a terminal, unless `NO_COLOR` or `CLICOLOR_FORCE` says otherwise.
    #[default]
    Auto,
    /// Always colour.
    Always,
    /// Never colour.
    Never,
}
