use clap::Parser;
use clap::Subcommand;

use crate::runtime::Runtime;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

#[derive(Subcommand)]
pub(crate) enum Command {
    Check {
        #[clap(
            short,
            long,
            help = "Input message description file (Supported format: JSON)"
        )]
        input_file: String,
    },
    Generate {
        #[clap(
            short,
            long,
            help = "Input message description file (Supported format: JSON)"
        )]
        input_file: String,
        #[clap(
            short,
            long,
            help = "Optional output directory for the generated dissector. If not specified, the current directory will be used"
        )]
        output_directory: Option<String>,
    },
}

#[derive(Parser)]
#[command(author = AUTHORS)]
#[command(version = VERSION)]
#[command(about = DESCRIPTION)]
#[command(long_about = DESCRIPTION)]
#[command(arg_required_else_help = true)]
pub(crate) struct CliParser {
    #[command(subcommand)]
    pub(crate) command: Command,
}

impl CliParser {
    pub(crate) fn run() -> anyhow::Result<()> {
        match Self::parse().command {
            Command::Check { input_file } => Runtime::run_check(&input_file),
            Command::Generate {
                input_file,
                output_directory,
            } => Runtime::run_generate(&input_file, output_directory),
        }
    }
}
