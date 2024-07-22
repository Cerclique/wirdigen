use anyhow::bail;

use crate::cli_parser::CliParser;

mod cli_parser;
mod error;
mod file_format;
mod runtime;

fn main() -> anyhow::Result<()> {
    if let Err(e) = CliParser::run() {
        bail!(e);
    } else {
        Ok(())
    }
}
