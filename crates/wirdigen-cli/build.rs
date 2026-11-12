//! Generates shell completions and man pages into `$OUT_DIR/completions` and `$OUT_DIR/man`, from
//! the same clap definitions the binary parses (spec §9.1). The release workflow packs them into
//! the archives; there is no runtime subcommand for them.

#[expect(dead_code, reason = "the binary reads the parsed fields; the build script only needs the command's shape")]
#[path = "src/cli.rs"]
mod cli;

#[path = "src/assets.rs"]
mod assets;

use std::env;
use std::path::PathBuf;

use clap::CommandFactory;

fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=src/cli.rs");
    println!("cargo::rerun-if-changed=src/assets.rs");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR for build scripts"));
    assets::write(cli::Cli::command(), &out_dir)
}
