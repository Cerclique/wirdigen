//! Shell completions and man pages for the release archives (spec §9.1, §12.4).
//!
//! `build.rs` includes this file to write them at build time; the binary only compiles it for tests.

use std::fs;
use std::io;
use std::path::Path;

use clap_complete::Shell;

/// Writes the completion scripts of `command` into `dir/completions`, and its man pages, one per
/// subcommand, into `dir/man`.
pub(crate) fn write(mut command: clap::Command, dir: &Path) -> io::Result<()> {
    // clap's built-in `help` subcommand would otherwise get a page per subcommand it describes. It
    // must be disabled before anything builds the command, which adds it.
    let man_command = command.clone().disable_help_subcommand(true);

    let completions = dir.join("completions");
    fs::create_dir_all(&completions)?;
    let bin_name = command.get_name().to_owned();
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell, Shell::Elvish] {
        clap_complete::generate_to(shell, &mut command, &bin_name, &completions)?;
    }

    let man = dir.join("man");
    fs::create_dir_all(&man)?;
    clap_mangen::generate_to(man_command, &man)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use clap::CommandFactory;

    use crate::cli::Cli;

    fn written(dir: &Path, file: &str) -> String {
        fs::read_to_string(dir.join(file)).unwrap_or_else(|error| panic!("`{file}` not written: {error}"))
    }

    #[test]
    fn writes_a_completion_script_per_shell() {
        let dir = tempfile::tempdir().unwrap();

        super::write(Cli::command(), dir.path()).unwrap();

        for file in ["wirdigen.bash", "_wirdigen", "wirdigen.fish", "_wirdigen.ps1", "wirdigen.elv"] {
            let script = written(dir.path(), &format!("completions/{file}"));
            assert!(script.contains("deny-warnings"), "`{file}` misses `--deny-warnings`");
            assert!(script.contains("out-dir"), "`{file}` misses `--out-dir`");
        }
    }

    #[test]
    fn writes_a_man_page_for_the_command_and_each_subcommand() {
        let dir = tempfile::tempdir().unwrap();

        super::write(Cli::command(), dir.path()).unwrap();

        assert!(written(dir.path(), "man/wirdigen.1").contains("wirdigen\\-generate(1)"));
        assert!(written(dir.path(), "man/wirdigen-validate.1").contains("deny\\-warnings"));
        assert!(written(dir.path(), "man/wirdigen-generate.1").contains("out\\-dir"));
        assert!(written(dir.path(), "man/wirdigen-schema.1").contains("JSON Schema"));
    }

    #[test]
    fn writes_no_man_page_for_the_help_subcommand() {
        let dir = tempfile::tempdir().unwrap();

        super::write(Cli::command(), dir.path()).unwrap();

        let mut pages: Vec<_> =
            fs::read_dir(dir.path().join("man")).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        pages.sort();
        assert_eq!(pages, ["wirdigen-generate.1", "wirdigen-schema.1", "wirdigen-validate.1", "wirdigen.1"]);
    }
}
