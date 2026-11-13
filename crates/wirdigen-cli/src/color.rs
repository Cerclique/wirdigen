//! Whether Diagnostics on stderr are coloured (spec §9.5).

use std::ffi::OsStr;

use crate::cli::ColorChoice;

/// Decides colour from the flag, then `NO_COLOR`, then `CLICOLOR_FORCE`, then the terminal.
pub(crate) fn use_color(
    choice: ColorChoice,
    no_color: Option<&OsStr>,
    clicolor_force: Option<&OsStr>,
    stderr_is_terminal: bool,
) -> bool {
    let is_set = |value: Option<&OsStr>| value.is_some_and(|v| !v.is_empty());
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto if is_set(no_color) => false,
        ColorChoice::Auto if is_set(clicolor_force) && clicolor_force != Some(OsStr::new("0")) => true,
        ColorChoice::Auto => stderr_is_terminal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decide(choice: ColorChoice, no_color: Option<&str>, force: Option<&str>, tty: bool) -> bool {
        use_color(choice, no_color.map(OsStr::new), force.map(OsStr::new), tty)
    }

    #[test]
    fn auto_follows_the_terminal() {
        assert!(decide(ColorChoice::Auto, None, None, true));
        assert!(!decide(ColorChoice::Auto, None, None, false));
    }

    #[test]
    fn explicit_flag_beats_the_environment() {
        assert!(decide(ColorChoice::Always, Some("1"), None, false));
        assert!(!decide(ColorChoice::Never, None, Some("1"), true));
    }

    #[test]
    fn no_color_turns_auto_off_even_on_a_terminal() {
        assert!(!decide(ColorChoice::Auto, Some("1"), None, true));
    }

    #[test]
    fn empty_no_color_is_ignored() {
        assert!(decide(ColorChoice::Auto, Some(""), None, true));
    }

    #[test]
    fn clicolor_force_turns_auto_on_off_a_terminal() {
        assert!(decide(ColorChoice::Auto, None, Some("1"), false));
    }

    #[test]
    fn clicolor_force_zero_or_empty_is_ignored() {
        assert!(!decide(ColorChoice::Auto, None, Some("0"), false));
        assert!(!decide(ColorChoice::Auto, None, Some(""), false));
    }

    #[test]
    fn no_color_beats_clicolor_force() {
        assert!(!decide(ColorChoice::Auto, Some("1"), Some("1"), true));
    }
}
