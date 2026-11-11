//! `assert_cmd` tests for what `trycmd` cannot see: file mtimes and colour (spec §9.3, §9.5,
//! §10.8).

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use assert_cmd::Command;
use tempfile::TempDir;

const MINIMAL: &str = "../wirdigen/tests/valid/minimal.wirdigen.yaml";
const ERRORS: &str = "../wirdigen/tests/render/several.wirdigen.yaml";

fn wirdigen() -> Command {
    let mut command = Command::cargo_bin("wirdigen").unwrap();
    command.env_remove("NO_COLOR").env_remove("CLICOLOR_FORCE");
    command
}

/// A work directory holding `minimal.wirdigen.yaml`, and the path its Dissector goes to.
fn work_dir() -> (TempDir, PathBuf) {
    let work = tempfile::tempdir().unwrap();
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join(MINIMAL);
    fs::copy(input, work.path().join("minimal.wirdigen.yaml")).unwrap();
    let output = work.path().join("minimal.lua");
    (work, output)
}

fn generate_minimal(work: &TempDir) {
    wirdigen().args(["generate", "minimal.wirdigen.yaml"]).current_dir(work.path()).assert().success();
}

fn mtime(path: &Path) -> SystemTime {
    fs::metadata(path).unwrap().modified().unwrap()
}

#[test]
fn an_identical_dissector_is_not_rewritten() {
    let (work, output) = work_dir();
    generate_minimal(&work);
    let past = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    File::options().write(true).open(&output).unwrap().set_modified(past).unwrap();

    generate_minimal(&work);

    assert_eq!(mtime(&output), past);
}

#[test]
fn a_different_dissector_is_replaced() {
    let (work, output) = work_dir();
    fs::write(&output, "-- stale\n").unwrap();

    generate_minimal(&work);

    let printed =
        wirdigen().args(["generate", "minimal.wirdigen.yaml", "-o", "-"]).current_dir(work.path()).assert().success();
    assert_eq!(fs::read(&output).unwrap(), printed.get_output().stdout);
    let mut left: Vec<_> = fs::read_dir(work.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    left.sort();
    assert_eq!(left, ["minimal.lua", "minimal.wirdigen.yaml"], "no temporary file is left behind");
}

#[test]
fn clicolor_force_colours_diagnostics_off_a_terminal() {
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join(ERRORS);
    let forced = wirdigen().arg("validate").arg(&input).env("CLICOLOR_FORCE", "1").assert().code(1);
    assert!(String::from_utf8_lossy(&forced.get_output().stderr).contains('\u{1b}'));

    let plain = wirdigen().arg("validate").arg(&input).assert().code(1);
    assert!(!String::from_utf8_lossy(&plain.get_output().stderr).contains('\u{1b}'));
}

#[cfg(unix)]
#[test]
fn a_new_dissector_gets_the_permissions_of_any_new_file() {
    use std::os::unix::fs::PermissionsExt;

    let (work, output) = work_dir();
    let plain = work.path().join("plain");
    fs::write(&plain, "").unwrap();

    generate_minimal(&work);

    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode();
    assert_eq!(mode(&output), mode(&plain));
}

#[cfg(unix)]
#[test]
fn a_symlinked_dissector_is_replaced_through_its_link() {
    let (work, output) = work_dir();
    let target = work.path().join("target.lua");
    fs::write(&target, "-- stale\n").unwrap();
    std::os::unix::fs::symlink("target.lua", &output).unwrap();

    generate_minimal(&work);

    assert!(output.is_symlink(), "the link stays in place");
    assert_ne!(fs::read(&target).unwrap(), b"-- stale\n");
}

#[test]
fn check_writes_nothing() {
    let (work, output) = work_dir();
    let check = || wirdigen().args(["generate", "--check", "minimal.wirdigen.yaml"]).current_dir(work.path()).assert();

    check().code(1);
    assert!(!output.exists(), "a missing Dissector is not created");

    fs::write(&output, "-- stale\n").unwrap();
    let past = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    File::options().write(true).open(&output).unwrap().set_modified(past).unwrap();
    check().code(1);
    assert_eq!(fs::read(&output).unwrap(), b"-- stale\n");
    assert_eq!(mtime(&output), past, "a stale Dissector is not touched");
}
