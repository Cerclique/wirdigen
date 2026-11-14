//! `assert_cmd` tests for what `trycmd` cannot see: file mtimes and colour (spec §9.3, §9.5,
//! §10.8).

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use assert_cmd::Command;
use tempfile::TempDir;

const MINIMAL: &str = "../wirdigen/tests/valid/minimal.wirdigen.yaml";
const ERRORS: &str = "../wirdigen/tests/render/several.wirdigen.yaml";
const WARNINGS: &str = "../wirdigen/tests/diagnostics/unused-type/unused.wirdigen.yaml";

fn wirdigen() -> Command {
    let mut command = Command::cargo_bin("wirdigen").expect("cargo builds the `wirdigen` binary for integration tests");
    command.env_remove("NO_COLOR").env_remove("CLICOLOR_FORCE");
    command
}

/// A work directory holding `minimal.wirdigen.yaml`, and the path its Dissector goes to.
fn work_dir() -> (TempDir, PathBuf) {
    let work = tempfile::tempdir().expect("the system temp directory is writable");
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join(MINIMAL);
    fs::copy(input, work.path().join("minimal.wirdigen.yaml"))
        .expect("the minimal corpus case exists and the work dir is writable");
    let output = work.path().join("minimal.lua");
    (work, output)
}

fn generate_minimal(work: &TempDir) {
    wirdigen().args(["generate", "minimal.wirdigen.yaml"]).current_dir(work.path()).assert().success();
}

/// The Dissector `generate -o -` prints for `minimal.wirdigen.yaml`.
fn minimal_dissector(work: &TempDir) -> Vec<u8> {
    let printed =
        wirdigen().args(["generate", "minimal.wirdigen.yaml", "-o", "-"]).current_dir(work.path()).assert().success();
    printed.get_output().stdout.clone()
}

fn mtime(path: &Path) -> SystemTime {
    fs::metadata(path).and_then(|m| m.modified()).expect("the file exists and the platform records mtimes")
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

    assert_eq!(fs::read(&output).unwrap(), minimal_dissector(&work));
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

#[cfg(unix)]
#[test]
fn a_dangling_symlink_gets_its_target_created() {
    let (work, output) = work_dir();
    fs::create_dir(work.path().join("sub")).unwrap();
    let link = work.path().join("sub/out.lua");
    std::os::unix::fs::symlink("../gen/target.lua", &link).unwrap();

    wirdigen()
        .args(["generate", "-o", "sub/out.lua", "minimal.wirdigen.yaml"])
        .current_dir(work.path())
        .assert()
        .success();

    assert!(link.is_symlink(), "the link stays in place");
    assert_eq!(fs::read(work.path().join("gen/target.lua")).unwrap(), minimal_dissector(&work));
    assert!(!output.exists());
}

#[cfg(unix)]
#[test]
fn a_chain_of_symlinks_is_followed_to_its_missing_end() {
    let (work, output) = work_dir();
    let middle = work.path().join("middle.lua");
    let end = work.path().join("end.lua");
    std::os::unix::fs::symlink("middle.lua", &output).unwrap();
    std::os::unix::fs::symlink(&end, &middle).unwrap();

    generate_minimal(&work);

    assert!(output.is_symlink() && middle.is_symlink(), "both links stay in place");
    assert_eq!(fs::read(&end).unwrap(), minimal_dissector(&work));
}

#[cfg(unix)]
#[test]
fn a_symlink_loop_cannot_be_written() {
    let (work, output) = work_dir();
    std::os::unix::fs::symlink("other.lua", &output).unwrap();
    std::os::unix::fs::symlink("minimal.lua", work.path().join("other.lua")).unwrap();

    let failed = wirdigen()
        .args(["generate", "minimal.wirdigen.yaml"])
        .current_dir(work.path())
        .timeout(Duration::from_secs(10))
        .assert()
        .code(1);

    let stderr = String::from_utf8_lossy(&failed.get_output().stderr);
    assert!(stderr.contains("cannot write `minimal.lua`"), "{stderr}");
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

#[test]
fn deny_warnings_does_not_write_a_warnings_only_dissector() {
    let work = tempfile::tempdir().unwrap();
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join(WARNINGS);
    fs::copy(input, work.path().join("unused.wirdigen.yaml")).unwrap();
    let output = work.path().join("unused.lua");
    let generate = |deny: &[&str]| {
        wirdigen().arg("generate").args(deny).arg("unused.wirdigen.yaml").current_dir(work.path()).assert()
    };

    generate(&["--deny-warnings"]).code(1);
    assert!(!output.exists(), "a denied warning fails the file");

    generate(&[]).success();
    assert!(output.exists(), "without the flag, warnings do not stop the write");
}
