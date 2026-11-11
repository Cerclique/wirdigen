//! `wirdigen schema [-o <file>]` (spec §9.1): the library's JSON Schema, on stdout or in a file.

use std::fs;

use assert_cmd::Command;

fn wirdigen() -> Command {
    Command::cargo_bin("wirdigen").unwrap()
}

#[test]
fn schema_prints_the_json_schema() {
    wirdigen().arg("schema").assert().success().stdout(wirdigen::json_schema()).stderr("");
}

#[test]
fn schema_writes_the_json_schema_to_a_file() {
    let work = tempfile::tempdir().unwrap();
    let output = work.path().join("nested/wirdigen.schema.json");

    wirdigen().args(["schema", "-o"]).arg(&output).assert().success().stdout("").stderr("");

    assert_eq!(fs::read_to_string(output).unwrap(), wirdigen::json_schema());
}

#[test]
fn schema_to_dash_prints_it() {
    wirdigen().args(["schema", "-o", "-"]).assert().success().stdout(wirdigen::json_schema());
}

#[test]
fn an_unwritable_schema_file_fails_with_code_1() {
    let work = tempfile::tempdir().unwrap();
    let blocker = work.path().join("file");
    fs::write(&blocker, "").unwrap();

    let assert = wirdigen().args(["schema", "-o"]).arg(blocker.join("schema.json")).assert().code(1).stdout("");

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(stderr.starts_with("error: cannot write `"), "{stderr}");
}
