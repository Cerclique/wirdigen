//! Lua checks (spec §10.4), run only with `WIRDIGEN_LUA=1` (`make test-lua`).
//!
//! Every golden Dissector and every prelude chunk must compile under the real `lua5.2`,
//! `lua5.3` and `lua5.4` interpreters, and each chunk plus its dependencies must run its top
//! level under 5.3 and 5.4 with only the standard library and inert Wireshark placeholders.
//! The source goes to the interpreter on stdin, checked by the `lua_check.lua` driver.
//! A missing or mislabelled interpreter fails the tests instead of skipping them.
//!
//! The module is in-crate because the prelude chunks are private.

use std::io::Write as _;
use std::process::{Command, Stdio};

const DRIVER: &str = include_str!("lua_check.lua");

/// A real interpreter, found on `PATH` by its Debian name.
#[derive(Debug, Clone, Copy)]
struct Lua {
    binary: &'static str,
    /// The interpreter's `_VERSION`, so a mislabelled binary cannot pass for another version.
    version: &'static str,
}

const LUA_5_2: Lua = Lua { binary: "lua5.2", version: "Lua 5.2" };
const LUA_5_3: Lua = Lua { binary: "lua5.3", version: "Lua 5.3" };
const LUA_5_4: Lua = Lua { binary: "lua5.4", version: "Lua 5.4" };

#[derive(Debug, Clone, Copy)]
enum Mode {
    /// Parse and compile without running.
    Compile,
    /// Run the top level in a strict environment.
    Run,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Compile => "compile",
            Mode::Run => "run",
        }
    }
}

/// Checks `source` with `lua`, returning the interpreter's message on failure.
///
/// # Panics
///
/// When the interpreter is missing or is not the expected version: the checks fail rather
/// than skip (spec §10.9).
fn check(lua: Lua, mode: Mode, name: &str, source: &str) -> Result<(), String> {
    let header = format!("local mode, version, name = {:?}, {:?}, {name:?}\n", mode.as_str(), lua.version);
    let mut child = Command::new(lua.binary)
        .arg("-e")
        .arg(header + DRIVER)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run `{}` ({e}); install it or unset WIRDIGEN_LUA", lua.binary));
    // The driver exits before reading stdin on a wrong interpreter, so a failed write is only
    // an error once the exit status says the source was read.
    let written = child.stdin.take().expect("stdin is piped").write_all(source.as_bytes());
    let output = child.wait_with_output().expect("the interpreter's output is readable");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    match output.status.code() {
        Some(0 | 1) if written.is_err() => panic!("cannot send the source to `{}`: {written:?}", lua.binary),
        Some(0) => Ok(()),
        Some(1) => Err(stderr),
        _ => panic!("`{}` is unusable: {} {stderr}", lua.binary, output.status),
    }
}

fn enabled() -> bool {
    std::env::var_os("WIRDIGEN_LUA").is_some_and(|v| v == "1")
}

/// Every interpreter: the whole file must parse under 5.2 so the version guard can run
/// (spec §5.4), and Wireshark ≥ 4.4 embeds 5.3 or 5.4.
const EVERY_LUA: [Lua; 3] = [LUA_5_2, LUA_5_3, LUA_5_4];
/// The interpreters of the supported Wireshark versions.
const SUPPORTED_LUA: [Lua; 2] = [LUA_5_3, LUA_5_4];

/// Checks each `(name, source)` under each interpreter and fails with every failure at once.
fn assert_all(lua: &[Lua], mode: Mode, sources: &[(String, String)]) {
    assert!(!sources.is_empty(), "nothing to check");
    let failures: Vec<String> = lua
        .iter()
        .flat_map(|&lua| {
            sources.iter().filter_map(move |(name, source)| {
                check(lua, mode, name, source).err().map(|e| format!("{} {}: {e}", lua.binary, mode.as_str()))
            })
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every golden `tests/cases/<case>/<case>.lua`.
fn goldens() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases");
    let mut goldens: Vec<(String, String)> = std::fs::read_dir(&root)
        .unwrap()
        .map(|entry| {
            let case = entry.unwrap().file_name().into_string().unwrap();
            let name = format!("{case}.lua");
            let source = std::fs::read_to_string(root.join(&case).join(&name)).unwrap();
            (name, source)
        })
        .collect();
    goldens.sort();
    goldens
}

#[cfg(test)]
mod tests {
    use proptest::test_runner::TestCaseError;

    use super::*;
    use crate::{prelude, random};

    #[test]
    fn goldens_compile_under_every_lua() {
        if enabled() {
            assert_all(&EVERY_LUA, Mode::Compile, &goldens());
        }
    }

    #[test]
    fn prelude_chunks_compile_under_every_lua() {
        if enabled() {
            let chunks: Vec<_> =
                prelude::chunk_sources().map(|(name, source)| (format!("chunk {name}"), source)).collect();
            assert_all(&EVERY_LUA, Mode::Compile, &chunks);
        }
    }

    #[test]
    fn prelude_chunks_with_their_dependencies_run_strictly() {
        if enabled() {
            let chunks: Vec<_> = prelude::chunk_sources()
                .map(|(name, _)| (format!("chunk {name}"), prelude::select(&[name]).join("\n")))
                .collect();
            assert_all(&SUPPORTED_LUA, Mode::Run, &chunks);
        }
    }

    /// The Dissector of a random valid description (spec §10.7) compiles under every Lua,
    /// as the goldens do.
    #[test]
    fn random_dissectors_compile_under_every_lua() {
        if !enabled() {
            return;
        }
        random::check(|text| {
            let source = crate::Source::new("random.wirdigen.yaml", text);
            let lua = crate::validate(&source).map_err(|d| TestCaseError::fail(d.to_string()))?.generate();
            for interpreter in EVERY_LUA {
                check(interpreter, Mode::Compile, "random.lua", &lua)
                    .map_err(|e| TestCaseError::fail(format!("{}: {e}", interpreter.binary)))?;
            }
            Ok(())
        });
    }

    #[test]
    fn a_syntax_error_does_not_compile() {
        if !enabled() {
            return;
        }
        let error = check(LUA_5_4, Mode::Compile, "broken", "local x = = 1\n").unwrap_err();
        assert!(error.contains("broken:1:"), "{error}");
    }

    #[test]
    fn floor_division_does_not_parse_under_5_2() {
        if !enabled() {
            return;
        }
        assert!(check(LUA_5_2, Mode::Compile, "floor", "local x = 7 // 2\n").is_err());
        assert!(check(LUA_5_4, Mode::Compile, "floor", "local x = 7 // 2\n").is_ok());
    }

    #[test]
    fn reading_an_undefined_global_fails_at_run() {
        if !enabled() {
            return;
        }
        let source = "local x = wd_undefined\n";
        assert!(check(LUA_5_4, Mode::Compile, "global", source).is_ok());
        let error = check(LUA_5_4, Mode::Run, "global", source).unwrap_err();
        assert!(error.contains("global:1:") && error.contains("wd_undefined"), "{error}");
    }

    #[test]
    fn wireshark_globals_are_inert_placeholders_at_run() {
        if !enabled() {
            return;
        }
        let source = r#"
            assert(string.match(get_version(), "^4%.4%."))
            local proto = Proto.new("demo", "Demo")
            proto.fields = { ProtoField.uint8("demo.id", "Id", base.DEC) }
            DissectorTable.get("udp.port"):add(4242, proto)
            local mask = bit.band(0xff, 0x0f)
        "#;
        check(LUA_5_4, Mode::Run, "wireshark", source).unwrap();
    }

    #[test]
    #[should_panic(expected = "install it or unset WIRDIGEN_LUA")]
    fn a_missing_interpreter_fails() {
        let missing = Lua { binary: "wirdigen-no-such-lua", version: "Lua 5.4" };
        let _ = check(missing, Mode::Compile, "empty", "");
    }

    #[test]
    fn a_mislabelled_interpreter_fails() {
        if !enabled() {
            return;
        }
        let mislabelled = Lua { binary: "lua5.4", version: "Lua 5.2" };
        let outcome = std::panic::catch_unwind(|| check(mislabelled, Mode::Compile, "empty", ""));
        let message = *outcome.unwrap_err().downcast::<String>().unwrap();
        assert!(message.contains("expected Lua 5.2 but this interpreter is Lua 5.4"), "{message}");
    }
}
