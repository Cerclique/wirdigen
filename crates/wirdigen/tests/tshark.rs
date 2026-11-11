//! Dissector behaviour in real tshark (spec §10.5, ADR 0011), run only with `WIRDIGEN_TSHARK=1`
//! (`make test-tshark`). A missing `tshark` or `text2pcap` fails the tests instead of skipping them.
//!
//! A corpus case may carry `packets.txt`: text2pcap hex, one commented packet per offset-0 line
//! run. The harness wraps each packet in UDP to [`PORT`], loads the golden `<case>.lua` with
//! `-X lua_script`, decodes [`PORT`] as the protocol (Decode As) and cuts tshark's `-T json`
//! output down to the protocol's own layer, which must match `dissected.json`.
//!
//! tshark exits 0 when a Lua script fails to load, and as root it skips the script with only a
//! warning, so success is never judged from the exit status. It is judged from stderr, which
//! must be empty, from `_ws.lua.error` and `_ws.malformed.expert` items anywhere in a packet,
//! and from every packet carrying the protocol's layer. tshark runs without `-J`, which could hide a
//! top-level `_ws.lua.error`; the cut to the protocol's layer is made here instead.
//!
//! Both supported Wireshark versions must produce the same `dissected.json`. A version-specific
//! expectation is a documented exception: `dissected-<major>.<minor>.json` next to it, used only
//! by that tshark version. `WIRDIGEN_BLESS=1` rewrites the file in use.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

/// The UDP destination port decoded as the protocol under test.
const PORT: u16 = 9999;
/// The UDP source port; above [`PORT`] so UDP tries [`PORT`] first.
const SOURCE_PORT: u16 = 40000;

fn enabled() -> bool {
    std::env::var_os("WIRDIGEN_TSHARK").is_some_and(|v| v == "1")
}

/// A per-test scratch directory, also the tools' `WIRESHARK_CONFIG_DIR`, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("wirdigen-tshark-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("config")).unwrap();
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Runs a Wireshark tool in the harness's fixed environment.
    ///
    /// # Panics
    ///
    /// When the tool cannot be started: the tests fail rather than skip (spec §10.9).
    fn run(&self, program: &str, args: &[&str]) -> Output {
        Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .env("WIRESHARK_CONFIG_DIR", self.path("config"))
            .output()
            .unwrap_or_else(|e| panic!("cannot run `{program}` ({e}); install it or unset WIRDIGEN_TSHARK"))
    }

    /// Turns text2pcap hex into a capture of UDP packets to [`PORT`].
    fn capture(&self, packets: &Path) -> PathBuf {
        let pcap = self.path("packets.pcapng");
        let ports = format!("{SOURCE_PORT},{PORT}");
        let output = self.run("text2pcap", &["-q", "-u", &ports, path_str(packets), path_str(&pcap)]);
        assert!(output.status.success(), "text2pcap failed: {}", String::from_utf8_lossy(&output.stderr));
        pcap
    }

    /// Dissects `pcap` with the Dissector in `lua` and returns each packet's `proto` layer, or
    /// why the run is unusable.
    fn dissect(&self, lua: &Path, proto: &str, pcap: &Path) -> Result<Vec<Value>, String> {
        let script = format!("lua_script:{}", path_str(lua));
        let decode_as = format!("udp.port=={PORT},{proto}");
        let output = self.run(
            "tshark",
            &["-r", path_str(pcap), "-X", &script, "-d", &decode_as, "-T", "json", "--no-duplicate-keys"],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            return Err(format!("tshark wrote to stderr ({}):\n{stderr}", output.status));
        }
        let packets: Vec<Value> = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("tshark's JSON is unreadable ({e}, {})", output.status))?;
        packets
            .iter()
            .enumerate()
            .map(|(index, packet)| {
                let number = index + 1;
                if let Some(error) = first_error_key(packet) {
                    return Err(format!("packet {number} has `{error}`:\n{packet:#}"));
                }
                packet
                    .pointer(&format!("/_source/layers/{proto}"))
                    .cloned()
                    .ok_or_else(|| format!("packet {number} has no `{proto}` layer:\n{packet:#}"))
            })
            .collect()
    }

    /// The running tshark's `major.minor`.
    fn tshark_version(&self) -> String {
        let output = self.run("tshark", &["--version"]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let version = stdout.split_whitespace().nth(2).unwrap_or_default();
        let mut parts = version.split('.');
        match (parts.next(), parts.next()) {
            (Some(major), Some(minor)) if !major.is_empty() => format!("{major}.{minor}"),
            _ => panic!("cannot read the tshark version from {stdout:?}"),
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("test paths are UTF-8")
}

/// The first key naming a Lua error or a malformed-packet exception, anywhere in `value`.
/// Not errors: `_ws.lua.fake`, on every packet once a Lua script is loaded, and a bare
/// `_ws.malformed`, which Wireshark adds beside every expert info in the MALFORMED group (our
/// truncation report). An exception escaping a dissector adds `_ws.malformed.expert`.
fn first_error_key(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => map.iter().find_map(|(key, value)| {
            if key == "_ws.lua.error" || key == "_ws.malformed.expert" {
                Some(key.clone())
            } else {
                first_error_key(value)
            }
        }),
        Value::Array(values) => values.iter().find_map(first_error_key),
        _ => None,
    }
}

/// The number of packets in text2pcap hex: a packet starts at each offset-0 line.
fn packet_count(packets: &str) -> usize {
    packets
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|token| !token.starts_with('#') && token.chars().all(|c| c.is_ascii_hexdigit()))
        .filter(|offset| offset.chars().all(|c| c == '0'))
        .count()
}

/// The protocol's filter name, from `Proto("<name>", …)` in the generated Dissector.
fn proto_name(lua: &str) -> &str {
    let start = lua.find("Proto(\"").expect("the Dissector creates its Proto") + "Proto(\"".len();
    let len = lua[start..].find('"').expect("the Proto name is a string literal");
    &lua[start..start + len]
}

fn case_dir(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases").join(case)
}

/// `dissected.json`, or the documented `dissected-<major>.<minor>.json` exception for this tshark.
fn expectation(dir: &Path, scratch: &Scratch) -> PathBuf {
    let has_exception =
        fs::read_dir(dir).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with("dissected-"));
    if has_exception {
        let specific = dir.join(format!("dissected-{}.json", scratch.tshark_version()));
        if specific.exists() {
            return specific;
        }
    }
    dir.join("dissected.json")
}

fn check(case: &str) {
    if !enabled() {
        return;
    }
    let dir = case_dir(case);
    let lua = dir.join(format!("{case}.lua"));
    let source = fs::read_to_string(&lua).unwrap();
    let proto = proto_name(&source);
    let packets = dir.join("packets.txt");
    let expected_count = packet_count(&fs::read_to_string(&packets).unwrap());
    assert!(expected_count > 0, "{}: no packets", packets.display());

    let scratch = Scratch::new(case);
    let pcap = scratch.capture(&packets);
    let layers = scratch.dissect(&lua, proto, &pcap).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert_eq!(layers.len(), expected_count, "{case}: tshark dissected a different number of packets");

    let actual = serde_json::to_string_pretty(&layers).unwrap() + "\n";
    let golden = expectation(&dir, &scratch);
    if std::env::var_os("WIRDIGEN_BLESS").is_some_and(|v| v == "1") {
        fs::write(&golden, &actual).unwrap();
    }
    let expected = fs::read_to_string(&golden)
        .unwrap_or_else(|_| panic!("{} is missing: bless it. tshark produced:\n{actual}", golden.display()));
    assert_eq!(actual, expected, "{case}: tshark's dissection differs from {}", golden.display());
}

macro_rules! cases {
    ($($test:ident => $case:literal),* $(,)?) => {
        $(#[test] fn $test() { check($case); })*

        #[test]
        fn every_case_with_packets_has_a_test() {
            let tested = [$($case),*];
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases");
            for entry in fs::read_dir(root).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().into_string().unwrap();
                let has_packets = entry.path().join("packets.txt").exists();
                assert_eq!(has_packets, tested.contains(&name.as_str()), "tests/cases/{name}: packets.txt and its tshark test go together");
            }
        }
    };
}

cases! {
    uints => "uints",
    lua_keywords => "lua-keywords",
    integers => "integers",
    fixed_types => "fixed-types",
    endian => "endian",
    display => "display",
    tree_text => "tree-text",
    strings => "strings",
    bytes => "bytes",
    prefixes => "prefixes",
    timestamps => "timestamps",
    timestamps_le => "timestamps-le",
    values => "values",
    structures => "structures",
    types => "types",
    expressions => "expressions",
    references => "references",
    runtime => "runtime",
}

/// A Dissector that cannot be trusted must fail the run, whatever tshark's exit status says.
mod harness {
    use super::*;

    /// Dissects the `uints` corpus packets with `lua` in place of the golden Dissector.
    fn dissect_uints_with(name: &str, lua: &str) -> Result<Vec<Value>, String> {
        let scratch = Scratch::new(name);
        let script = scratch.path("dissector.lua");
        fs::write(&script, lua).unwrap();
        let pcap = scratch.capture(&case_dir("uints").join("packets.txt"));
        scratch.dissect(&script, "uints", &pcap)
    }

    #[test]
    fn a_lua_load_error_fails() {
        if !enabled() {
            return;
        }
        let error = dissect_uints_with("load-error", "local x = = 1\n").unwrap_err();
        assert!(error.contains("dissector.lua"), "{error}");
    }

    #[test]
    fn a_lua_error_while_dissecting_fails() {
        if !enabled() {
            return;
        }
        let lua = r#"
            local proto = Proto("uints", "UINTS")
            function proto.dissector(tvb, pinfo, tree)
                tree:add(proto, tvb())
                error("wirdigen harness probe")
            end
            DissectorTable.get("udp.port"):add_for_decode_as(proto)
        "#;
        let error = dissect_uints_with("dissect-error", lua).unwrap_err();
        assert!(error.contains("`_ws.lua.error`"), "{error}");
    }

    #[test]
    fn a_packet_without_the_protocol_fails() {
        if !enabled() {
            return;
        }
        let lua = r#"
            local proto = Proto("uints", "UINTS")
            function proto.dissector(tvb, pinfo, tree)
                return 0
            end
            DissectorTable.get("udp.port"):add_for_decode_as(proto)
        "#;
        let error = dissect_uints_with("rejecting-dissector", lua).unwrap_err();
        assert!(error.contains("packet 1 has no `uints` layer"), "{error}");
    }

    #[test]
    #[should_panic(expected = "install it or unset WIRDIGEN_TSHARK")]
    fn a_missing_tool_fails() {
        let _ = Scratch::new("missing-tool").run("wirdigen-no-such-tshark", &["--version"]);
    }

    #[test]
    fn packets_start_at_each_offset_zero_line() {
        let text = "# one\n0000  01 02\n0010  03\n# two, # 0000 in a comment\n000000 04\n\n";
        assert_eq!(packet_count(text), 2);
    }

    #[test]
    fn errors_are_found_at_any_depth() {
        let packet = serde_json::json!({ "_source": { "layers": { "uints": { "_ws.lua.error": "" } } } });
        assert_eq!(first_error_key(&packet).as_deref(), Some("_ws.lua.error"));
        let exception = serde_json::json!({ "_ws.malformed": { "_ws.malformed.expert": "" } });
        assert_eq!(first_error_key(&exception).as_deref(), Some("_ws.malformed.expert"));
        let fine = serde_json::json!({
            "_ws.lua.fake": "",
            "uints": { "uints.small": "1", "_ws.malformed": "Malformed Packet" }
        });
        assert_eq!(first_error_key(&fine), None);
    }
}
