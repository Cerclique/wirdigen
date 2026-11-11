//! Dissector behaviour in real tshark (spec §10.5, ADR 0011), run only with `WIRDIGEN_TSHARK=1`
//! (`make test-tshark`). A missing `tshark` or `text2pcap` fails the tests instead of skipping them.
//!
//! A corpus case may carry `packets.txt`: text2pcap hex, one commented packet per offset-0 line
//! run. The harness wraps each packet in UDP to [`PORT`], loads the golden `<case>.lua` with
//! `-X lua_script`, decodes [`PORT`] as the protocol (Decode As) and cuts tshark's `-T json`
//! output down to the protocol's own layer, which must match `dissected.json`. A case of
//! [`BY_DECLARED_PORT`] declares [`PORT`] itself and is decoded without Decode As.
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
//!
//! The Info column is not in the protocol's layer. A case that carries `info.txt` also checks it
//! (spec §3.14): one line per packet, the column as tshark's `_ws.col.info` field gives it.
//! `WIRDIGEN_BLESS=1` rewrites it too.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

#[path = "tshark/bad_input.rs"]
mod bad_input;

/// The UDP destination port decoded as the protocol under test.
const PORT: u16 = 9999;
/// The UDP source port; above [`PORT`] so UDP tries [`PORT`] first.
const SOURCE_PORT: u16 = 40000;

/// The cases that declare [`PORT`] under `registration:`, decoded by it without Decode As.
const BY_DECLARED_PORT: [&str; 1] = ["registration"];

/// How the harness wraps each packet: text2pcap's flag for it.
#[derive(Debug, Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    fn text2pcap_flag(self) -> &'static str {
        match self {
            Transport::Udp => "-u",
            Transport::Tcp => "-T",
        }
    }
}

fn enabled() -> bool {
    std::env::var_os("WIRDIGEN_TSHARK").is_some_and(|v| v == "1")
}

/// Whether expectations are rewritten from tshark's output (`WIRDIGEN_BLESS=1`).
fn blessing() -> bool {
    std::env::var_os("WIRDIGEN_BLESS").is_some_and(|v| v == "1")
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
        self.capture_over(Transport::Udp, PORT, packets)
    }

    /// Turns text2pcap hex into a capture of `transport` packets to `port`.
    fn capture_over(&self, transport: Transport, port: u16, packets: &Path) -> PathBuf {
        let pcap = self.path("packets.pcapng");
        let ports = format!("{SOURCE_PORT},{port}");
        let flag = transport.text2pcap_flag();
        let output = self.run("text2pcap", &["-q", flag, &ports, path_str(packets), path_str(&pcap)]);
        assert!(output.status.success(), "text2pcap failed: {}", String::from_utf8_lossy(&output.stderr));
        pcap
    }

    /// Dissects `pcap` with the Dissector in `lua`, decoding UDP [`PORT`] as `proto`, and returns
    /// each packet's `proto` layer, or why the run is unusable.
    fn dissect(&self, lua: &Path, proto: &str, pcap: &Path) -> Result<Vec<Value>, String> {
        let decode_as = format!("udp.port=={PORT},{proto}");
        self.dissect_with(lua, proto, pcap, &["-d", &decode_as])
    }

    /// Dissects `pcap` with the Dissector in `lua` and tshark's extra `options`, and returns
    /// each packet's `proto` layer, or why the run is unusable.
    fn dissect_with(&self, lua: &Path, proto: &str, pcap: &Path, options: &[&str]) -> Result<Vec<Value>, String> {
        let packets = self.tshark_json(lua, pcap, options)?;
        packets.iter().enumerate().map(|(index, packet)| own_layer(packet, index + 1, proto)).collect()
    }

    /// Dissects `pcap` with the Dissector in `lua` and tshark's extra `options`, and returns
    /// tshark's `-T json` packets, or why the run is unusable: anything on stderr, or unreadable
    /// JSON.
    fn tshark_json(&self, lua: &Path, pcap: &Path, options: &[&str]) -> Result<Vec<Value>, String> {
        let script = format!("lua_script:{}", path_str(lua));
        let mut args = vec!["-r", path_str(pcap), "-X", &script];
        args.extend(options);
        args.extend(["-T", "json", "--no-duplicate-keys"]);
        let output = self.run("tshark", &args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            return Err(format!("tshark wrote to stderr ({}):\n{stderr}", output.status));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("tshark's JSON is unreadable ({e}, {})", output.status))
    }

    /// Dissects `pcap` with the Dissector in `lua` and tshark's extra `options`, and returns the
    /// Info column of each packet, one line each.
    fn info_column(&self, lua: &Path, pcap: &Path, options: &[&str]) -> Result<String, String> {
        let script = format!("lua_script:{}", path_str(lua));
        let mut args = vec!["-r", path_str(pcap), "-X", &script];
        args.extend(options);
        args.extend(["-T", "fields", "-e", "_ws.col.info"]);
        let output = self.run("tshark", &args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            return Err(format!("tshark wrote to stderr ({}):\n{stderr}", output.status));
        }
        String::from_utf8(output.stdout).map_err(|e| format!("tshark's Info column is not UTF-8 ({e})"))
    }

    /// The running tshark's full version, such as `4.6.9`, from `TShark (Wireshark) 4.6.9.`.
    fn tshark_full_version(&self) -> String {
        let output = self.run("tshark", &["--version"]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.split_whitespace().nth(2).unwrap_or_default().trim_end_matches('.').to_owned()
    }

    /// The running tshark's `major.minor`.
    fn tshark_version(&self) -> String {
        let version = self.tshark_full_version();
        let mut parts = version.split('.');
        match (parts.next(), parts.next()) {
            (Some(major), Some(minor)) if !major.is_empty() => format!("{major}.{minor}"),
            _ => panic!("cannot read the tshark version from {version:?}"),
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

/// The `proto` layer of `packet`, packet `number` of its capture, or why the packet is
/// unusable: a Lua error or an escaped exception anywhere in it, or no `proto` layer.
fn own_layer(packet: &Value, number: usize, proto: &str) -> Result<Value, String> {
    if let Some(error) = first_error_key(packet) {
        return Err(format!("packet {number} has `{error}`:\n{packet:#}"));
    }
    packet
        .pointer(&format!("/_source/layers/{proto}"))
        .cloned()
        .ok_or_else(|| format!("packet {number} has no `{proto}` layer:\n{packet:#}"))
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

/// tshark's options decoding the case's packets as `proto`: Decode As, unless the case is one of
/// [`BY_DECLARED_PORT`].
fn case_options(case: &str, proto: &str) -> Vec<String> {
    if BY_DECLARED_PORT.contains(&case) {
        Vec::new()
    } else {
        vec!["-d".to_owned(), format!("udp.port=={PORT},{proto}")]
    }
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
    let options = case_options(case, proto);
    let options: Vec<&str> = options.iter().map(String::as_str).collect();
    let options = options.as_slice();
    let layers = scratch.dissect_with(&lua, proto, &pcap, options);
    let layers = layers.unwrap_or_else(|e| panic!("{case}: {e}"));
    assert_eq!(layers.len(), expected_count, "{case}: tshark dissected a different number of packets");

    let actual = serde_json::to_string_pretty(&layers).unwrap() + "\n";
    let golden = expectation(&dir, &scratch);
    if blessing() {
        fs::write(&golden, &actual).unwrap();
    }
    let expected = fs::read_to_string(&golden)
        .unwrap_or_else(|_| panic!("{} is missing: bless it. tshark produced:\n{actual}", golden.display()));
    assert_eq!(actual, expected, "{case}: tshark's dissection differs from {}", golden.display());

    let info = dir.join("info.txt");
    if info.exists() {
        let actual = scratch.info_column(&lua, &pcap, options).unwrap_or_else(|e| panic!("{case}: {e}"));
        if blessing() {
            fs::write(&info, &actual).unwrap();
        }
        let expected = fs::read_to_string(&info).unwrap();
        assert_eq!(actual, expected, "{case}: tshark's Info column differs from {}", info.display());
    }
}

macro_rules! cases {
    ($($test:ident => $case:literal),* $(,)?) => {
        $(#[test] fn $test() { check($case); })*

        /// The case's Dissector never raises a Lua error on bad input (spec §5.3, §10.6).
        mod bad_packets {
            $(#[test] fn $test() { super::bad_input::check($case); })*
        }

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
    bitfields => "bitfields",
    bitfield_references => "bitfield-references",
    arrays => "arrays",
    conditionals => "conditionals",
    switch => "switch",
    hidden => "hidden",
    padding => "padding",
    expect => "expect",
    handoff => "handoff",
    registration => "registration",
    info => "info",
    info_default => "info-default",
    info_empty => "info-empty",
}

/// Registration (spec §3.12): the declared ports follow their range preferences, and TCP ports
/// are claimed like UDP ones. The `registration` case declares UDP [`PORT`] and TCP
/// [`TCP_PORT`].
mod registration {
    use super::*;

    /// The TCP port the `registration` case declares.
    const TCP_PORT: u16 = 9998;

    /// Dissects the `registration` corpus packets, sent over `transport` to `port`, with
    /// tshark's extra `options` and no Decode As.
    fn dissect(name: &str, transport: Transport, port: u16, options: &[&str]) -> Result<Vec<Value>, String> {
        let dir = case_dir("registration");
        let scratch = Scratch::new(name);
        let pcap = scratch.capture_over(transport, port, &dir.join("packets.txt"));
        scratch.dissect_with(&dir.join("registration.lua"), "registration", &pcap, options)
    }

    #[test]
    fn a_declared_tcp_port_is_claimed() {
        if !enabled() {
            return;
        }
        dissect("tcp", Transport::Tcp, TCP_PORT, &[]).unwrap();
    }

    #[test]
    fn a_port_inside_a_declared_range_is_claimed() {
        if !enabled() {
            return;
        }
        dissect("range", Transport::Udp, 6005, &[]).unwrap();
    }

    #[test]
    fn a_changed_preference_releases_the_old_ports() {
        if !enabled() {
            return;
        }
        let error = dissect("moved-away", Transport::Udp, PORT, &["-o", "registration.udp_ports:1234"]).unwrap_err();
        assert!(error.contains("packet 1 has no `registration` layer"), "{error}");
    }

    #[test]
    fn a_changed_preference_claims_the_new_ports() {
        if !enabled() {
            return;
        }
        let undeclared = dissect("undeclared", Transport::Tcp, PORT, &[]).unwrap_err();
        assert!(undeclared.contains("packet 1 has no `registration` layer"), "{undeclared}");
        let ports = format!("registration.tcp_ports:{PORT}");
        dissect("moved-to", Transport::Tcp, PORT, &["-o", &ports]).unwrap();
    }
}

/// The snapshot of Wireshark's built-in protocols behind `protocol-name-taken` (spec §3.3,
/// §10.9), `src/builtin_protocols.tsv`, must match the latest stable tshark.
///
/// A tshark older than the snapshot's (the 4.4 floor) is not compared. The same version must
/// list the same protocols; a newer one means the snapshot is out of date. `WIRDIGEN_BLESS=1`
/// rewrites it (`make docker-refresh-protocols`).
mod builtin_protocols {
    use super::*;

    fn snapshot_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/builtin_protocols.tsv")
    }

    /// The snapshot's first line, before its version.
    const HEADER: &str = "# tshark -G protocols, Wireshark ";

    /// A `major.minor.patch` version, as numbers so that 4.10 sorts after 4.9.
    fn parse_version(text: &str) -> [u32; 3] {
        let parts: Option<Vec<u32>> = text.split('.').map(|p| p.parse().ok()).collect();
        parts.and_then(|p| p.try_into().ok()).unwrap_or_else(|| panic!("cannot read a version from {text:?}"))
    }

    /// The Wireshark version in the snapshot's header.
    fn snapshot_version(snapshot: &str) -> &str {
        let header = snapshot.lines().next().unwrap_or_default();
        let rest = header.strip_prefix(HEADER).unwrap_or_else(|| panic!("unexpected snapshot header {header:?}"));
        rest.split(':').next().unwrap_or_default()
    }

    /// The snapshot `tshark -G protocols` gives: a header with the version, then the full name,
    /// short name and filter name of each protocol.
    fn render(version: &str, protocols: &str) -> String {
        let mut snapshot = format!("{HEADER}{version}: full name, short name, filter name\n");
        for line in protocols.lines() {
            let columns: Vec<&str> = line.split('\t').take(3).collect();
            assert_eq!(columns.len(), 3, "unexpected `tshark -G protocols` line {line:?}");
            snapshot.push_str(&columns.join("\t"));
            snapshot.push('\n');
        }
        snapshot
    }

    #[test]
    fn the_snapshot_is_current() {
        if !enabled() {
            return;
        }
        let scratch = Scratch::new("builtin-protocols");
        let version = scratch.tshark_full_version();
        let path = snapshot_path();
        let committed = fs::read_to_string(&path).unwrap();
        if parse_version(&version) < parse_version(snapshot_version(&committed)) {
            return;
        }
        let output = scratch.run("tshark", &["-G", "protocols"]);
        assert!(output.status.success(), "tshark -G protocols failed: {}", String::from_utf8_lossy(&output.stderr));
        let actual = render(&version, &String::from_utf8(output.stdout).unwrap());
        if blessing() {
            fs::write(&path, &actual).unwrap();
            return;
        }
        // Not assert_eq!, which would print both 3000-line snapshots.
        assert!(
            actual == committed,
            "{} is out of date for Wireshark {version}: run `make docker-refresh-protocols`",
            path.display()
        );
    }

    #[test]
    fn versions_compare_as_numbers() {
        assert!(parse_version("4.10.0") > parse_version("4.9.2"));
        assert_eq!(parse_version("4.6.9"), [4, 6, 9]);
    }

    #[test]
    fn the_snapshot_keeps_three_columns_under_a_versioned_header() {
        let protocols = "29West Protocol\t29West\t29west\tT\tT\tT\n";
        let snapshot = render("4.6.9", protocols);
        assert_eq!(snapshot_version(&snapshot), "4.6.9");
        assert_eq!(snapshot.lines().nth(1), Some("29West Protocol\t29West\t29west"));
    }

    #[test]
    fn the_committed_snapshot_has_a_version() {
        parse_version(snapshot_version(&fs::read_to_string(snapshot_path()).unwrap()));
    }
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

    /// Runs the bad-input harness over the `uints` corpus packets with `lua` in place of the
    /// golden Dissector.
    fn bad_uints_with(name: &str, lua: &str) -> Result<(), String> {
        let scratch = Scratch::new(name);
        let script = scratch.path("dissector.lua");
        fs::write(&script, lua).unwrap();
        let valid = bad_input::parse_packets(&fs::read_to_string(case_dir("uints").join("packets.txt")).unwrap());
        let config = bad_input::Config { seed: 42, mutations: 4, random: 2 };
        let decode_as = format!("udp.port=={PORT},uints");
        let target =
            bad_input::Target { scratch: &scratch, lua: &script, proto: "uints", options: &["-d", &decode_as] };
        target.run(&valid, &config)
    }

    /// A Dissector that misbehaves, through `misbehave()`, on packets longer than 3 bytes.
    fn misbehaving_on_long_packets(misbehave: &str) -> String {
        format!(
            r#"
            local proto = Proto("uints", "UINTS")
            function proto.dissector(tvb, pinfo, tree)
                tree:add(proto, tvb())
                if tvb:len() > 3 then {misbehave} end
            end
            DissectorTable.get("udp.port"):add_for_decode_as(proto)
            "#
        )
    }

    #[test]
    fn a_bad_packet_raising_a_lua_error_is_reported_smallest_first_with_the_seed() {
        if !enabled() {
            return;
        }
        let error = bad_uints_with("bad-error", &misbehaving_on_long_packets(r#"error("wirdigen harness probe")"#))
            .unwrap_err();
        assert!(error.contains("WIRDIGEN_BAD_SEED=42"), "{error}");
        assert!(error.contains("smallest, 4 bytes"), "{error}");
        assert!(error.contains("`_ws.lua.error`"), "{error}");
    }

    #[test]
    fn a_bad_packet_writing_to_stderr_is_reported_smallest_first_with_the_seed() {
        if !enabled() {
            return;
        }
        let error =
            bad_uints_with("bad-stderr", &misbehaving_on_long_packets(r#"io.stderr:write("probe\n")"#)).unwrap_err();
        assert!(error.contains("WIRDIGEN_BAD_SEED=42"), "{error}");
        assert!(error.contains("smallest, 4 bytes"), "{error}");
        assert!(error.contains("probe"), "{error}");
    }

    #[test]
    fn well_behaved_bad_packets_pass() {
        if !enabled() {
            return;
        }
        bad_uints_with("bad-fine", &misbehaving_on_long_packets("")).unwrap();
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
