//! Random descriptions × random and truncated packets in real tshark (spec §10.7), run only with
//! `WIRDIGEN_TSHARK=1` (`make test-tshark-random`) and meant for the weekly run: it takes
//! `PROPTEST_CASES` descriptions (the proptest default otherwise) and `PROPTEST_RNG_SEED` makes a
//! run repeatable.
//!
//! Each description from [`random`] is generated, and the Dissector sees random packets and their
//! truncations in one tshark run, over UDP or, for a description with `framing:`, TCP. As in the
//! bad-input harness (spec §10.6), the run must write nothing to stderr, raise no
//! `_ws.lua.error` or escaped exception and, over UDP, attribute every packet to the protocol.
//! A description that hands bytes to a Wireshark dissector (`dissector:`) may see that dissector
//! report a packet malformed, as Ethernet does for a few random bytes, so its packets may be.
//! A failure reports the smallest failing packet as text2pcap hex, and proptest shrinks the
//! description and prints it as YAML. `WIRDIGEN_RANDOM_PACKETS` sets the random packets per
//! description.
//!
//! The module is in-crate because the strategy is private. It fails rather than skips when
//! `tshark` or `text2pcap` is missing (spec §10.9), and runs as a non-root user since tshark
//! skips `-X lua_script` as root.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use proptest::test_runner::TestCaseError;
use serde_json::Value;

use crate::random;

/// The port decoded as the protocol under test.
const PORT: u16 = 9999;
/// The source port; above [`PORT`] so the transport tries [`PORT`] first.
const SOURCE_PORT: u16 = 40000;
/// Random packets per description when `WIRDIGEN_RANDOM_PACKETS` is unset.
const DEFAULT_PACKETS: usize = 16;
/// The longest random packet.
const MAX_LEN: usize = 256;
/// The most packets run one by one to find the smallest failing one.
const MAX_ISOLATED: usize = 128;

fn enabled() -> bool {
    std::env::var_os("WIRDIGEN_TSHARK").is_some_and(|v| v == "1")
}

/// What the packets travel over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    fn flag(self) -> &'static str {
        match self {
            Transport::Udp => "-u",
            Transport::Tcp => "-T",
        }
    }

    fn decode_as(self, proto: &str) -> String {
        match self {
            Transport::Udp => format!("udp.port=={PORT},{proto}"),
            Transport::Tcp => format!("tcp.port=={PORT},{proto}"),
        }
    }
}

/// `SplitMix64`, so that a description's packets are the same on every run.
struct Rng(u64);

impl Rng {
    /// Seeded by an FNV-1a hash of `text`, the description.
    fn of(text: &str) -> Rng {
        Rng(text
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325, |hash, byte| (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number below `bound`, which is not 0.
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("below a usize")
    }
}

/// `count` random packets and their truncations, none empty (UDP never calls a Dissector for an
/// empty payload, spec §10.5). Bytes are uniform, small (to land on lengths and counts of 0 or 1)
/// or `0xff` (to land on the largest), by packet.
fn packets(rng: &mut Rng, count: usize) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    for _ in 0..count {
        let len = 1 + rng.below(MAX_LEN);
        let mode = rng.below(3);
        let bytes: Vec<u8> = (0..len)
            .map(|_| match mode {
                0 => rng.next().to_le_bytes()[0],
                1 => rng.next().to_le_bytes()[0] % 3,
                _ => 0xff,
            })
            .collect();
        for cut in [len, len - 1, len / 2, len / 4, 1] {
            if cut > 0 && !packets.iter().any(|p: &Vec<u8>| p[..] == bytes[..cut]) {
                packets.push(bytes[..cut].to_vec());
            }
        }
    }
    packets
}

/// `bytes` as text2pcap hex, 16 bytes per offset line.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for (line, chunk) in bytes.chunks(16).enumerate() {
        write!(text, "{:04x} ", line * 16).expect("writing to a String");
        for byte in chunk {
            write!(text, " {byte:02x}").expect("writing to a String");
        }
        text.push('\n');
    }
    text
}

/// A scratch directory, also the tools' `WIRESHARK_CONFIG_DIR`, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("wirdigen-random-tshark-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("config")).unwrap();
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Runs a Wireshark tool in a fixed environment.
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

    /// Dissects `packets` with the Dissector in `lua`, one capture and one tshark run, and returns
    /// why the run fails.
    fn dissect(&self, lua: &Path, proto: &str, run: Run, packets: &[&[u8]]) -> Result<(), String> {
        let Run { transport, malformed_fails } = run;
        let text = self.path("packets.txt");
        fs::write(&text, packets.iter().map(|p| hex(p)).collect::<String>()).unwrap();
        let pcap = self.path("packets.pcapng");
        let ports = format!("{SOURCE_PORT},{PORT}");
        let output =
            self.run("text2pcap", &["-q", transport.flag(), &ports, text.to_str().unwrap(), pcap.to_str().unwrap()]);
        assert!(output.status.success(), "text2pcap failed: {}", String::from_utf8_lossy(&output.stderr));

        let script = format!("lua_script:{}", lua.display());
        let decode_as = transport.decode_as(proto);
        let output = self.run(
            "tshark",
            &["-r", pcap.to_str().unwrap(), "-X", &script, "-d", &decode_as, "-T", "json", "--no-duplicate-keys"],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            return Err(format!("tshark wrote to stderr ({}):\n{stderr}", output.status));
        }
        let captured: Vec<Value> = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("tshark's JSON is unreadable ({e}, {})", output.status))?;
        for (index, packet) in captured.iter().enumerate() {
            if let Some(error) = first_error_key(packet).filter(|key| malformed_fails || key != MALFORMED) {
                return Err(format!("packet {} has `{error}`:\n{packet:#}", index + 1));
            }
            // Over TCP, bytes held for a Message still incomplete carry no layer of the protocol.
            if transport == Transport::Udp && packet.pointer(&format!("/_source/layers/{proto}")).is_none() {
                return Err(format!("packet {} has no `{proto}` layer:\n{packet:#}", index + 1));
            }
        }
        Ok(())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The key of the expert item for a malformed packet.
const MALFORMED: &str = "_ws.malformed.expert";

/// How a run is judged.
#[derive(Debug, Clone, Copy)]
struct Run {
    transport: Transport,
    /// Whether a malformed packet fails the run: not when a Wireshark dissector may have caused it.
    malformed_fails: bool,
}

/// The first `_ws.lua.error` or `_ws.malformed.expert` key anywhere in `value`.
fn first_error_key(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => map.iter().find_map(|(key, value)| {
            if key == "_ws.lua.error" || key == MALFORMED { Some(key.clone()) } else { first_error_key(value) }
        }),
        Value::Array(values) => values.iter().find_map(first_error_key),
        _ => None,
    }
}

/// The protocol's filter name, from `Proto("<name>", …)` in the generated Dissector.
fn proto_name(lua: &str) -> &str {
    let start = lua.find("Proto(\"").expect("the Dissector creates its Proto") + "Proto(\"".len();
    let len = lua[start..].find('"').expect("the Proto name is a string literal");
    &lua[start..start + len]
}

/// Runs `packets` through the Dissector `lua` and reports the smallest failing packet: all in one
/// tshark run first, then, when that fails, the smallest packets one by one.
fn check_packets(scratch: &Scratch, lua: &str, run: Run, mut packets: Vec<Vec<u8>>) -> Result<(), String> {
    let script = scratch.path("dissector.lua");
    fs::write(&script, lua).unwrap();
    let proto = proto_name(lua);
    // Smallest first, so that the first failure is the smallest.
    packets.sort_by_key(Vec::len);
    let all: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
    let Err(reason) = scratch.dissect(&script, proto, run, &all) else {
        return Ok(());
    };
    for packet in packets.iter().take(MAX_ISOLATED) {
        if let Err(reason) = scratch.dissect(&script, proto, run, &[packet]) {
            return Err(format!(
                "the smallest failing packet, {} bytes, over {:?}:\n{}{reason}",
                packet.len(),
                run.transport,
                hex(packet)
            ));
        }
    }
    Err(format!("{} packets fail together, none of the {MAX_ISOLATED} smallest alone: {reason}", packets.len()))
}

fn packet_count() -> usize {
    match std::env::var("WIRDIGEN_RANDOM_PACKETS") {
        Ok(count) => count.parse().unwrap_or_else(|_| panic!("WIRDIGEN_RANDOM_PACKETS is not a count: {count:?}")),
        Err(_) => DEFAULT_PACKETS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_dissectors_survive_random_and_truncated_packets() {
        if !enabled() {
            return;
        }
        let count = packet_count();
        let scratch = Scratch::new("random");
        random::check(move |text| {
            let source = crate::Source::new("random.wirdigen.yaml", text);
            let lua = crate::validate(&source).map_err(|d| TestCaseError::fail(d.to_string()))?.generate();
            let transport = if text.contains("framing:") { Transport::Tcp } else { Transport::Udp };
            let run = Run { transport, malformed_fails: !text.contains("dissector:") };
            let packets = packets(&mut Rng::of(text), count);
            check_packets(&scratch, &lua, run, packets).map_err(TestCaseError::fail)
        });
    }

    const UDP: Run = Run { transport: Transport::Udp, malformed_fails: true };

    /// A Dissector that raises a Lua error on packets longer than 3 bytes.
    const FAILING_ON_LONG_PACKETS: &str = r#"
        local proto = Proto("probe", "PROBE")
        function proto.dissector(tvb, pinfo, tree)
            tree:add(proto, tvb())
            if tvb:len() > 3 then error("wirdigen harness probe") end
        end
        DissectorTable.get("udp.port"):add_for_decode_as(proto)
    "#;

    #[test]
    fn a_failing_packet_is_reported_smallest_first() {
        if !enabled() {
            return;
        }
        let scratch = Scratch::new("failing");
        let packets = vec![vec![1; 9], vec![1; 4], vec![1; 2], vec![1; 20]];
        let error = check_packets(&scratch, FAILING_ON_LONG_PACKETS, UDP, packets).unwrap_err();
        assert!(error.contains("smallest failing packet, 4 bytes"), "{error}");
        assert!(error.contains("`_ws.lua.error`"), "{error}");
    }

    #[test]
    fn a_well_behaved_dissector_passes() {
        if !enabled() {
            return;
        }
        let scratch = Scratch::new("fine");
        let lua = FAILING_ON_LONG_PACKETS.replace("> 3", "> 3000");
        check_packets(&scratch, &lua, UDP, vec![vec![1; 9], vec![1; 4]]).unwrap();
    }

    #[test]
    fn packets_are_repeatable_and_never_empty() {
        let first = packets(&mut Rng::of("a description"), 8);
        assert_eq!(first, packets(&mut Rng::of("a description"), 8));
        assert!(first.iter().all(|p| !p.is_empty() && p.len() <= MAX_LEN));
    }
}
