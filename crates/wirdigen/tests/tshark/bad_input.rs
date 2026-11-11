//! Bad input (spec §5.3, §10.6): the promise that a generated Dissector never raises a Lua
//! error, whatever the packet.
//!
//! From each valid packet of a case's `packets.txt`, the harness derives every truncation and
//! seeded mutations (bit flips, a length or count set to 0, max or huge, inserted or removed
//! bytes, garbage), and adds a few random packets. They all go into one capture and one tshark
//! run per case, which must write nothing to stderr, raise no `_ws.lua.error` or escaped
//! exception, and attribute every packet to the protocol. A failure reports the seed and the
//! smallest failing packet, as text2pcap hex ready to become a `packets.txt` regression.
//!
//! TCP cases (spec §3.13) are also re-split at random segment boundaries: their valid packets,
//! as one stream cut at random places, must dissect into the same Messages as
//! `dissected.json`, and each bad packet is a stream of its own, cut into one to three segments.
//! A segment TCP keeps for reassembly carries no layer of the protocol, so a TCP packet passes
//! with the protocol's layer or with its bytes held for a Message still incomplete.
//!
//! The seed is fixed unless `WIRDIGEN_BAD_SEED` gives one (a number, or `random`);
//! `WIRDIGEN_BAD_MUTATIONS` sets the mutations per valid packet and `WIRDIGEN_BAD_RANDOM` the
//! random packets per case, for the weekly run's larger counts.

use std::fmt::{self, Write as _};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::{
    PORT, Scratch, Transport, case_dir, case_options, case_transport, enabled, expectation, first_error_key, own_layer,
    proto_name,
};

/// The seed of PR runs.
const DEFAULT_SEED: u64 = 0x5749_5244_4947_454e;
/// Mutations per valid packet in PR runs.
const DEFAULT_MUTATIONS: usize = 16;
/// Random packets per case in PR runs.
const DEFAULT_RANDOM: usize = 8;

/// Checks the corpus case `case` against bad input; see the module documentation.
pub(super) fn check(case: &str) {
    if !enabled() {
        return;
    }
    let dir = case_dir(case);
    let lua = dir.join(format!("{case}.lua"));
    let source = fs::read_to_string(&lua).unwrap();
    let proto = proto_name(&source);
    let options = case_options(case, proto);
    let options: Vec<&str> = options.iter().map(String::as_str).collect();
    let valid = parse_packets(&fs::read_to_string(dir.join("packets.txt")).unwrap());
    let scratch = Scratch::new(&format!("bad-{case}"));
    let transport = case_transport(case);
    let target = Target { scratch: &scratch, lua: &lua, proto, options: &options, transport };
    let config = Config::from_env();
    if transport == Transport::Tcp {
        let expected = fs::read_to_string(expectation(&dir, &scratch)).unwrap();
        let expected: Vec<Value> = serde_json::from_str(&expected).unwrap();
        target.resplit(&valid, &messages(&expected), &config).unwrap_or_else(|e| panic!("{case}: {e}"));
    }
    target.run(&valid, &config).unwrap_or_else(|e| panic!("{case}: {e}"));
}

/// The Messages of the protocol's layers, one per packet: a packet holding several Messages
/// has an array of them, one with none has `null`.
fn messages(layers: &[Value]) -> Vec<Value> {
    layers
        .iter()
        .flat_map(|layer| match layer {
            Value::Array(messages) => messages.clone(),
            Value::Null => Vec::new(),
            message => vec![message.clone()],
        })
        .collect()
}

/// Whether TCP holds the bytes of `packet` for a Message still incomplete.
fn held_for_reassembly(packet: &Value) -> bool {
    packet.pointer("/_source/layers/tcp/tcp.segment_data").is_some()
}

/// A Dissector under test: the script `lua` creating `proto`, run in `scratch` with tshark's
/// extra `options`.
pub(super) struct Target<'a> {
    pub(super) scratch: &'a Scratch,
    pub(super) lua: &'a Path,
    pub(super) proto: &'a str,
    pub(super) options: &'a [&'a str],
    /// What the packets travel over: each a datagram, or each a TCP stream of its own.
    pub(super) transport: Transport,
}

impl Target<'_> {
    /// Runs the packets derived from `valid` through the Dissector and reports the smallest
    /// failing one.
    pub(super) fn run(&self, valid: &[Vec<u8>], config: &Config) -> Result<(), String> {
        let mut packets = derive(valid, config);
        if packets.is_empty() {
            return Ok(());
        }
        // Smallest first, so that the first failure is the smallest.
        packets.sort_by_key(|p| p.bytes.len());
        let dissect = |count: usize| self.dissect(&packets[..count]);
        match dissect(packets.len()) {
            Ok(failures) => match failures.first() {
                None => Ok(()),
                Some((index, reason)) => {
                    let summary = format!("{} of {} bad packets fail", failures.len(), packets.len());
                    Err(report(&summary, config, &packets[*index], reason))
                }
            },
            Err(mut reason) => {
                // Whether a prefix of the packets spoils the run grows with the prefix: find the
                // shortest, whose last packet is the smallest culprit.
                let (mut low, mut high) = (1, packets.len());
                while low < high {
                    let middle = low + (high - low) / 2;
                    match dissect(middle) {
                        Err(spoiled) => {
                            high = middle;
                            reason = spoiled;
                        }
                        Ok(_) => low = middle + 1,
                    }
                }
                let summary = format!("a bad packet among {} spoils the tshark run", packets.len());
                Err(report(&summary, config, &packets[high - 1], &reason))
            }
        }
    }

    /// Dissects `packets` in one tshark run and returns the index and reason of each failing one,
    /// or why the run as a whole is unusable.
    fn dissect(&self, packets: &[BadPacket]) -> Result<Vec<(usize, String)>, String> {
        let (pcap, origins) = match self.transport {
            Transport::Udp => {
                let hex = self.scratch.path("bad-packets.txt");
                fs::write(&hex, packets.iter().map(|p| text2pcap(&p.bytes)).collect::<String>()).unwrap();
                (self.scratch.capture(&hex), (0..packets.len()).collect())
            }
            Transport::Tcp => {
                // Each packet is a stream of its own, cut where its bytes say, so that a prefix
                // of the packets cuts each one alike.
                let streams: Vec<Vec<&[u8]>> =
                    packets.iter().map(|p| split(&p.bytes, &mut Rng::new(fingerprint(&p.bytes)), 3)).collect();
                let origins = streams.iter().enumerate().flat_map(|(i, s)| std::iter::repeat_n(i, s.len())).collect();
                (self.tcp_capture(&streams), origins)
            }
        };
        let origins: Vec<usize> = origins;
        let dissected = self.scratch.tshark_json(self.lua, &pcap, self.options)?;
        if dissected.len() != origins.len() {
            return Err(format!("tshark dissected {} of {} packets", dissected.len(), origins.len()));
        }
        let mut failures: Vec<(usize, String)> = Vec::new();
        for (index, packet) in dissected.iter().enumerate() {
            let Err(reason) = own_layer(packet, index + 1, self.proto) else { continue };
            let held =
                self.transport == Transport::Tcp && first_error_key(packet).is_none() && held_for_reassembly(packet);
            let origin = origins[index];
            if !held && failures.last().is_none_or(|(last, _)| *last != origin) {
                failures.push((origin, reason));
            }
        }
        Ok(failures)
    }

    /// Writes a capture of `streams`, each a TCP stream to [`PORT`] from a port of its own, one
    /// segment per frame, and returns its path.
    fn tcp_capture(&self, streams: &[Vec<&[u8]>]) -> std::path::PathBuf {
        let path = self.scratch.path("bad-packets.pcap");
        fs::write(&path, tcp_pcap(streams)).unwrap();
        path
    }

    /// Spec §10.6: the valid packets of a TCP case, as one stream cut at random places, dissect
    /// into the `expected` Messages.
    fn resplit(&self, valid: &[Vec<u8>], expected: &[Value], config: &Config) -> Result<(), String> {
        let stream: Vec<u8> = valid.concat();
        let mut rng = Rng::new(config.seed);
        for _ in 0..RESPLITS {
            let segments = split(&stream, &mut rng, stream.len());
            let lengths: Vec<usize> = segments.iter().map(|s| s.len()).collect();
            let pcap = self.tcp_capture(std::slice::from_ref(&segments));
            let dissected = self.scratch.tshark_json(self.lua, &pcap, self.options)?;
            let replay = format!("WIRDIGEN_BAD_SEED={}, segments of {lengths:?} bytes", config.seed);
            if let Some(error) = dissected.iter().find_map(first_error_key) {
                return Err(format!("the valid stream re-split ({replay}) has `{error}`"));
            }
            let layers: Vec<Value> = dissected
                .iter()
                .map(|p| p.pointer(&format!("/_source/layers/{}", self.proto)).cloned().unwrap_or(Value::Null))
                .collect();
            let actual = messages(&layers);
            if actual != expected {
                return Err(format!(
                    "the valid stream re-split ({replay}) dissects into other Messages:\n{:#}",
                    Value::Array(actual)
                ));
            }
        }
        Ok(())
    }
}

/// How many times the valid stream of a TCP case is re-split.
const RESPLITS: usize = 4;

/// `bytes` cut into 1 to `most` non-empty segments, at places drawn from `rng`.
fn split<'b>(bytes: &'b [u8], rng: &mut Rng, most: usize) -> Vec<&'b [u8]> {
    let count = 1 + rng.below(most.min(bytes.len()).max(1));
    let mut cuts: Vec<usize> = (0..count - 1).map(|_| 1 + rng.below(bytes.len() - 1)).collect();
    cuts.sort_unstable();
    cuts.dedup();
    let mut segments = Vec::new();
    let mut start = 0;
    for cut in cuts.into_iter().chain([bytes.len()]) {
        segments.push(&bytes[start..cut]);
        start = cut;
    }
    segments
}

/// An FNV-1a hash of `bytes`, the seed of how a bad packet is cut into segments.
fn fingerprint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3))
}

/// A pcap capture of `streams`: each a TCP stream over IPv4 and Ethernet, from port 20000 plus
/// its index to [`PORT`], one segment per frame. Checksums are left at 0, which Wireshark does
/// not check by default.
fn tcp_pcap(streams: &[Vec<&[u8]>]) -> Vec<u8> {
    let mut pcap = Vec::new();
    for word in [0xa1b2_c3d4_u32, 0x0004_0002, 0, 0, 0x0004_0000, 1] {
        // Magic, version 2.4 (minor then major as one little-endian word), zone, accuracy,
        // snapshot length, Ethernet.
        pcap.extend_from_slice(&word.to_le_bytes());
    }
    let mut frame_number: u32 = 0;
    for (index, segments) in streams.iter().enumerate() {
        let source = u16::try_from(20_000 + index % 40_000).expect("a port");
        let mut seq: u32 = 1;
        for segment in segments {
            let mut frame = Vec::new();
            frame.extend_from_slice(&[0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0x08, 0x00]);
            let total = u16::try_from(40 + segment.len()).expect("a short segment");
            let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
            ip[2..4].copy_from_slice(&total.to_be_bytes());
            frame.extend_from_slice(&ip);
            frame.extend_from_slice(&source.to_be_bytes());
            frame.extend_from_slice(&PORT.to_be_bytes());
            frame.extend_from_slice(&seq.to_be_bytes());
            frame.extend_from_slice(&1u32.to_be_bytes());
            // Header of 5 words, PSH and ACK, a full window, no checksum or urgent pointer.
            frame.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
            frame.extend_from_slice(segment);
            seq = seq.wrapping_add(u32::try_from(segment.len()).expect("a short segment"));
            let len = u32::try_from(frame.len()).expect("a short frame");
            for word in [frame_number, 0, len, len] {
                pcap.extend_from_slice(&word.to_le_bytes());
            }
            pcap.extend_from_slice(&frame);
            frame_number += 1;
        }
    }
    pcap
}

/// The failure message: `summary`, how to replay the run, and the smallest failing packet.
fn report(summary: &str, config: &Config, packet: &BadPacket, reason: &str) -> String {
    let Config { seed, mutations, random } = config;
    format!(
        "{summary} (replay with WIRDIGEN_BAD_SEED={seed} WIRDIGEN_BAD_MUTATIONS={mutations} \
         WIRDIGEN_BAD_RANDOM={random}). The smallest, {} bytes, is {}:\n{}\
         In the capture of bad packets, sorted smallest first: {reason}",
        packet.bytes.len(),
        packet.origin,
        text2pcap(&packet.bytes),
    )
}

/// `bytes` as text2pcap hex, 16 bytes per offset line.
fn text2pcap(bytes: &[u8]) -> String {
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

/// The packets of text2pcap hex, one per offset-0 line run.
pub(super) fn parse_packets(text: &str) -> Vec<Vec<u8>> {
    let mut packets: Vec<Vec<u8>> = Vec::new();
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        let Some(offset) = tokens.next().filter(|t| t.chars().all(|c| c.is_ascii_hexdigit())) else {
            continue;
        };
        if offset.chars().all(|c| c == '0') {
            packets.push(Vec::new());
        }
        let packet = packets.last_mut().expect("a packet starts at an offset-0 line");
        packet.extend(tokens.map(|t| u8::from_str_radix(t, 16).unwrap_or_else(|_| panic!("bad hex byte {t:?}"))));
    }
    packets
}

/// A packet derived from a valid one, or a random one.
struct BadPacket {
    bytes: Vec<u8>,
    origin: Origin,
}

/// How a [`BadPacket`] was made; packets are numbered from 1 as in `packets.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Origin {
    Truncated { packet: usize },
    Mutated { packet: usize, mutation: Mutation },
    Random,
}

/// One change to a valid packet.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mutation {
    /// One bit flipped, numbered from the first byte's most significant bit.
    BitFlip { bit: usize },
    /// `width` bytes at `offset`, standing for a length or count, set to `fill`.
    Set { offset: usize, width: usize, fill: Fill },
    /// `len` random bytes inserted before `offset`.
    Insert { offset: usize, len: usize },
    /// `len` bytes removed from `offset`.
    Remove { offset: usize, len: usize },
    /// `len` bytes from `offset` overwritten with random ones.
    Garbage { offset: usize, len: usize },
}

/// What [`Mutation::Set`] writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fill {
    Zero,
    /// Every bit set.
    Max,
    /// `7f ff … ff`: the largest signed value read big-endian, nearly every bit set read
    /// little-endian.
    Huge,
}

/// The seed and counts of a run.
pub(super) struct Config {
    pub(super) seed: u64,
    /// Mutations per valid packet.
    pub(super) mutations: usize,
    /// Random packets per case.
    pub(super) random: usize,
}

impl Config {
    /// The fixed PR configuration, overridden by `WIRDIGEN_BAD_SEED`, `WIRDIGEN_BAD_MUTATIONS`
    /// and `WIRDIGEN_BAD_RANDOM`.
    fn from_env() -> Config {
        let seed = match std::env::var("WIRDIGEN_BAD_SEED").ok().as_deref() {
            None => DEFAULT_SEED,
            Some("random") => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
                Rng::new(now.as_secs() ^ u64::from(now.subsec_nanos()) ^ u64::from(std::process::id())).next()
            }
            Some(seed) => parse_env("WIRDIGEN_BAD_SEED", seed),
        };
        let count = |name: &str, default: usize| std::env::var(name).map_or(default, |value| parse_env(name, &value));
        Config {
            seed,
            mutations: count("WIRDIGEN_BAD_MUTATIONS", DEFAULT_MUTATIONS),
            random: count("WIRDIGEN_BAD_RANDOM", DEFAULT_RANDOM),
        }
    }
}

/// `value` of the environment variable `name`.
///
/// # Panics
///
/// When `value` does not parse.
fn parse_env<T: std::str::FromStr>(name: &str, value: &str) -> T {
    value.parse().unwrap_or_else(|_| panic!("{name}={value:?} is not a non-negative number"))
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Truncated { packet } => write!(f, "a truncation of packet {packet}"),
            Origin::Mutated { packet, mutation } => write!(f, "packet {packet} with {mutation}"),
            Origin::Random => write!(f, "random"),
        }
    }
}

impl fmt::Display for Mutation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mutation::BitFlip { bit } => write!(f, "bit {bit} flipped"),
            Mutation::Set { offset, width, fill } => {
                let fill = match fill {
                    Fill::Zero => "0",
                    Fill::Max => "max",
                    Fill::Huge => "huge",
                };
                write!(f, "{width} bytes at offset {offset} set to {fill}")
            }
            Mutation::Insert { offset, len } => write!(f, "{len} bytes inserted at offset {offset}"),
            Mutation::Remove { offset, len } => write!(f, "{len} bytes removed at offset {offset}"),
            Mutation::Garbage { offset, len } => write!(f, "{len} garbage bytes at offset {offset}"),
        }
    }
}

/// `SplitMix64`: a small deterministic generator, so a seed replays the same packets anywhere.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in `0..n`, for a non-zero `n`.
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("below a usize")
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next().to_le_bytes()[0]).collect()
    }
}

/// The longest run of bytes inserted, removed or overwritten with garbage.
const MAX_RUN: usize = 8;
/// The longest random packet.
const MAX_RANDOM_LEN: usize = 64;

/// Every truncation of each valid packet, `config.mutations` mutations of each, and
/// `config.random` random packets, none of them empty.
fn derive(packets: &[Vec<u8>], config: &Config) -> Vec<BadPacket> {
    let mut rng = Rng::new(config.seed);
    let mut derived = Vec::new();
    for (index, packet) in packets.iter().enumerate() {
        let number = index + 1;
        derived.extend(
            truncations(packet)
                .into_iter()
                .map(|bytes| BadPacket { bytes, origin: Origin::Truncated { packet: number } }),
        );
        for _ in 0..config.mutations {
            let mutation = pick_mutation(packet.len(), &mut rng);
            let mut bytes = packet.clone();
            apply(&mut bytes, &mutation, &mut rng);
            derived.push(BadPacket { bytes, origin: Origin::Mutated { packet: number, mutation } });
        }
    }
    for _ in 0..config.random {
        let len = 1 + rng.below(MAX_RANDOM_LEN);
        derived.push(BadPacket { bytes: rng.bytes(len), origin: Origin::Random });
    }
    derived
}

/// A mutation of a packet of `len` bytes, `len` > 0, that leaves it non-empty.
fn pick_mutation(len: usize, rng: &mut Rng) -> Mutation {
    let run = |rng: &mut Rng, room: usize| 1 + rng.below(room.min(MAX_RUN));
    match rng.below(5) {
        0 => Mutation::BitFlip { bit: rng.below(len * 8) },
        1 => {
            let widths: Vec<usize> = [1, 2, 4, 8].into_iter().filter(|&w| w <= len).collect();
            let width = widths[rng.below(widths.len())];
            let fill = [Fill::Zero, Fill::Max, Fill::Huge][rng.below(3)];
            Mutation::Set { offset: rng.below(len - width + 1), width, fill }
        }
        2 if len > 1 => {
            let offset = rng.below(len);
            Mutation::Remove { offset, len: run(rng, (len - offset).min(len - 1)) }
        }
        3 => {
            let offset = rng.below(len);
            Mutation::Garbage { offset, len: run(rng, len - offset) }
        }
        _ => Mutation::Insert { offset: rng.below(len + 1), len: run(rng, MAX_RUN) },
    }
}

/// Applies `mutation` to `bytes`, drawing inserted and garbage bytes from `rng`.
fn apply(bytes: &mut Vec<u8>, mutation: &Mutation, rng: &mut Rng) {
    match *mutation {
        Mutation::BitFlip { bit } => bytes[bit / 8] ^= 0x80 >> (bit % 8),
        Mutation::Set { offset, width, fill } => {
            let target = &mut bytes[offset..offset + width];
            match fill {
                Fill::Zero => target.fill(0x00),
                Fill::Max => target.fill(0xff),
                Fill::Huge => {
                    target.fill(0xff);
                    target[0] = 0x7f;
                }
            }
        }
        Mutation::Insert { offset, len } => {
            let inserted = rng.bytes(len);
            bytes.splice(offset..offset, inserted);
        }
        Mutation::Remove { offset, len } => {
            bytes.drain(offset..offset + len);
        }
        Mutation::Garbage { offset, len } => {
            let garbage = rng.bytes(len);
            bytes[offset..offset + len].copy_from_slice(&garbage);
        }
    }
}

/// Every non-empty proper prefix of `packet`.
fn truncations(packet: &[u8]) -> Vec<Vec<u8>> {
    (1..packet.len()).map(|len| packet[..len].to_vec()).collect()
}

mod tests {
    use super::*;

    #[test]
    fn packets_are_read_from_text2pcap_hex() {
        let text = "# one\n0000  01 02\n0002  03\n# two\n0000  ff\n";
        assert_eq!(parse_packets(text), vec![vec![1, 2, 3], vec![0xff]]);
    }

    #[test]
    fn every_truncation_keeps_at_least_one_byte() {
        assert_eq!(truncations(&[1, 2, 3]), vec![vec![1], vec![1, 2]]);
    }

    fn valid() -> Vec<Vec<u8>> {
        vec![vec![0x02, 0x01, 0x01, 0xaa, 0x02, 0x00, 0x02, 0xff], vec![0x00], vec![0x00, 0x01, 0x01, 0x02, 0xaa]]
    }

    fn config(seed: u64) -> Config {
        Config { seed, mutations: 64, random: 5 }
    }

    #[test]
    fn a_seed_derives_the_same_packets() {
        let bytes = |seed| derive(&valid(), &config(seed)).into_iter().map(|p| p.bytes).collect::<Vec<_>>();
        assert_eq!(bytes(7), bytes(7));
        assert_ne!(bytes(7), bytes(8));
    }

    #[test]
    fn every_truncation_every_mutation_kind_and_the_random_packets_are_derived() {
        let packets = derive(&valid(), &config(1));
        let origins: Vec<&Origin> = packets.iter().map(|p| &p.origin).collect();
        let truncated = origins.iter().filter(|o| matches!(o, Origin::Truncated { .. })).count();
        assert_eq!(truncated, 7 + 4);
        let mutated = origins.iter().filter(|o| matches!(o, Origin::Mutated { .. })).count();
        assert_eq!(mutated, 3 * 64);
        assert_eq!(origins.iter().filter(|o| matches!(o, Origin::Random)).count(), 5);
        let has = |kind: fn(&Mutation) -> bool| {
            origins.iter().any(|o| matches!(o, Origin::Mutated { mutation, .. } if kind(mutation)))
        };
        assert!(has(|m| matches!(m, Mutation::BitFlip { .. })));
        assert!(has(|m| matches!(m, Mutation::Set { fill: Fill::Zero, .. })));
        assert!(has(|m| matches!(m, Mutation::Set { fill: Fill::Max, .. })));
        assert!(has(|m| matches!(m, Mutation::Set { fill: Fill::Huge, .. })));
        assert!(has(|m| matches!(m, Mutation::Insert { .. })));
        assert!(has(|m| matches!(m, Mutation::Remove { .. })));
        assert!(has(|m| matches!(m, Mutation::Garbage { .. })));
    }

    #[test]
    fn no_packet_is_empty() {
        // UDP never calls a Dissector for an empty payload (spec §10.5).
        for seed in 0..50 {
            assert!(derive(&valid(), &config(seed)).iter().all(|p| !p.bytes.is_empty()), "seed {seed}");
        }
    }

    #[test]
    fn hex_round_trips_through_text2pcap() {
        let bytes: Vec<u8> = (0..20).collect();
        let text = text2pcap(&bytes);
        assert!(text.starts_with("0000  00 01 02"), "{text}");
        assert!(text.contains("\n0010  10 11 12 13\n"), "{text}");
        assert_eq!(parse_packets(&text), vec![bytes]);
    }

    #[test]
    fn set_writes_zero_max_or_huge() {
        let mut huge = vec![0x11; 3];
        apply(&mut huge, &Mutation::Set { offset: 0, width: 3, fill: Fill::Huge }, &mut Rng::new(0));
        assert_eq!(huge, [0x7f, 0xff, 0xff]);
        let mut bytes = vec![0x11; 6];
        apply(&mut bytes, &Mutation::Set { offset: 1, width: 4, fill: Fill::Max }, &mut Rng::new(0));
        assert_eq!(bytes, [0x11, 0xff, 0xff, 0xff, 0xff, 0x11]);
        apply(&mut bytes, &Mutation::Set { offset: 0, width: 2, fill: Fill::Zero }, &mut Rng::new(0));
        assert_eq!(bytes, [0x00, 0x00, 0xff, 0xff, 0xff, 0x11]);
    }

    #[test]
    fn a_split_keeps_every_byte_in_order_in_non_empty_segments() {
        let bytes: Vec<u8> = (0..10).collect();
        let mut rng = Rng::new(3);
        for most in [1, 3, 10] {
            for _ in 0..50 {
                let segments = split(&bytes, &mut rng, most);
                assert!((1..=most).contains(&segments.len()), "{segments:?}");
                assert!(segments.iter().all(|s| !s.is_empty()), "{segments:?}");
                assert_eq!(segments.concat(), bytes);
            }
        }
        assert_eq!(split(&[7], &mut rng, 3), vec![&[7][..]]);
    }

    #[test]
    fn a_tcp_capture_has_a_frame_per_segment() {
        let pcap = tcp_pcap(&[vec![&[1, 2][..], &[3][..]], vec![&[4][..]]]);
        // A 24-byte header, then per frame a 16-byte record header and 54 bytes of headers.
        assert_eq!(pcap.len(), 24 + 3 * (16 + 54) + 4);
    }

    #[test]
    fn a_bit_flip_flips_one_bit_most_significant_first() {
        let mut bytes = vec![0x00, 0x00];
        apply(&mut bytes, &Mutation::BitFlip { bit: 9 }, &mut Rng::new(0));
        assert_eq!(bytes, [0x00, 0x40]);
    }

    #[test]
    fn insert_and_remove_change_the_length() {
        let mut bytes = vec![1, 2, 3, 4];
        apply(&mut bytes, &Mutation::Remove { offset: 1, len: 2 }, &mut Rng::new(0));
        assert_eq!(bytes, [1, 4]);
        apply(&mut bytes, &Mutation::Insert { offset: 1, len: 3 }, &mut Rng::new(0));
        assert_eq!(bytes.len(), 5);
        assert_eq!((bytes[0], bytes[4]), (1, 4));
    }
}
