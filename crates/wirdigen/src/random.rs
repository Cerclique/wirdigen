//! Random valid Protocol Descriptions (spec §10.7): a proptest strategy over the whole v1
//! language, and the properties every description it draws must have.
//!
//! The strategy draws a shape (which Fields, Types, Enums, Expressions and top-level keys a
//! description has) and renders it as YAML. Rendering names every Field, Type and Enum uniquely
//! and picks each Field path among those an Expression may read where it is written (spec §4.3),
//! so every description is valid by construction: one that `validate` rejects is a bug in either.
//!
//! For each description, `validate` accepts it, `generate` does not panic, two generations are
//! byte-identical and the JSON Schema accepts it (spec §6.5); the Lua checks compile the output
//! under `WIRDIGEN_LUA=1` (`lua_check`). `PROPTEST_CASES` sets the number of cases. Nothing is
//! persisted between runs: a shrunk failure becomes a corpus case instead, under `tests/cases/`
//! or `tests/valid/`.

use std::fmt;

use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::{Config, TestRunner};

use crate::expr::{self, BinaryOp, Expr, ExprKind, Spanned, UnaryOp};

/// A rendered description. Its `Debug` is the YAML itself, so a failing case reads as a file.
#[derive(Clone)]
struct DescriptionText(String);

impl fmt::Debug for DescriptionText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\n{}", self.0)
    }
}

/// No regression files: shrunk failures become corpus cases (see the module docs). The case count
/// stays the default, which `PROPTEST_CASES` overrides.
fn config() -> Config {
    Config { failure_persistence: None, ..Config::default() }
}

/// The stack of the thread drawing descriptions: their nested shapes go deeper than a test
/// thread's default stack holds on every OS (Windows' debug frames are the largest).
const STACK: usize = 64 * 1024 * 1024;

/// Runs `property` on random valid descriptions, by their YAML text, and panics with the
/// smallest failing description it finds.
pub(crate) fn check(property: impl Fn(&str) -> Result<(), TestCaseError> + Send + 'static) {
    let outcome = deep_stack(move || TestRunner::new(config()).run(&description(), |text| property(&text.0)));
    if let Err(error) = outcome {
        panic!("{error}");
    }
}

/// Runs `f` on a thread with a stack deep enough for the strategy, passing on its panic.
fn deep_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let thread = std::thread::Builder::new().stack_size(STACK).spawn(f).expect("a thread can be spawned");
    thread.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// A random valid Protocol Description.
fn description() -> impl Strategy<Value = DescriptionText> {
    shape().prop_map(|shape| DescriptionText(render(&shape)))
}

// Shapes: every choice a description makes, with no names. A path an Expression reads is an
// `Index` into the Fields readable where it is written, resolved when rendering.

#[derive(Debug, Clone)]
struct Shape {
    name: &'static str,
    title: Option<&'static str>,
    registration: Option<Registration>,
    framing: Option<Framing>,
    endian: Option<&'static str>,
    info: Option<Vec<InfoPiece>>,
    fields: Layout,
    types: Vec<TypeShape>,
    enums: Vec<Table>,
    allow: Option<Vec<&'static str>>,
    /// Whether the layout starts with a Field every Type reads without declaring it, so each
    /// use of a Type resolves it in its own scope (spec §3.5, §4.3).
    context: bool,
    /// The order the top-level keys are written in.
    order: Vec<&'static str>,
}

#[derive(Debug, Clone)]
struct Registration {
    udp: Option<Keys>,
    tcp: Option<Keys>,
}

/// A length-prefixed header read first, and the Message length computed from it.
#[derive(Debug, Clone)]
struct Framing {
    /// The bytes of the length Field.
    bytes: u8,
    /// Whether the length Field is a bitfield, whose sub-Fields the length may read.
    bits: bool,
    /// Header bytes beyond the length Field.
    extra: u8,
    length: ExprShape,
}

#[derive(Debug, Clone)]
enum InfoPiece {
    Text(&'static str),
    Field(Index),
}

#[derive(Debug, Clone)]
struct TypeShape {
    endian: Option<&'static str>,
    fields: Layout,
}

type Layout = Vec<Entry>;

#[derive(Debug, Clone)]
enum Entry {
    Padding(Operand),
    Field(Box<FieldShape>),
}

#[derive(Debug, Clone)]
struct FieldShape {
    kind: Kind,
    condition: Option<Operand>,
    hidden: Option<bool>,
    label: Option<&'static str>,
    description: Option<&'static str>,
    /// Written only where a Field takes it: a built-in type or an inline structure.
    endian: Option<&'static str>,
}

#[derive(Debug, Clone)]
enum Kind {
    Int {
        bytes: u8,
        signed: bool,
        display: Option<Index>,
        mapping: Option<Mapping>,
        expect: Option<Keys>,
        bits: Option<Bits>,
    },
    Bool {
        labels: (Option<&'static str>, Option<&'static str>),
        expect: Option<Vec<bool>>,
    },
    Float {
        double: bool,
        unit: Option<Unit>,
    },
    Fixed(&'static str),
    Time {
        relative: bool,
        encoding: Option<Index>,
        display: Option<Index>,
    },
    Text {
        bytes: bool,
        length: Length,
        encoding: Option<Index>,
        display: Option<Index>,
        dissector: Option<&'static str>,
    },
    Structure {
        fields: Layout,
        array: Option<Repeat>,
    },
    Type {
        ty: Index,
        array: Option<Repeat>,
    },
    Switch {
        subject: Operand,
        cases: Vec<Body>,
        keys: Keys,
        default: Option<Body>,
    },
}

#[derive(Debug, Clone)]
enum Mapping {
    Values(Table),
    Enum(Index),
    Unit(Unit),
}

#[derive(Debug, Clone)]
enum Unit {
    One(&'static str),
    Two(&'static str, &'static str),
}

/// A values table: disjoint keys, each with a label.
#[derive(Debug, Clone)]
struct Table {
    keys: Keys,
    labels: Vec<&'static str>,
}

/// Disjoint integers and ranges, from `start` up: each step skips `gap` values, then covers
/// `width + 1` of them, written in the style `style`.
#[derive(Debug, Clone)]
struct Keys {
    start: i64,
    steps: Vec<(u8, u8, u8)>,
}

/// Cut points splitting a bitfield's width into entries, and what each entry is.
#[derive(Debug, Clone)]
struct Bits {
    cuts: Vec<Index>,
    entries: Vec<Bit>,
}

#[derive(Debug, Clone)]
enum Bit {
    Padding,
    /// A sub-Field, boolean when one bit wide and nothing makes it an integer.
    Sub {
        display: Option<Index>,
        mapping: Option<Mapping>,
        labels: (Option<&'static str>, Option<&'static str>),
        expect: Option<Keys>,
        hidden: Option<bool>,
        label: Option<&'static str>,
        description: Option<&'static str>,
    },
}

#[derive(Debug, Clone)]
enum Length {
    Size(Operand),
    Remaining,
    Prefix(&'static str),
    Terminator(u8),
}

#[derive(Debug, Clone)]
enum Repeat {
    Count(Operand),
    ToEnd,
}

#[derive(Debug, Clone)]
enum Body {
    Type(Index),
    Fields(Layout),
}

/// A constant written as a YAML integer, or an Expression written as a string.
#[derive(Debug, Clone)]
enum Operand {
    Constant(i64),
    Expr(ExprShape),
}

#[derive(Debug, Clone)]
enum ExprShape {
    Int(u64),
    Path(Index),
    Builtin(expr::Builtin),
    Unary(UnaryOp, Box<ExprShape>),
    Binary(BinaryOp, Box<ExprShape>, Box<ExprShape>),
}

// Vocabulary.

/// Field names: Lua keywords and names Lua gives a meaning, interleaved with plain ones, so the
/// generated code's mangling is exercised.
const KEYWORD_NAMES: &[&str] = &[
    "end", "type", "local", "function", "and", "or", "not", "nil", "repeat", "until", "return", "then", "while", "do",
    "else", "elseif", "for", "goto", "if", "in", "break", "self", "string", "tree", "buffer",
];
const PROTOCOLS: &[&str] = &["wdrand", "wd-rand", "p", "p_2-x", "abcdefghijklmnopqrstuvwxyz012345"];
/// Single-line texts for titles, labels, descriptions, units and Info text, quoted in YAML.
const TEXTS: &[&str] = &[
    "Length",
    "Msg type",
    "Ünïcode ✓ 日本語",
    "quote \" and backslash \\",
    "colon: here",
    "# not a comment",
    "]] [[long]] [=[",
    "%d %s %%",
    "tab\there",
    "end",
    "'single'",
];
const INFO_TEXTS: &[&str] = &[" ", " id=", "{literal}", ": ", "}{", "x"];
const UNSIGNED_DISPLAYS: &[&str] = &["dec", "hex", "oct", "dec_hex", "hex_dec"];
const BYTES_DISPLAYS: &[&str] = &["plain", "dot", "dash", "colon", "space"];
const TIME_DISPLAYS: &[&str] = &["local", "utc", "doy_utc"];
const STRING_ENCODINGS: &[&str] = &["ascii", "utf8", "utf16", "ucs2", "latin1"];
const ABS_TIME_ENCODINGS: &[&str] = &["secs", "secs_nsecs", "ntp", "msecs", "usecs", "nsecs"];
const REL_TIME_ENCODINGS: &[&str] = &["secs", "secs_nsecs", "msecs", "usecs", "nsecs"];
const PREFIXES: &[&str] = &["uint8", "uint16", "uint24", "uint32", "uint40", "uint48", "uint56", "uint64"];
const FIXED: &[&str] = &["ipv4", "ipv6", "ether", "eui64", "guid"];
const DISSECTORS: &[&str] = &["data", "ip", "eth_withoutfcs", "wirdigen_no_such_dissector"];
const ALLOWS: &[&str] = &[
    "tcp-without-framing",
    "unused-type",
    "unused-enum",
    "unreachable-value",
    "unreachable-field",
    "unreachable-expect",
    "protocol-name-taken",
    "not-a-warning",
];
const TOP_KEYS: [&str; 10] =
    ["name", "title", "registration", "framing", "endian", "info", "fields", "types", "enums", "allow"];

// Strategies.

fn text() -> impl Strategy<Value = &'static str> {
    prop::sample::select(TEXTS)
}

fn endian() -> impl Strategy<Value = Option<&'static str>> {
    prop::option::weighted(0.2, prop::sample::select(&["big", "little"][..]))
}

fn maybe<T: fmt::Debug + Clone>(strategy: impl Strategy<Value = T>) -> impl Strategy<Value = Option<T>> {
    prop::option::weighted(0.25, strategy)
}

fn shape() -> impl Strategy<Value = Shape> {
    let identity = (prop::sample::select(PROTOCOLS), maybe(text()), endian(), any::<bool>());
    let around = (
        maybe(any_registration()),
        maybe(framing()),
        maybe(prop::collection::vec(info_piece(), 0..5)),
        maybe(prop::collection::vec(prop::sample::select(ALLOWS), 0..3)),
        Just(TOP_KEYS.to_vec()).prop_shuffle(),
    );
    let layouts = (
        layout(2),
        prop::collection::vec((endian(), layout(1)).prop_map(|(endian, fields)| TypeShape { endian, fields }), 0..4),
        prop::collection::vec(table(), 0..3),
    );
    (identity, around, layouts).prop_map(
        |((name, title, endian, context), (registration, framing, info, allow, order), (fields, types, enums))| Shape {
            name,
            title,
            registration,
            framing,
            endian,
            info,
            fields,
            types,
            enums,
            allow,
            context,
            order,
        },
    )
}

fn any_registration() -> impl Strategy<Value = Registration> {
    let ports = |max: u8| keys(1i64..=60_000, max);
    (maybe(ports(5)), maybe(ports(5)), any::<bool>()).prop_map(|(udp, tcp, tcp_first)| match (udp, tcp) {
        // Registration declares at least one transport.
        (None, None) if tcp_first => {
            Registration { udp: None, tcp: Some(Keys { start: 4242, steps: vec![(0, 0, 0)] }) }
        }
        (None, None) => Registration { udp: Some(Keys { start: 4242, steps: vec![(0, 0, 0)] }), tcp: None },
        (udp, tcp) => Registration { udp, tcp },
    })
}

fn framing() -> impl Strategy<Value = Framing> {
    (prop::sample::select(&[1u8, 2, 4][..]), any::<bool>(), 0u8..4, expr_shape())
        .prop_map(|(bytes, bits, extra, length)| Framing { bytes, bits, extra, length })
}

fn info_piece() -> impl Strategy<Value = InfoPiece> {
    prop_oneof![
        1 => prop::sample::select(INFO_TEXTS).prop_map(InfoPiece::Text),
        2 => any::<Index>().prop_map(InfoPiece::Field),
    ]
}

/// Disjoint keys from somewhere in `start`.
fn keys(start: impl Strategy<Value = i64>, max: u8) -> impl Strategy<Value = Keys> {
    (
        start,
        prop::collection::vec((0u8..20, prop_oneof![3 => Just(0u8), 1 => 1u8..6], any::<u8>()), 1..=usize::from(max)),
    )
        .prop_map(|(start, steps)| Keys { start, steps })
}

fn table() -> impl Strategy<Value = Table> {
    keys(-5i64..20, 6).prop_flat_map(|keys| {
        let n = keys.steps.len();
        (Just(keys), prop::collection::vec(text(), n)).prop_map(|(keys, labels)| Table { keys, labels })
    })
}

fn unit() -> impl Strategy<Value = Unit> {
    prop_oneof![text().prop_map(Unit::One), (text(), text()).prop_map(|(one, many)| Unit::Two(one, many))]
}

fn mapping() -> impl Strategy<Value = Mapping> {
    prop_oneof![
        table().prop_map(Mapping::Values),
        any::<Index>().prop_map(Mapping::Enum),
        unit().prop_map(Mapping::Unit)
    ]
}

fn labels() -> impl Strategy<Value = (Option<&'static str>, Option<&'static str>)> {
    (maybe(text()), maybe(text()))
}

fn layout(depth: u32) -> BoxedStrategy<Layout> {
    let entry = prop_oneof![
        1 => any_operand(true).prop_map(Entry::Padding),
        10 => field(depth).prop_map(|field| Entry::Field(Box::new(field))),
    ];
    prop::collection::vec(entry, 1..5).boxed()
}

fn field(depth: u32) -> impl Strategy<Value = FieldShape> {
    (
        kind(depth),
        prop::option::weighted(0.15, any_operand(false)),
        maybe(any::<bool>()),
        maybe(text()),
        maybe(text()),
        endian(),
    )
        .prop_map(|(kind, condition, hidden, label, description, endian)| FieldShape {
            kind,
            condition,
            hidden,
            label,
            description,
            endian,
        })
}

fn kind(depth: u32) -> BoxedStrategy<Kind> {
    let int =
        (1u8..=8, any::<bool>(), maybe(any::<Index>()), maybe(mapping()), maybe(keys(-3i64..300, 3)), maybe(bits()))
            .prop_map(|(bytes, signed, display, mapping, expect, bits)| Kind::Int {
                bytes,
                signed,
                display,
                mapping,
                expect,
                bits,
            });
    let boolean = (labels(), maybe(prop::collection::vec(any::<bool>(), 1..3)))
        .prop_map(|(labels, expect)| Kind::Bool { labels, expect });
    let float = (any::<bool>(), maybe(unit())).prop_map(|(double, unit)| Kind::Float { double, unit });
    let fixed = prop::sample::select(FIXED).prop_map(Kind::Fixed);
    let time = (any::<bool>(), maybe(any::<Index>()), maybe(any::<Index>()))
        .prop_map(|(relative, encoding, display)| Kind::Time { relative, encoding, display });
    let text = (
        any::<bool>(),
        length(),
        maybe(any::<Index>()),
        maybe(any::<Index>()),
        maybe(prop::sample::select(DISSECTORS)),
    )
        .prop_map(|(bytes, length, encoding, display, dissector)| Kind::Text {
            bytes,
            length,
            encoding,
            display,
            dissector,
        });
    let leaf = prop_oneof![6 => int, 2 => boolean, 1 => float, 1 => fixed, 1 => time, 3 => text];
    if depth == 0 {
        return leaf.boxed();
    }
    let structure = (layout(depth - 1), maybe(repeat())).prop_map(|(fields, array)| Kind::Structure { fields, array });
    let type_use = (any::<Index>(), maybe(repeat())).prop_map(|(ty, array)| Kind::Type { ty, array });
    let switch =
        (any_operand(false), prop::collection::vec(body(depth - 1), 1..4), keys(-3i64..10, 3), maybe(body(depth - 1)))
            .prop_map(|(subject, cases, keys, default)| Kind::Switch { subject, cases, keys, default });
    prop_oneof![10 => leaf, 2 => structure, 2 => type_use, 1 => switch].boxed()
}

fn bits() -> impl Strategy<Value = Bits> {
    let bit = prop_oneof![
        1 => Just(Bit::Padding),
        4 => (maybe(any::<Index>()), maybe(mapping()), labels(), maybe(keys(0i64..8, 2)), maybe(any::<bool>()), maybe(text()), maybe(text()))
            .prop_map(|(display, mapping, labels, expect, hidden, label, description)| Bit::Sub {
                display,
                mapping,
                labels,
                expect,
                hidden,
                label,
                description,
            }),
    ];
    (prop::collection::vec(any::<Index>(), 0..5), prop::collection::vec(bit, 6))
        .prop_map(|(cuts, entries)| Bits { cuts, entries })
}

fn length() -> impl Strategy<Value = Length> {
    prop_oneof![
        3 => any_operand(true).prop_map(Length::Size),
        1 => Just(Length::Remaining),
        2 => prop::sample::select(PREFIXES).prop_map(Length::Prefix),
        2 => prop_oneof![Just(0u8), any::<u8>()].prop_map(Length::Terminator),
    ]
}

fn repeat() -> impl Strategy<Value = Repeat> {
    prop_oneof![2 => any_operand(true).prop_map(Repeat::Count), 1 => Just(Repeat::ToEnd)]
}

fn body(depth: u32) -> impl Strategy<Value = Body> {
    prop_oneof![any::<Index>().prop_map(Body::Type), layout(depth).prop_map(Body::Fields)]
}

/// An operand: a small constant, non-negative for an amount, or an Expression.
fn any_operand(amount: bool) -> impl Strategy<Value = Operand> {
    let constant = if amount { (0i64..10).boxed() } else { (-3i64..10).boxed() };
    prop_oneof![1 => constant.prop_map(Operand::Constant), 3 => expr_shape().prop_map(Operand::Expr)]
}

fn expr_shape() -> impl Strategy<Value = ExprShape> {
    let leaf = prop_oneof![
        3 => prop_oneof![4 => 0u64..10, 2 => 0u64..0x1_0000, 1 => any::<u64>()].prop_map(ExprShape::Int),
        4 => any::<Index>().prop_map(ExprShape::Path),
        1 => prop::sample::select(expr::Builtin::ALL.to_vec()).prop_map(ExprShape::Builtin),
    ];
    leaf.prop_recursive(3, 12, 2, |inner| {
        let unary = prop::sample::select(vec![UnaryOp::Not, UnaryOp::Complement, UnaryOp::Negate]);
        prop_oneof![
            (unary, inner.clone()).prop_map(|(op, operand)| ExprShape::Unary(op, Box::new(operand))),
            (prop::sample::select(BinaryOp::ALL.to_vec()), inner.clone(), inner)
                .prop_map(|(op, left, right)| ExprShape::Binary(op, Box::new(left), Box::new(right))),
        ]
    })
}

// YAML.

/// A YAML node to print: a scalar already spelled as written, a sequence or a mapping whose
/// keys are spelled as written.
#[derive(Debug, Clone)]
enum Yaml {
    Scalar(String),
    Seq(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    fn plain(text: impl fmt::Display) -> Self {
        Self::Scalar(text.to_string())
    }

    fn quoted(text: &str) -> Self {
        Self::Scalar(quote(text))
    }

    /// Whether the node is printed in flow style: scalars, and collections of a few scalars.
    fn is_flow(&self) -> bool {
        match self {
            Self::Scalar(_) => true,
            Self::Seq(items) => items.iter().all(|i| matches!(i, Self::Scalar(_))),
            Self::Map(entries) => entries.len() <= 6 && entries.iter().all(|(_, v)| matches!(v, Self::Scalar(_))),
        }
    }

    fn flow(&self, out: &mut String) {
        match self {
            Self::Scalar(text) => out.push_str(text),
            Self::Seq(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    out.push_str(if i == 0 { " " } else { ", " });
                    item.flow(out);
                }
                out.push_str(" ]");
            }
            Self::Map(entries) => {
                out.push('{');
                for (i, (key, value)) in entries.iter().enumerate() {
                    out.push_str(if i == 0 { " " } else { ", " });
                    out.push_str(key);
                    out.push_str(": ");
                    value.flow(out);
                }
                out.push_str(" }");
            }
        }
    }

    /// Prints the value of a mapping entry or a sequence item, after its `key:` or `-`.
    fn value(&self, out: &mut String, indent: usize) {
        if self.is_flow() {
            out.push(' ');
            self.flow(out);
            out.push('\n');
            return;
        }
        out.push('\n');
        self.block(out, indent);
    }

    fn block(&self, out: &mut String, indent: usize) {
        let pad = " ".repeat(indent);
        match self {
            Self::Scalar(_) => unreachable!("a scalar is printed in flow style"),
            Self::Seq(items) => {
                for item in items {
                    out.push_str(&pad);
                    out.push('-');
                    match item {
                        // A mapping starts on the dash's line.
                        Self::Map(entries) if !item.is_flow() => {
                            out.push(' ');
                            block_map(entries, out, indent + 2, true);
                        }
                        _ => item.value(out, indent + 2),
                    }
                }
            }
            Self::Map(entries) => block_map(entries, out, indent, false),
        }
    }
}

fn block_map(entries: &[(String, Yaml)], out: &mut String, indent: usize, first_inline: bool) {
    for (i, (key, value)) in entries.iter().enumerate() {
        if i > 0 || !first_inline {
            out.push_str(&" ".repeat(indent));
        }
        out.push_str(key);
        out.push(':');
        value.value(out, indent + 2);
    }
}

/// A double-quoted YAML scalar.
fn quote(text: &str) -> String {
    let mut quoted = String::from('"');
    for c in text.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\t' => quoted.push_str("\\t"),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

// Rendering.

/// A Field path, by its names.
type Path = Vec<String>;

/// What the Fields of a structure, or a Field, offer to the rest of the description.
#[derive(Debug, Default)]
struct Offer {
    /// The paths later Expressions may read (spec §4.3).
    readable: Vec<Path>,
    /// The paths the Info column may show (spec §3.14).
    shown: Vec<Path>,
}

impl Offer {
    fn extend_under(&mut self, name: &str, inner: Offer, readable: bool, shown: bool) {
        let under = |paths: Vec<Path>| {
            paths.into_iter().map(|path| std::iter::once(name.to_owned()).chain(path).collect::<Path>())
        };
        if readable {
            self.readable.extend(under(inner.readable));
        }
        if shown {
            self.shown.extend(under(inner.shown));
        }
    }
}

struct Renderer<'s> {
    shape: &'s Shape,
    /// Names given so far.
    names: usize,
    /// The Types rendered so far: their names and what their bodies offer.
    types: Vec<(String, Offer)>,
}

fn render(shape: &Shape) -> String {
    let mut renderer = Renderer { shape, names: 0, types: Vec::new() };
    let context = shape.context.then(|| renderer.name());
    let free: Vec<Path> = context.iter().map(|name| vec![name.clone()]).collect();
    let mut types = Vec::new();
    for (i, ty) in shape.types.iter().enumerate() {
        // A Type uses only the Types before it, so none contains itself.
        let (fields, offer) = renderer.layout(&ty.fields, &mut free.clone(), i);
        let mut body = Vec::new();
        if let Some(endian) = ty.endian {
            body.push(("endian".to_owned(), Yaml::plain(endian)));
        }
        body.push(("fields".to_owned(), fields));
        let name = format!("Type{i}Body");
        types.push((name.clone(), Yaml::Map(body)));
        renderer.types.push((name, offer));
    }
    let framing = shape.framing.as_ref().map(|framing| renderer.framing(framing));
    let mut visible = free;
    if let Some((_, _, header)) = &framing {
        visible.extend(header.iter().cloned());
    }
    let (fields, mut offer) = renderer.layout(&shape.fields, &mut visible, shape.types.len());
    let Yaml::Seq(mut fields) = fields else { unreachable!("a layout is a sequence") };
    if let Some(name) = context {
        fields.insert(
            0,
            Yaml::Map(vec![("name".to_owned(), Yaml::plain(&name)), ("type".to_owned(), Yaml::plain("uint16"))]),
        );
        offer.shown.push(vec![name]);
    }
    let framing = framing.map(|(framing, field, header)| {
        fields.insert(0, field);
        offer.shown.extend(header);
        framing
    });
    let mut top = Vec::new();
    for key in &shape.order {
        let value = match *key {
            "name" => Some(Yaml::plain(shape.name)),
            "title" => shape.title.map(Yaml::quoted),
            "registration" => shape.registration.as_ref().map(registration),
            "framing" => framing.clone(),
            "endian" => shape.endian.map(Yaml::plain),
            "info" => shape.info.as_ref().map(|pieces| Yaml::quoted(&info(pieces, &offer.shown))),
            "fields" => Some(Yaml::Seq(fields.clone())),
            "types" => (!types.is_empty()).then(|| Yaml::Map(types.clone())),
            "enums" => (!shape.enums.is_empty()).then(|| {
                Yaml::Map(shape.enums.iter().enumerate().map(|(i, table)| (format!("E{i}"), values(table))).collect())
            }),
            "allow" => shape.allow.as_ref().map(|names| Yaml::Seq(names.iter().map(Yaml::plain).collect())),
            other => unreachable!("`{other}` is not a top-level key"),
        };
        if let Some(value) = value {
            top.push(((*key).to_owned(), value));
        }
    }
    let mut out = String::new();
    block_map(&top, &mut out, 0, false);
    out
}

fn registration(registration: &Registration) -> Yaml {
    let ports = |keys: &Keys| Yaml::Seq(keys.keys().map(|(key, _)| key).collect());
    let mut transports = Vec::new();
    if let Some(udp) = &registration.udp {
        transports.push(("udp".to_owned(), ports(udp)));
    }
    if let Some(tcp) = &registration.tcp {
        transports.push(("tcp".to_owned(), ports(tcp)));
    }
    Yaml::Map(vec![("ports".to_owned(), Yaml::Map(transports))])
}

/// The Info template: text with escaped braces, and references to Fields it may show.
fn info(pieces: &[InfoPiece], shown: &[Path]) -> String {
    let mut template = String::new();
    for piece in pieces {
        match piece {
            InfoPiece::Text(text) => template.push_str(&text.replace('{', "{{").replace('}', "}}")),
            InfoPiece::Field(index) if !shown.is_empty() => {
                template.push('{');
                template.push_str(&index.get(shown).join("."));
                template.push('}');
            }
            InfoPiece::Field(_) => {}
        }
    }
    template
}

fn values(table: &Table) -> Yaml {
    Yaml::Map(
        table.keys.keys().zip(&table.labels).map(|((key, _), label)| (key_text(&key), Yaml::quoted(label))).collect(),
    )
}

fn key_text(key: &Yaml) -> String {
    let mut text = String::new();
    key.flow(&mut text);
    text
}

impl Keys {
    /// Each key as written, with its bounds.
    fn keys(&self) -> impl Iterator<Item = (Yaml, (i64, i64))> + '_ {
        let mut next = self.start;
        self.steps.iter().map(move |&(gap, width, style)| {
            let low = next + i64::from(gap);
            let high = low + i64::from(width);
            next = high + 1;
            let key = if low == high {
                match style % 3 {
                    0 if low >= 0 => Yaml::plain(format_args!("{low:#x}")),
                    _ => Yaml::plain(low),
                }
            } else {
                match style % 3 {
                    0 if low >= 0 => Yaml::plain(format_args!("{low}-{high}")),
                    1 => Yaml::quoted(&format!("{low} - {high}")),
                    _ => Yaml::quoted(&format!("{low}-{high}")),
                }
            };
            (key, (low, high))
        })
    }

    /// A single key, or a list of them.
    fn one_or_list(&self) -> Yaml {
        let mut keys: Vec<Yaml> = self.keys().map(|(key, _)| key).collect();
        if keys.len() == 1 { keys.remove(0) } else { Yaml::Seq(keys) }
    }
}

impl Renderer<'_> {
    fn name(&mut self) -> String {
        let n = self.names;
        self.names += 1;
        match KEYWORD_NAMES.get(n / 2) {
            Some(keyword) if n % 2 == 1 => (*keyword).to_owned(),
            _ if n % 4 == 2 => format!("msg_type_{n}"),
            _ => format!("f{n}"),
        }
    }

    /// `framing:`, the length Field it reads, first in the layout, and that Field's paths.
    fn framing(&mut self, framing: &Framing) -> (Yaml, Yaml, Vec<Path>) {
        let name = self.name();
        let bits = u32::from(framing.bytes) * 8;
        let mut field =
            vec![("name".to_owned(), Yaml::plain(&name)), ("type".to_owned(), Yaml::plain(format_args!("uint{bits}")))];
        let mut readable = vec![vec![name.clone()]];
        if framing.bits {
            let (high, low) = (self.name(), self.name());
            field.push((
                "bits".to_owned(),
                Yaml::Seq(vec![
                    Yaml::Map(vec![("name".to_owned(), Yaml::plain(&high)), ("width".to_owned(), Yaml::plain(4))]),
                    Yaml::Map(vec![
                        ("name".to_owned(), Yaml::plain(&low)),
                        ("width".to_owned(), Yaml::plain(bits - 4)),
                    ]),
                ]),
            ));
            readable.push(vec![name.clone(), high]);
            readable.push(vec![name.clone(), low]);
        }
        let size = u64::from(framing.bytes + framing.extra);
        let mut length = expression(&framing.length, &readable, false);
        if length.constant().is_some_and(|value| value.map_or(true, |value| value < i64::try_from(size).unwrap_or(0))) {
            length = binary(BinaryOp::Add, path(vec![name.clone()]), int(size));
        }
        let framing = Yaml::Map(vec![
            ("header".to_owned(), Yaml::plain(size)),
            ("length".to_owned(), Yaml::quoted(&length.to_string())),
        ]);
        (framing, Yaml::Map(field), readable)
    }

    /// A structure read where `visible` paths are readable, using the first `types` Types.
    fn layout(&mut self, layout: &Layout, visible: &mut Vec<Path>, types: usize) -> (Yaml, Offer) {
        let mark = visible.len();
        let mut entries = Vec::new();
        let mut offer = Offer::default();
        for entry in layout {
            match entry {
                Entry::Padding(amount) => {
                    entries.push(Yaml::Map(vec![("padding".to_owned(), operand(amount, visible, true))]));
                }
                Entry::Field(field) => {
                    let (yaml, name, inner) = self.field(field, visible, types);
                    let readable = field.condition.is_none();
                    let start = offer.readable.len();
                    offer.extend_under(&name, inner, readable, true);
                    visible.extend(offer.readable[start..].iter().cloned());
                    entries.push(yaml);
                }
            }
        }
        visible.truncate(mark);
        (Yaml::Seq(entries), offer)
    }

    /// A Field, its name, and what it offers below its name: an empty path for itself.
    fn field(&mut self, field: &FieldShape, visible: &mut Vec<Path>, types: usize) -> (Yaml, String, Offer) {
        let name = self.name();
        let mut map = vec![("name".to_owned(), Yaml::plain(&name))];
        let itself = || vec![Vec::new()];
        let mut endian = field.endian;
        let offer = match &field.kind {
            Kind::Int { bytes, signed, display, mapping, expect, bits } => {
                let prefix = if *signed { "int" } else { "uint" };
                map.push(("type".to_owned(), Yaml::plain(format_args!("{prefix}{}", u32::from(*bytes) * 8))));
                if let Some(display) = display {
                    let display = if *signed { "dec" } else { display.get(UNSIGNED_DISPLAYS) };
                    map.push(("display".to_owned(), Yaml::plain(display)));
                }
                if let Some(mapping) = mapping {
                    map.extend(self.mapping(mapping));
                }
                if let Some(expect) = expect {
                    map.push(("expect".to_owned(), expect.one_or_list()));
                }
                let mut offer = Offer { readable: itself(), shown: itself() };
                if let (Some(bits), false) = (bits, signed) {
                    let (yaml, names) = self.bits(bits, u32::from(*bytes) * 8);
                    map.push(("bits".to_owned(), yaml));
                    offer.readable.extend(names.iter().map(|n| vec![n.clone()]));
                    offer.shown.extend(names.into_iter().map(|n| vec![n]));
                }
                offer
            }
            Kind::Bool { .. } | Kind::Float { .. } | Kind::Fixed(_) | Kind::Time { .. } | Kind::Text { .. } => {
                value(&field.kind, &mut map, visible)
            }
            Kind::Structure { fields, array } => {
                let (fields, inner) = self.layout(fields, visible, types);
                map.push(("fields".to_owned(), fields));
                push_repeat(&mut map, array.as_ref(), visible);
                if array.is_some() { Offer::default() } else { inner }
            }
            Kind::Type { ty, array } if types > 0 => {
                endian = None;
                let (ty, inner) = &self.types[ty.index(types)];
                map.push(("type".to_owned(), Yaml::plain(ty)));
                push_repeat(&mut map, array.as_ref(), visible);
                if array.is_some() {
                    Offer::default()
                } else {
                    Offer { readable: inner.readable.clone(), shown: inner.shown.clone() }
                }
            }
            // No Type to use yet: an integer instead.
            Kind::Type { .. } => {
                map.push(("type".to_owned(), Yaml::plain("uint8")));
                Offer { readable: itself(), shown: itself() }
            }
            Kind::Switch { subject, cases, keys, default } => {
                endian = None;
                map.push(("switch".to_owned(), operand(subject, visible, false)));
                let mut shown = itself();
                let mut rendered = Vec::new();
                for ((key, _), body) in keys.keys().zip(cases) {
                    let (yaml, inner) = self.body(body, visible, types);
                    shown.extend(inner);
                    rendered.push((key_text(&key), yaml));
                }
                map.push(("cases".to_owned(), Yaml::Map(rendered)));
                if let Some(body) = default {
                    let (yaml, inner) = self.body(body, visible, types);
                    shown.extend(inner);
                    map.push(("default".to_owned(), yaml));
                }
                Offer { readable: Vec::new(), shown }
            }
        };
        if let Some(endian) = endian {
            map.push(("endian".to_owned(), Yaml::plain(endian)));
        }
        if let Some(condition) = &field.condition {
            map.push(("if".to_owned(), operand(condition, visible, false)));
        }
        if let Some(hidden) = field.hidden {
            map.push(("hidden".to_owned(), Yaml::plain(hidden)));
        }
        if let Some(label) = field.label {
            map.push(("label".to_owned(), Yaml::quoted(label)));
        }
        if let Some(description) = field.description {
            map.push(("description".to_owned(), Yaml::quoted(description)));
        }
        (Yaml::Map(map), name, offer)
    }

    /// A case or a default, and the paths below the `switch` Field it shows: a case adds no
    /// segment (spec §3.9).
    fn body(&mut self, body: &Body, visible: &mut Vec<Path>, types: usize) -> (Yaml, Vec<Path>) {
        match body {
            Body::Type(ty) if types > 0 => {
                let (name, offer) = &self.types[ty.index(types)];
                (Yaml::plain(name), offer.shown.clone())
            }
            Body::Type(_) => {
                let name = self.name();
                let field =
                    Yaml::Map(vec![("name".to_owned(), Yaml::plain(&name)), ("type".to_owned(), Yaml::plain("uint8"))]);
                (Yaml::Seq(vec![field]), vec![vec![name]])
            }
            Body::Fields(fields) => {
                let (yaml, offer) = self.layout(fields, visible, types);
                (yaml, offer.shown)
            }
        }
    }

    fn mapping(&self, mapping: &Mapping) -> Option<(String, Yaml)> {
        match mapping {
            Mapping::Values(table) => Some(("values".to_owned(), values(table))),
            Mapping::Enum(index) if !self.shape.enums.is_empty() => {
                Some(("values".to_owned(), Yaml::plain(format_args!("E{}", index.index(self.shape.enums.len())))))
            }
            Mapping::Enum(_) => None,
            Mapping::Unit(unit) => Some(("unit".to_owned(), unit_yaml(unit))),
        }
    }

    /// The `bits:` of a container `width` bits wide, and the names of its sub-Fields.
    fn bits(&mut self, bits: &Bits, width: u32) -> (Yaml, Vec<String>) {
        let mut cuts: Vec<u32> = bits
            .cuts
            .iter()
            .map(|cut| u32::try_from(cut.index(width as usize - 1)).expect("a bit position") + 1)
            .collect();
        cuts.sort_unstable();
        cuts.dedup();
        let mut entries = Vec::new();
        let mut names = Vec::new();
        let mut from = 0;
        for (i, to) in cuts.into_iter().chain([width]).enumerate() {
            let size = to - from;
            from = to;
            let bit = &bits.entries[i % bits.entries.len()];
            let Bit::Sub { display, mapping, labels, expect, hidden, label, description } = bit else {
                entries.push(Yaml::Map(vec![("padding".to_owned(), Yaml::plain(size))]));
                continue;
            };
            let name = self.name();
            let mut map = vec![("name".to_owned(), Yaml::plain(&name)), ("width".to_owned(), Yaml::plain(size))];
            let mapping = mapping.as_ref().and_then(|m| self.mapping(m));
            // One bit is a boolean unless `display`, `values` or `unit` make it an integer.
            let integer = size > 1 || display.is_some() || mapping.is_some();
            if integer {
                if let Some(display) = display {
                    map.push(("display".to_owned(), Yaml::plain(display.get(UNSIGNED_DISPLAYS))));
                }
                map.extend(mapping);
                if let Some(expect) = expect {
                    map.push(("expect".to_owned(), expect.one_or_list()));
                }
            } else {
                push_labels(&mut map, *labels);
                if let Some(expect) = expect {
                    let values: Vec<bool> = expect.keys().map(|(_, (low, _))| low % 2 == 1).collect();
                    map.push(("expect".to_owned(), bool_expect(&values)));
                }
            }
            if let Some(hidden) = hidden {
                map.push(("hidden".to_owned(), Yaml::plain(hidden)));
            }
            if let Some(label) = label {
                map.push(("label".to_owned(), Yaml::quoted(label)));
            }
            if let Some(description) = description {
                map.push(("description".to_owned(), Yaml::quoted(description)));
            }
            entries.push(Yaml::Map(map));
            names.push(name);
        }
        (Yaml::Seq(entries), names)
    }
}

/// Adds the keys of a Field of a built-in type other than an integer, and says what it offers.
fn value(kind: &Kind, map: &mut Vec<(String, Yaml)>, visible: &[Path]) -> Offer {
    let itself = || vec![Vec::new()];
    match kind {
        Kind::Bool { labels, expect } => {
            map.push(("type".to_owned(), Yaml::plain("bool")));
            push_labels(map, *labels);
            if let Some(expect) = expect {
                map.push(("expect".to_owned(), bool_expect(expect)));
            }
            Offer { readable: itself(), shown: itself() }
        }
        Kind::Float { double, unit } => {
            map.push(("type".to_owned(), Yaml::plain(if *double { "float64" } else { "float32" })));
            if let Some(unit) = unit {
                map.push(("unit".to_owned(), unit_yaml(unit)));
            }
            Offer { readable: Vec::new(), shown: itself() }
        }
        Kind::Fixed(ty) => {
            map.push(("type".to_owned(), Yaml::plain(ty)));
            Offer { readable: Vec::new(), shown: itself() }
        }
        Kind::Time { relative, encoding, display } => {
            let (ty, encodings) =
                if *relative { ("rel_time", REL_TIME_ENCODINGS) } else { ("abs_time", ABS_TIME_ENCODINGS) };
            map.push(("type".to_owned(), Yaml::plain(ty)));
            if let Some(encoding) = encoding {
                map.push(("encoding".to_owned(), Yaml::plain(encoding.get(encodings))));
            }
            if let (Some(display), false) = (display, relative) {
                map.push(("display".to_owned(), Yaml::plain(display.get(TIME_DISPLAYS))));
            }
            Offer { readable: Vec::new(), shown: itself() }
        }
        Kind::Text { bytes, length, encoding, display, dissector } => {
            map.push(("type".to_owned(), Yaml::plain(if *bytes { "bytes" } else { "string" })));
            let encoding = encoding.filter(|_| !bytes).map(|e| *e.get(STRING_ENCODINGS));
            let wide = matches!(encoding, Some("utf16" | "ucs2"));
            map.push(match length {
                Length::Size(amount) => ("size".to_owned(), operand(amount, visible, true)),
                Length::Remaining => ("size".to_owned(), Yaml::quoted("_remaining")),
                Length::Prefix(ty) => ("prefix".to_owned(), Yaml::plain(ty)),
                // A 2-byte code unit ends only at a 2-byte zero.
                Length::Terminator(byte) => ("terminator".to_owned(), Yaml::plain(if wide { 0 } else { *byte })),
            });
            if let Some(encoding) = encoding {
                map.push(("encoding".to_owned(), Yaml::plain(encoding)));
            }
            if *bytes {
                if let Some(display) = display {
                    map.push(("display".to_owned(), Yaml::plain(display.get(BYTES_DISPLAYS))));
                }
                if let Some(dissector) = dissector {
                    map.push(("dissector".to_owned(), Yaml::plain(dissector)));
                }
            }
            Offer { readable: Vec::new(), shown: itself() }
        }
        Kind::Int { .. } | Kind::Structure { .. } | Kind::Type { .. } | Kind::Switch { .. } => {
            unreachable!("not a value of a built-in type other than an integer")
        }
    }
}

fn push_labels(map: &mut Vec<(String, Yaml)>, (true_label, false_label): (Option<&str>, Option<&str>)) {
    if let Some(label) = true_label {
        map.push(("true".to_owned(), Yaml::quoted(label)));
    }
    if let Some(label) = false_label {
        map.push(("false".to_owned(), Yaml::quoted(label)));
    }
}

fn push_repeat(map: &mut Vec<(String, Yaml)>, array: Option<&Repeat>, visible: &[Path]) {
    match array {
        Some(Repeat::Count(count)) => map.push(("count".to_owned(), operand(count, visible, true))),
        Some(Repeat::ToEnd) => map.push(("repeat".to_owned(), Yaml::plain("to_end"))),
        None => {}
    }
}

fn bool_expect(values: &[bool]) -> Yaml {
    let mut values: Vec<Yaml> = values.iter().map(|&v| Yaml::plain(u8::from(v))).collect();
    if values.len() == 1 { values.remove(0) } else { Yaml::Seq(values) }
}

fn unit_yaml(unit: &Unit) -> Yaml {
    match unit {
        Unit::One(one) => Yaml::quoted(one),
        Unit::Two(one, many) => Yaml::Seq(vec![Yaml::quoted(one), Yaml::quoted(many)]),
    }
}

/// An operand reading the `visible` paths. A constant amount (a size, count or padding) is never
/// negative and never faults, as validation requires (spec §3.6).
fn operand(operand: &Operand, visible: &[Path], amount: bool) -> Yaml {
    match operand {
        Operand::Constant(value) => Yaml::plain(value),
        Operand::Expr(shape) => {
            let mut expr = expression(shape, visible, true);
            if amount && expr.constant().is_some_and(|value| value.map_or(true, |value| value < 0)) {
                expr = int(1);
            }
            Yaml::quoted(&expr.to_string())
        }
    }
}

/// The Expression of `shape`, its paths picked among `visible`, or literals when none is.
fn expression(shape: &ExprShape, visible: &[Path], builtins: bool) -> Expr {
    match shape {
        ExprShape::Int(value) => int(*value),
        ExprShape::Path(index) if !visible.is_empty() => path(index.get(visible).clone()),
        ExprShape::Path(index) => int(index.index(256) as u64),
        ExprShape::Builtin(builtin) if builtins => leaf(ExprKind::Builtin(*builtin)),
        ExprShape::Builtin(_) => int(4),
        ExprShape::Unary(op, operand) => leaf(ExprKind::Unary {
            op: Spanned { value: *op, span: 0..0 },
            operand: Box::new(expression(operand, visible, builtins)),
        }),
        ExprShape::Binary(op, left, right) => {
            binary(*op, expression(left, visible, builtins), expression(right, visible, builtins))
        }
    }
}

fn leaf(kind: ExprKind) -> Expr {
    Expr { kind, span: 0..0 }
}

fn int(value: u64) -> Expr {
    leaf(ExprKind::Int(value))
}

fn path(segments: Path) -> Expr {
    leaf(ExprKind::Path(segments))
}

fn binary(op: BinaryOp, left: Expr, right: Expr) -> Expr {
    leaf(ExprKind::Binary { op: Spanned { value: op, span: 0..0 }, left: Box::new(left), right: Box::new(right) })
}

#[cfg(test)]
mod tests {
    use proptest::strategy::ValueTree;

    use super::*;
    use crate::source::Source;
    use crate::{RenderOptions, yaml};

    /// `validate` accepts every description, and generation gives the same bytes twice.
    #[test]
    fn validate_accepts_them_and_generation_is_deterministic() {
        check(|text| {
            let source = Source::new("random.wirdigen.yaml", text);
            let generate = || match crate::validate(&source) {
                Ok(valid) => Ok(valid.generate()),
                Err(diagnostics) => Err(TestCaseError::fail(diagnostics.render(&source, &RenderOptions::default()))),
            };
            let lua = generate()?;
            prop_assert!(lua == generate()?, "two generations differ");
            Ok(())
        });
    }

    /// The JSON Schema accepts every description (spec §6.5).
    #[test]
    fn the_schema_accepts_them() {
        check(|text| {
            let validator = crate::schema::testing::validator();
            let root = yaml::parse(text).expect("valid YAML").expect("not empty");
            let instance = crate::schema::testing::to_json(&root);
            let errors: Vec<String> =
                validator.iter_errors(&instance).map(|e| format!("{e} at {}", e.instance_path())).collect();
            prop_assert!(errors.is_empty(), "{}", errors.join("\n"));
            Ok(())
        });
    }

    /// Every construct of the v1 language turns up among a few hundred descriptions.
    #[test]
    fn the_strategy_covers_the_language() {
        let texts: Vec<String> = deep_stack(|| {
            let mut runner = TestRunner::deterministic();
            let strategy = description();
            (0..300).map(|_| strategy.new_tree(&mut runner).expect("a description").current().0).collect()
        });
        let missing: Vec<&str> = [
            "title:",
            "registration:",
            "udp:",
            "tcp:",
            "framing:",
            "endian: little",
            "info:",
            "types:",
            "enums:",
            "allow:",
            "padding:",
            "bits:",
            "width:",
            "count:",
            "repeat: to_end",
            "switch:",
            "cases:",
            "default:",
            "if:",
            "hidden: true",
            "label:",
            "description:",
            "display:",
            "encoding:",
            "values:",
            "unit:",
            "true:",
            "false:",
            "expect:",
            "size:",
            "_remaining",
            "_offset",
            "prefix:",
            "terminator:",
            "dissector:",
            "type: uint40",
            "type: int24",
            "type: bool",
            "type: float64",
            "type: guid",
            "type: abs_time",
            "type: rel_time",
            "type: string",
            "type: bytes",
            "type: Type",
            "values: E",
            "name: end",
        ]
        .into_iter()
        .filter(|construct| !texts.iter().any(|text| text.contains(construct)))
        .collect();
        assert!(missing.is_empty(), "never drawn: {missing:?}");
    }
}
