//! Lowering: a validated description becomes a private, Dissector-shaped model (ADR 0010).
//!
//! Everything lowering relies on is checked by validation, so it cannot fail: a surprise here is
//! a Wirdigen bug and panics, it is never a Diagnostic.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use crate::bits::Bit;
use crate::description::Protocol;
use crate::expect::Expect;
use crate::expr::{self, BinaryOp, Expr, ExprKind, UnaryOp};
use crate::field::{
    self, Amount, Array, Builtin, BuiltinField, Display, Encoding, Endian, Field, FieldKind, Operand, default_label,
};
use crate::mapping::{self, Entry, Mapping, Table, Values};
use crate::prelude;
use crate::scope::Reference;
use crate::switch::{Body, Switch, wire_ranges};
use crate::types::NamedType;

/// The model the emitter prints.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Dissector {
    /// The Source name's last path component.
    pub(crate) source_name: String,
    /// The protocol's filter name (`demo`).
    pub(crate) filter_name: String,
    /// The Protocol column text (`DEMO`).
    pub(crate) short_name: String,
    /// The tree root text.
    pub(crate) full_name: String,
    /// The value tables of Enums, each declared once before the `ProtoField`s that use it.
    pub(crate) tables: Vec<SharedTable>,
    /// The tables `switch` Fields name their subject's value from, each declared once.
    pub(crate) names: Vec<NamesTable>,
    /// The `ProtoField`s to register, each once.
    pub(crate) proto_fields: Vec<ProtoField>,
    /// The site tables of the uses of Types outside any Type, each declared once.
    pub(crate) sites: Vec<SharedSite>,
    /// The dissect functions of the Types, each after the Types it calls (spec §7.3).
    pub(crate) types: Vec<TypeFunction>,
    /// The statements of the top-level layout.
    pub(crate) layout: Vec<Stmt>,
    /// The locals the top-level layout keeps values Expressions read in, declared up front.
    pub(crate) locals: Vec<String>,
    /// The prelude chunks the Dissector uses, before dependencies are added.
    pub(crate) chunks: Vec<&'static str>,
}

/// A `ProtoField` to register.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProtoField {
    /// The mangled Lua local (`f_length`).
    pub(crate) local: String,
    /// The filter name (`demo.length`).
    pub(crate) abbrev: String,
    /// The tree text.
    pub(crate) label: String,
    /// The blurb, if any.
    pub(crate) description: Option<String>,
    pub(crate) field_type: FieldType,
    /// What Wireshark shows in place of, or after, the value.
    pub(crate) strings: Option<Strings>,
    /// The bits of the container a bitfield sub-Field holds (spec §3.8).
    pub(crate) mask: Option<Mask>,
}

/// The mask of a bitfield sub-Field's `ProtoField`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mask {
    /// The bits of the container the sub-Field holds.
    pub(crate) bits: u64,
    /// The bytes of the container, which the mask is written as wide as.
    pub(crate) bytes: usize,
}

/// The labels of a `ProtoField`, in the argument a constructor calls its valuestring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Strings {
    /// A value string, or a range string (`base.RANGE_STRING`) when `range`.
    Table { table: TableRef, range: bool },
    /// A unit (`base.UNIT_STRING` on an integer), each form already starting with its space.
    Unit { singular: String, plural: Option<String> },
    /// The labels of a `bool`'s two states.
    TrueFalse { when_true: String, when_false: String },
}

/// Where a value table is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TableRef {
    /// In the `ProtoField`'s constructor call.
    Inline(LuaTable),
    /// In a local declared once: an index into [`Dissector::tables`].
    Shared(usize),
}

/// A value table as Wireshark reads it: keys and bounds as the `ProtoField`'s unsigned integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LuaTable {
    /// `{ [key] = label }`.
    Values(Vec<(i64, String)>),
    /// `{ { low, high, label } }`.
    Ranges(Vec<(i64, i64, String)>),
}

impl LuaTable {
    fn is_empty(&self) -> bool {
        match self {
            Self::Values(entries) => entries.is_empty(),
            Self::Ranges(entries) => entries.is_empty(),
        }
    }
}

/// The table of an Enum for the `ProtoField`s of one width and signedness.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SharedTable {
    /// The Lua local (`enum_MsgType`).
    pub(crate) local: String,
    /// The Enum it comes from.
    enum_name: String,
    pub(crate) table: LuaTable,
}

/// The labels of a `switch` subject's values (spec §3.9), as the Expression has them: signed
/// 64-bit integers.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NamesTable {
    /// The Lua local (`names_body`).
    pub(crate) local: String,
    /// `(low, high, label)`, in table order.
    pub(crate) entries: Vec<(i64, i64, String)>,
}

/// A Wireshark field type: how a `ProtoField` is declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldType {
    /// The `ProtoField.<constructor>` function (`uint16`, `ipv4`).
    pub(crate) constructor: &'static str,
    pub(crate) args: Args,
}

/// The arguments a `ProtoField` constructor takes after its filter name and label, which also
/// says where the blurb goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Args {
    /// `(display, valuestring, mask, description)`, as integers and `bool` take them; the
    /// display (`base.DEC`) is always written.
    Display(&'static str),
    /// `(display, description)`, as `string`, `stringz` and `bytes` take them; the display is
    /// always written.
    Base(&'static str),
    /// `(description)` only. `float` and `double` take a unit table first, but only when it is a
    /// table: without one their blurb is the third argument, not a `nil` unit then the blurb.
    Plain,
}

impl FieldType {
    const fn new(constructor: &'static str, args: Args) -> Self {
        Self { constructor, args }
    }
}

/// The dissect function of a Type: one per Type, shared by every use of it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TypeFunction {
    /// The Type's name.
    pub(crate) name: String,
    /// The statements of its Fields, whose paths are relative to the Type and whose
    /// `ProtoField`s are slots of the site table it is passed.
    pub(crate) body: Vec<Stmt>,
    /// Whether it takes a context table: the values of names it reads but does not declare.
    pub(crate) context: bool,
    /// The locals it keeps values Expressions read in, declared up front.
    pub(crate) locals: Vec<String>,
    /// What it returns after the offset, for callers whose Expressions read inside it: by key,
    /// a local, or a table of them. Empty when no caller reads inside it.
    pub(crate) exports: BTreeMap<String, Export>,
}

/// An entry of the table a Type's dissect function returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Export {
    /// The local holding a value, or the table a Type's function returned.
    Local(String),
    /// The entries of an inline structure.
    Table(BTreeMap<String, Export>),
}

/// The site table of one use of a Type: the `ProtoField`s registered for that use (spec §5.2),
/// passed to the Type's dissect function, by slot key.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Site {
    /// The path of the Field using the Type, which the Type's paths extend in truncation reports.
    pub(crate) path: String,
    /// The slots, in the Type's layout order: `f_<path>` holds a `ProtoField`, `t_<path>` the site
    /// table of a Type the Type uses.
    pub(crate) entries: Vec<(String, SiteEntry)>,
}

/// What a slot of a site table holds.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SiteEntry {
    /// Index into [`Dissector::proto_fields`].
    Field(usize),
    /// The site table of a use of a Type inside the Type.
    Site(Site),
}

/// The site table of a use of a Type outside any Type, declared once as a Lua local.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SharedSite {
    /// The Lua local (`site_req_hdr`).
    pub(crate) local: String,
    pub(crate) site: Site,
}

/// How a statement reaches a `ProtoField` or a site table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ref {
    /// A Lua local, outside any Type: an index into [`Dissector::proto_fields`] or
    /// [`Dissector::sites`].
    Local(usize),
    /// A slot of the site table, inside a Type's dissect function.
    Slot(String),
}

/// One step of a dissect function.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stmt {
    /// `{ padding: n }` (spec §3.10): bytes skipped, bounds-checked and shown as one "Padding"
    /// item with no `ProtoField`.
    Padding {
        /// The path of the structure the padding is in, empty at the top level, for the
        /// malformed-packet reports.
        parent: String,
        /// How many bytes are skipped: [`Length::Fixed`] or [`Length::Expression`].
        length: Length,
    },
    /// A bounds-checked read added to the tree.
    Read {
        field: Ref,
        length: Length,
        decode: Decode,
        /// The Field's path, for the comment and the truncation report.
        path: String,
        /// The local its value is kept in, when an Expression reads it.
        value: Option<Value>,
        /// Whether the item is hidden: left out of the tree, still filtered.
        hidden: bool,
        /// The sub-Fields of a bitfield, added under its item from the same bytes.
        bits: Vec<BitItem>,
        /// How the value is read into the local `value` for the `expect:` checks of the Field
        /// and its sub-Fields, when any has one.
        checked: Option<ValueRead>,
        /// The check of the Field's own `expect:`.
        expect: Option<Expected>,
    },
    /// An inline structure: a subtree item holding the statements of its Fields, as long as
    /// the bytes they read.
    Structure {
        field: Ref,
        /// The Field's path, for the comment.
        path: String,
        /// Whether the subtree item is hidden: left out of the tree with what it holds, still
        /// filtered (spec §3.10).
        hidden: bool,
        /// The statements of its Fields, inside the subtree.
        body: Vec<Stmt>,
    },
    /// A Field of a Type: a subtree item, filled by the Type's dissect function called with the
    /// site table of this use, as long as the bytes it read.
    Call {
        field: Ref,
        /// The Field's path, for the comment.
        path: String,
        /// Whether the subtree item is hidden, as for [`Stmt::Structure`].
        hidden: bool,
        /// The Type's name.
        ty: String,
        /// The site table of this use.
        site: Ref,
        /// The context table passed, by key, when the Type reads names it does not declare.
        context: Vec<(String, LuaExpr)>,
        /// The local the table the Type returns is kept in, when an Expression reads inside it.
        result: Option<String>,
    },
    /// An array (spec §3.7): its element, a [`Stmt::Structure`] or a [`Stmt::Call`], repeated,
    /// each element its own subtree item with the same `ProtoField`s. An element that reads no
    /// bytes stops the array as malformed.
    Array {
        /// The Field's path, for the comment and the malformed-packet reports.
        path: String,
        repeat: Repeat,
        element: Box<Stmt>,
    },
    /// A Field under `if:` (spec §3.9): `body`, the statement reading it, runs only when the
    /// condition is not zero.
    If {
        /// The Field's path, for the malformed-packet report of a condition with no value.
        path: String,
        /// The condition, never checked for a sign: any value other than zero is true (§4.4).
        condition: Computed,
        body: Box<Stmt>,
    },
    /// A `switch` Field (spec §3.9): a subtree item, holding what the case matching the subject
    /// reads, or the rest of the message shown raw with a note when none does.
    Switch {
        field: Ref,
        /// The Field's path, for the comment and the reports.
        path: String,
        /// Whether the subtree item is hidden, as for [`Stmt::Structure`].
        hidden: bool,
        subject: Computed,
        /// The table the subtree item names the subject's value from, an index into
        /// [`Dissector::names`]; without one it shows the number.
        names: Option<usize>,
        /// Each case, by the values it matches, as signed 64-bit ranges.
        cases: Vec<(Vec<(i64, i64)>, Branch)>,
        /// What is read when no case matches; without it, the rest of the message is shown
        /// raw with a note.
        default: Option<Branch>,
    },
}

/// What a `switch` case reads, straight into the `switch` Field's subtree.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Branch {
    /// The statements of inline Fields.
    Fields(Vec<Stmt>),
    /// A call of a Type's dissect function, with no item of its own.
    Call {
        ty: String,
        /// The site table of this use.
        site: Ref,
        /// The context table passed, by key.
        context: Vec<(String, LuaExpr)>,
    },
}

/// How many times an array repeats its element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Repeat {
    /// As many times as this Expression gives, evaluated once before the first element.
    Count(Computed),
    /// Until the message ends.
    ToEnd,
}

/// A `size:` or `count:` Expression as the Dissector evaluates it, with the checks it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Computed {
    pub(crate) value: LuaExpr,
    /// Whether the value is known only when the packet is read, so a negative one is reported
    /// as malformed (spec §4.4).
    pub(crate) checked: bool,
    /// Whether evaluating it can fault (division by zero, a shift out of 0..63), so it runs
    /// under `wd_evaluate`.
    pub(crate) faults: bool,
}

impl Computed {
    /// A value validation already checked: evaluated as is.
    const fn checked_already(value: LuaExpr) -> Self {
        Self { value, checked: false, faults: false }
    }
}

/// A bitfield sub-Field: a masked `ProtoField` added under its container's item, from the
/// container's bytes, which Wireshark masks and shifts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BitItem {
    /// The sub-Field's `ProtoField`.
    pub(crate) field: Ref,
    /// Whether the item is hidden, as every sub-Field of a hidden container is.
    pub(crate) hidden: bool,
    /// Whether the container is read little-endian (`add_le`).
    pub(crate) little: bool,
    /// The check of the sub-Field's `expect:`.
    pub(crate) expect: Option<Expected>,
}

/// An `expect:` check (spec §3.10): a value matching none of the ranges adds an expert info
/// warning on the item, and the dissection goes on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expected {
    /// The path of the Field or sub-Field checked, for the expert info.
    pub(crate) path: String,
    /// The value checked, read from the local `value` the container's bytes are read into.
    pub(crate) value: LuaExpr,
    /// The values expected, as signed 64-bit ranges: a `uint64` above 2^63 reads as negative.
    pub(crate) ranges: Vec<(i64, i64)>,
    /// The values expected as the expert info shows them: `1, 5-7`.
    pub(crate) text: String,
}

/// Where the value of a read is kept for Expressions, and how it is read (spec §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Value {
    pub(crate) local: String,
    pub(crate) read: ValueRead,
}

/// How an Expression reads a value: as a signed 64-bit integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueRead {
    /// An integer, with this `string.unpack` format (`">I2"`): a `uint64` above 2^63 wraps to
    /// a negative value.
    Integer(String),
    /// A `bool`: 1 when the byte is not zero, else 0.
    Bool,
}

/// Where the value of a read ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Length {
    /// After this many bytes.
    Fixed(usize),
    /// After as many bytes as this Expression gives.
    Expression(Computed),
    /// After as many bytes as the unsigned integer of `size` bytes just before the value says,
    /// read with the `TvbRange` call `read` (`uint()`).
    Prefix { size: usize, read: &'static str },
    /// Before the first `width`-byte run of `terminator`, searched in steps of `width`. The
    /// terminator is consumed but is not part of the value.
    Terminator { terminator: u8, width: usize },
}

/// An Expression compiled to prelude helper calls (ADR 0010): the emitter prints no native
/// bitwise operator or `//`, so the file parses under Lua 5.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LuaExpr {
    /// A literal, wrapping above `i64::MAX` as Lua's hexadecimal integers do.
    Int(u64),
    /// A call of the prelude helper `helper` (`wd_add`).
    Call { helper: &'static str, args: Vec<LuaExpr> },
    /// C's `&&`: 1 when both are non-zero, evaluating the right side only when the left is.
    And(Box<LuaExpr>, Box<LuaExpr>),
    /// C's `||`: 1 when either is non-zero, evaluating the right side only when the left is zero.
    Or(Box<LuaExpr>, Box<LuaExpr>),
    /// A value kept in a local, or inside the table a Type returned, by the keys down to it.
    Local { local: String, keys: Vec<String> },
    /// A value of the context table, by its key.
    Context(String),
    /// `_offset`: the offset of the Field being read.
    Offset,
    /// `_remaining`: the bytes from the Field being read to the end of the packet.
    Remaining,
}

/// Who decodes the bytes of a read, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decode {
    /// Wireshark, big-endian (`tree:add`).
    Big,
    /// Wireshark, little-endian (`tree:add_le`).
    Little,
    /// Wireshark, with this `ENC_*` encoding and, when the encoding has one, this `ENC_*` byte
    /// order (`tree:add_packet_field`).
    Encoded { encoding: &'static str, endian: Option<&'static str> },
    /// The generated Lua, with this `TvbRange` method, and the value is added as is: Lua cannot
    /// declare 40, 48 or 56-bit `ProtoField`s, so they are shown as 64-bit ones.
    Lua(&'static str),
}

pub(crate) fn lower(protocol: &Protocol, source_name: &str) -> Dissector {
    let (top, mut plans) = plans(protocol);
    let mut lowering = Lowering {
        plan: Plan::default(),
        root: &protocol.fields,
        types: &protocol.types,
        filter_name: &protocol.name,
        enums: &protocol.enums,
        proto_fields: Vec::new(),
        tables: Vec::new(),
        names: Vec::new(),
        slots: BTreeMap::new(),
        sites: Vec::new(),
        // The layout is never empty, so every Dissector reads something and checks bounds.
        chunks: vec![prelude::VERSION, prelude::MALFORMED, prelude::BOUNDS],
    };
    // Every Type's slots are known before any use of it builds a site table.
    let mut types = Vec::new();
    for t in &protocol.types {
        let mut slots = Vec::new();
        lowering.plan = plans.remove(&t.name).expect("every Type has a plan");
        lowering.root = &t.fields;
        let body = lowering.type_structure(&t.fields, &[], &mut slots);
        lowering.slots.insert(&t.name, slots);
        let plan = &lowering.plan;
        let exports = plan.export_table();
        types.push(TypeFunction { name: t.name.clone(), body, context: plan.context, locals: plan.locals(), exports });
    }
    lowering.plan = top;
    lowering.root = &protocol.fields;
    let layout = lowering.structure(&protocol.fields, &[]);
    let locals = lowering.plan.locals();
    let Lowering { proto_fields, tables, names, sites, chunks, .. } = lowering;

    let filter_name = protocol.name.clone();
    let short_name = filter_name.to_ascii_uppercase();
    Dissector {
        source_name: source_name.rsplit(['/', '\\']).next().unwrap_or(source_name).to_owned(),
        full_name: protocol.title.clone().unwrap_or_else(|| short_name.clone()),
        short_name,
        filter_name,
        tables,
        names,
        proto_fields,
        sites,
        types,
        layout,
        locals,
        chunks,
    }
}

/// What one dissect function keeps in locals, and for a Type, takes and returns (spec §7.3).
#[derive(Debug, Default)]
struct Plan {
    /// The locals of values Expressions read, by the path of the Field from the function's root.
    values: BTreeMap<Vec<String>, String>,
    /// The locals of the tables Types return, by the path of the Field of the Type.
    results: BTreeMap<Vec<String>, String>,
    /// For a Type: the paths inside it its callers read, which it returns.
    exports: BTreeSet<Vec<String>>,
    /// For a Type: whether it reads its context table.
    context: bool,
}

/// The plans of the top-level layout and of each Type. A caller's Expressions decide what a
/// Type returns, so callers are planned first: the layout, then the Types from the last one,
/// which no other Type uses.
fn plans(protocol: &Protocol) -> (Plan, BTreeMap<String, Plan>) {
    let mut demands: BTreeMap<String, BTreeSet<Vec<String>>> = BTreeMap::new();
    let top = Plan::new(&protocol.fields, BTreeSet::new(), &mut demands);
    let mut plans = BTreeMap::new();
    for t in protocol.types.iter().rev() {
        let exports = demands.remove(&t.name).unwrap_or_default();
        plans.insert(t.name.clone(), Plan::new(&t.fields, exports, &mut demands));
    }
    (top, plans)
}

impl Plan {
    /// The plan of a function reading `fields` that returns `exports`, adding to `demands` the
    /// paths it reads inside each Type.
    fn new(
        fields: &[field::Entry],
        exports: BTreeSet<Vec<String>>,
        demands: &mut BTreeMap<String, BTreeSet<Vec<String>>>,
    ) -> Self {
        let mut read = Vec::new();
        let mut context = false;
        references(fields, &mut |reference| match reference {
            Reference::Field(path) | Reference::Bits { container: path, .. } => read.push(path.clone()),
            Reference::Context(_) => context = true,
        });
        let mut plan = Self { context, ..Self::default() };
        for path in read.iter().chain(&exports) {
            plan.keep(fields, path, demands);
        }
        plan.exports = exports;
        plan
    }

    /// Gives the value at `path` a local: the Field's own, or the table of the Type it is in.
    fn keep(
        &mut self,
        fields: &[field::Entry],
        path: &[String],
        demands: &mut BTreeMap<String, BTreeSet<Vec<String>>>,
    ) {
        let (depth, field) = find(fields, path).expect("validation resolved the path");
        match &field.kind {
            FieldKind::Type { name, .. } => {
                let prefix = path[..=depth].to_vec();
                if !self.results.contains_key(&prefix) {
                    let local = self.local(&prefix);
                    self.results.insert(prefix, local);
                }
                demands.entry(name.clone()).or_default().insert(path[depth + 1..].to_vec());
            }
            FieldKind::Builtin(_) => {
                if !self.values.contains_key(path) {
                    let local = self.local(path);
                    self.values.insert(path.to_vec(), local);
                }
            }
            FieldKind::Structure(_) | FieldKind::Switch(_) => unreachable!("validation references values only"),
        }
    }

    /// A fresh local for the value at `path`: `v_` then the segments joined by `__`.
    fn local(&self, path: &[String]) -> String {
        unique(&format!("v_{}", path.join("__")), |name| {
            self.values.values().chain(self.results.values()).any(|l| l == name)
        })
    }

    /// Every local, in path order.
    fn locals(&self) -> Vec<String> {
        let mut all: Vec<(&Vec<String>, &String)> = self.values.iter().chain(&self.results).collect();
        all.sort();
        all.into_iter().map(|(_, local)| local.clone()).collect()
    }

    /// The Field of a Type on `path` whose returned table holds the value, with its local.
    fn result_for(&self, path: &[String]) -> Option<(&Vec<String>, &String)> {
        self.results.iter().find(|(prefix, _)| path.starts_with(prefix))
    }

    /// How an Expression reads `reference`. A sub-Field is its container's value shifted down and
    /// masked, which needs the bitwise prelude chunk.
    fn read(&self, reference: &Reference) -> LuaExpr {
        match reference {
            Reference::Context(key) => LuaExpr::Context(key.clone()),
            Reference::Bits { container, shift, width } => {
                sub_field_value(self.read(&Reference::Field(container.clone())), *shift, *width)
            }
            Reference::Field(path) => match self.result_for(path) {
                Some((prefix, local)) => LuaExpr::Local { local: local.clone(), keys: path[prefix.len()..].to_vec() },
                None => LuaExpr::Local { local: self.values[path].clone(), keys: Vec::new() },
            },
        }
    }

    /// The table a Type returns: each exported path, nested as its Fields are.
    fn export_table(&self) -> BTreeMap<String, Export> {
        let mut table = BTreeMap::new();
        for path in &self.exports {
            let (keys, local) = match self.result_for(path) {
                Some((prefix, local)) => (prefix.as_slice(), local),
                None => (path.as_slice(), &self.values[path]),
            };
            let (last, parents) = keys.split_last().expect("an export has a path");
            let mut entries = &mut table;
            for key in parents {
                let entry = entries.entry(key.clone()).or_insert_with(|| Export::Table(BTreeMap::new()));
                let Export::Table(inner) = entry else { unreachable!("a structure is not a value") };
                entries = inner;
            }
            entries.insert(last.clone(), Export::Local(local.clone()));
        }
        table
    }
}

/// The Field `path` leads to from `fields`, with its index on the path: the Field at the end
/// of the path, or the Field of a Type the path goes into. Inside a `switch` Field the path goes
/// on in the case that has the rest of it: cases reaching one path share its `ProtoField`, so
/// they have the same kind of Field there (spec §3.9).
fn find<'f>(fields: &'f [field::Entry], path: &[String]) -> Option<(usize, &'f Field)> {
    fn from<'f>(fields: &'f [field::Entry], path: &[String], depth: usize) -> Option<(usize, &'f Field)> {
        let field = fields.iter().filter_map(field::Entry::field).find(|f| f.name == path[depth])?;
        if depth + 1 == path.len() {
            return Some((depth, field));
        }
        match &field.kind {
            FieldKind::Type { .. } => Some((depth, field)),
            FieldKind::Builtin(_) => None,
            FieldKind::Structure(children) => from(children, path, depth + 1),
            FieldKind::Switch(switch) => switch.bodies().find_map(|body| match body {
                Body::Fields(children) => from(children, path, depth + 1),
                Body::Type { .. } => None,
            }),
        }
    }
    from(fields, path, 0)
}

/// Calls `f` with every reference the Expressions of `entries` and the context tables of their
/// uses of Types make, inline structures and `switch` cases included.
fn references(entries: &[field::Entry], f: &mut impl FnMut(&Reference)) {
    for entry in entries {
        let field = match entry {
            field::Entry::Field(field) => field,
            field::Entry::Padding(amount) => {
                if let Amount::Expression { references, .. } = amount {
                    references.values().for_each(&mut *f);
                }
                continue;
            }
        };
        if let Some(Operand::Expression { references, .. }) = &field.condition {
            references.values().for_each(&mut *f);
        }
        if let Some(Array::Count(Amount::Expression { references, .. })) = &field.array {
            references.values().for_each(&mut *f);
        }
        match &field.kind {
            FieldKind::Builtin(BuiltinField { length: field::Length::Expression { references, .. }, .. }) => {
                references.values().for_each(&mut *f);
            }
            FieldKind::Builtin(_) => {}
            FieldKind::Structure(children) => references(children, f),
            FieldKind::Type { context, .. } => context.iter().for_each(|(_, r)| f(r)),
            FieldKind::Switch(switch) => {
                if let Operand::Expression { references, .. } = &switch.subject {
                    references.values().for_each(&mut *f);
                }
                for body in switch.bodies() {
                    match body {
                        Body::Fields(children) => references(children, f),
                        Body::Type { context, .. } => context.iter().for_each(|(_, r)| f(r)),
                    }
                }
            }
        }
    }
}

/// A slot of a Type's site tables: what each use registers for one Field of the Type.
#[derive(Debug, Clone)]
struct Slot<'p> {
    /// The key in the site table.
    key: String,
    /// The Field's path inside the Type.
    segments: Vec<&'p str>,
    kind: SlotKind<'p>,
}

#[derive(Debug, Clone)]
enum SlotKind<'p> {
    /// The `ProtoField` of this Field.
    Field(&'p Field),
    /// The `ProtoField` of this sub-Field of the bitfield.
    Bit(&'p BuiltinField, &'p Bit),
    /// The site table of this Type, which the Field is of.
    Site(&'p str),
}

/// What lowering has built so far, while it walks the layout.
struct Lowering<'p> {
    /// The plan of the dissect function being lowered.
    plan: Plan,
    /// The Fields of the dissect function being lowered: the top-level layout or a Type body.
    root: &'p [field::Entry],
    types: &'p [NamedType],
    /// The protocol's filter name, the first segment of every `ProtoField`'s.
    filter_name: &'p str,
    enums: &'p BTreeMap<String, Table>,
    proto_fields: Vec<ProtoField>,
    tables: Vec<SharedTable>,
    names: Vec<NamesTable>,
    /// The slots of each Type's site tables, in the Type's layout order.
    slots: BTreeMap<&'p str, Vec<Slot<'p>>>,
    sites: Vec<SharedSite>,
    chunks: Vec<&'static str>,
}

impl<'p> Lowering<'p> {
    /// The statements of a structure outside any Type whose Fields' paths start with `parent`.
    fn structure(&mut self, entries: &'p [field::Entry], parent: &[&'p str]) -> Vec<Stmt> {
        entries
            .iter()
            .map(|entry| match entry {
                field::Entry::Field(field) => self.field(field, parent),
                field::Entry::Padding(amount) => self.padding(amount, parent),
            })
            .collect()
    }

    /// The statement skipping the bytes of a padding in the structure at `parent`.
    fn padding(&mut self, amount: &Amount, parent: &[&str]) -> Stmt {
        let length = match amount {
            Amount::Constant(size) => Length::Fixed(*size),
            Amount::Expression { expr, references } => Length::Expression(self.computed(expr, references)),
        };
        Stmt::Padding { parent: parent.join("."), length }
    }

    /// Registers the `ProtoField`s of a Field outside any Type whose path starts with `parent`,
    /// and returns the statement that reads it.
    fn field(&mut self, field: &'p Field, parent: &[&'p str]) -> Stmt {
        let segments: Vec<&str> = parent.iter().copied().chain([field.name.as_str()]).collect();
        let path = segments.join(".");
        let index = self.proto_field(field, &segments);
        let stmt = match &field.kind {
            FieldKind::Builtin(value) => {
                let bits = value
                    .bits
                    .iter()
                    .map(|bit| {
                        let path: Vec<&str> = segments.iter().copied().chain([bit.name.as_str()]).collect();
                        (Ref::Local(self.proto_field_bit(value, bit, &path)), bit)
                    })
                    .collect();
                self.read(value, Ref::Local(index), &segments, field.hidden, bits)
            }
            FieldKind::Structure(fields) => {
                let body = self.structure(fields, &segments);
                Stmt::Structure { field: Ref::Local(index), body, path, hidden: field.hidden }
            }
            FieldKind::Type { name, .. } => {
                let site = self.site(name, &segments);
                let local =
                    unique(&format!("site_{}", segments.join("__")), |n| self.sites.iter().any(|s| s.local == n));
                self.sites.push(SharedSite { local, site });
                let site = Ref::Local(self.sites.len() - 1);
                self.call(Ref::Local(index), field, &segments, site)
            }
            FieldKind::Switch(switch) => self.switch(Ref::Local(index), field, switch, &segments, None),
        };
        let stmt = self.array(field, &segments, stmt);
        self.condition(field, &segments, stmt)
    }

    /// The statement of the `switch` Field `field` at `segments`, whose `ProtoField` is
    /// `proto_field`. Inside a Type, its cases add their slots to `slots`.
    fn switch(
        &mut self,
        proto_field: Ref,
        field: &Field,
        switch: &'p Switch,
        segments: &[&'p str],
        mut slots: Option<&mut Vec<Slot<'p>>>,
    ) -> Stmt {
        let subject = self.operand(&switch.subject);
        let names = self.names(&switch.subject, segments);
        let cases = switch
            .cases
            .iter()
            .map(|case| (wire_ranges(case.key.low, case.key.high), self.branch(&case.body, segments, &mut slots)))
            .collect();
        let default = switch.default.as_ref().map(|body| self.branch(body, segments, &mut slots));
        if default.is_none() {
            self.use_chunk(prelude::UNMATCHED);
        }
        let path = segments.join(".");
        Stmt::Switch { field: proto_field, path, hidden: field.hidden, subject, names, cases, default }
    }

    /// What a case of the `switch` Field at `segments` reads. A case adds no segment to paths, so
    /// a Type's site table has the `switch` Field's path; one per Type serves every case using it.
    fn branch(&mut self, body: &'p Body, segments: &[&'p str], slots: &mut Option<&mut Vec<Slot<'p>>>) -> Branch {
        match body {
            Body::Fields(fields) => Branch::Fields(match slots {
                Some(slots) => self.type_structure(fields, segments, slots),
                None => self.structure(fields, segments),
            }),
            Body::Type { name, context } => {
                let site = if let Some(slots) = slots {
                    let key = format!("t_{}__{name}", segments.join("__"));
                    if !slots.iter().any(|s| s.key == key) {
                        let kind = SlotKind::Site(name);
                        slots.push(Slot { key: key.clone(), segments: segments.to_vec(), kind });
                    }
                    Ref::Slot(key)
                } else {
                    let local = format!("site_{}__{name}", segments.join("__"));
                    let index = self.sites.iter().position(|s| s.local == local).unwrap_or_else(|| {
                        let site = self.site(name, segments);
                        self.sites.push(SharedSite { local, site });
                        self.sites.len() - 1
                    });
                    Ref::Local(index)
                };
                let context = context.iter().map(|(key, r)| (key.clone(), self.reference(r))).collect();
                Branch::Call { ty: name.clone(), site, context }
            }
        }
    }

    /// The table naming the values of a `switch` subject (spec §3.9): the `values:` labels of the
    /// Field it is, when it is a bare path to a Field the same dissect function reads. A path
    /// the Type's caller resolves (a context value) can be another Field at each use, so the
    /// number is shown.
    fn names(&mut self, subject: &Operand, segments: &[&str]) -> Option<usize> {
        let Operand::Expression { expr, references } = subject else { return None };
        let ExprKind::Path(path) = &expr.kind else { return None };
        let (mapping, range) = match &references[path] {
            Reference::Field(path) => {
                let value = self.builtin_at(self.root, path)?;
                (value.mapping.as_ref()?, value.ty.int_range()?)
            }
            Reference::Bits { container, shift, width } => {
                let value = self.builtin_at(self.root, container)?;
                let bit = value.bits.iter().find(|b| b.shift == *shift && b.width == *width)?;
                (bit.mapping.as_ref()?, 0..=(1_i128 << width) - 1)
            }
            Reference::Context(_) => return None,
        };
        let table = match mapping {
            Mapping::Values(Values::Inline(table)) => table,
            Mapping::Values(Values::Enum(name)) => &self.enums[name],
            Mapping::Bool { .. } | Mapping::Unit { .. } => return None,
        };
        let entries = names_entries(table, &range);
        if entries.is_empty() {
            return None;
        }
        self.use_chunk(prelude::NAMES);
        Some(self.names.iter().position(|n| n.entries == entries).unwrap_or_else(|| {
            let local =
                unique(&format!("names_{}", segments.join("__")), |name| self.names.iter().any(|n| n.local == name));
            self.names.push(NamesTable { local, entries });
            self.names.len() - 1
        }))
    }

    /// The Field of a built-in type at `path` from `fields`, going into the Types on the way.
    fn builtin_at(&self, fields: &'p [field::Entry], path: &[String]) -> Option<&'p BuiltinField> {
        let (depth, field) = find(fields, path)?;
        match &field.kind {
            FieldKind::Builtin(value) if depth + 1 == path.len() => Some(value),
            FieldKind::Type { name, .. } => {
                let ty = self.types.iter().find(|t| t.name == *name)?;
                self.builtin_at(&ty.fields, &path[depth + 1..])
            }
            _ => None,
        }
    }

    /// The statement of `field`, at `segments`, given the statement `stmt` reading it, array and
    /// all: `stmt` itself, or `stmt` under the Field's `if:`.
    fn condition(&mut self, field: &Field, segments: &[&str], stmt: Stmt) -> Stmt {
        let Some(condition) = field.condition.as_ref() else { return stmt };
        let condition = self.operand(condition);
        Stmt::If { path: segments.join("."), condition, body: Box::new(stmt) }
    }

    /// An `if:` or `switch:` value as the Dissector evaluates it: any value is valid, but an
    /// Expression can fault, even a constant one (spec §4.4).
    fn operand(&mut self, operand: &Operand) -> Computed {
        match operand {
            // A negative constant wraps to the Lua literal with the same 64 bits.
            Operand::Constant(value) => {
                Computed::checked_already(LuaExpr::Int(u64::from_ne_bytes(value.to_ne_bytes())))
            }
            Operand::Expression { expr, references } => {
                let faults = can_fault(expr);
                if faults {
                    self.use_chunk(prelude::INVALID);
                }
                Computed { value: self.expression(expr, references), checked: false, faults }
            }
        }
    }

    /// The statement of `field`, at `segments`, given the statement `stmt` reading it once:
    /// `stmt` itself, or `stmt` repeated when the Field is an array.
    fn array(&mut self, field: &Field, segments: &[&str], stmt: Stmt) -> Stmt {
        let Some(array) = &field.array else { return stmt };
        // An element that reads no bytes is reported as malformed.
        self.use_chunk(prelude::INVALID);
        let repeat = match array {
            Array::ToEnd => Repeat::ToEnd,
            Array::Count(Amount::Constant(count)) => {
                let count = u64::try_from(*count).expect("a count fits in 64 bits");
                Repeat::Count(Computed::checked_already(LuaExpr::Int(count)))
            }
            Array::Count(Amount::Expression { expr, references }) => Repeat::Count(self.computed(expr, references)),
        };
        Stmt::Array { path: segments.join("."), repeat, element: Box::new(stmt) }
    }

    /// The statements of a structure inside a Type whose Fields' paths, relative to the Type,
    /// start with `parent`, adding the slots they read to `slots`.
    fn type_structure(
        &mut self,
        entries: &'p [field::Entry],
        parent: &[&'p str],
        slots: &mut Vec<Slot<'p>>,
    ) -> Vec<Stmt> {
        entries
            .iter()
            .map(|entry| {
                let field = match entry {
                    field::Entry::Field(field) => field,
                    field::Entry::Padding(amount) => return self.padding(amount, parent),
                };
                let segments: Vec<&str> = parent.iter().copied().chain([field.name.as_str()]).collect();
                let path = segments.join(".");
                let slot = |slots: &mut Vec<Slot<'p>>, prefix: &str, segments: Vec<&'p str>, kind: SlotKind<'p>| {
                    let key = unique(&format!("{prefix}{}", segments.join("__")), |k| slots.iter().any(|s| s.key == k));
                    slots.push(Slot { key: key.clone(), segments, kind });
                    Ref::Slot(key)
                };
                let field_ref = slot(slots, "f_", segments.clone(), SlotKind::Field(field));
                let stmt = match &field.kind {
                    FieldKind::Builtin(value) => {
                        let bits = value
                            .bits
                            .iter()
                            .map(|bit| {
                                let path = segments.iter().copied().chain([bit.name.as_str()]).collect();
                                (slot(slots, "f_", path, SlotKind::Bit(value, bit)), bit)
                            })
                            .collect();
                        self.read(value, field_ref, &segments, field.hidden, bits)
                    }
                    FieldKind::Structure(fields) => {
                        let body = self.type_structure(fields, &segments, slots);
                        Stmt::Structure { field: field_ref, path, body, hidden: field.hidden }
                    }
                    FieldKind::Type { name, .. } => {
                        let site = slot(slots, "t_", segments.clone(), SlotKind::Site(name));
                        self.call(field_ref, field, &segments, site)
                    }
                    FieldKind::Switch(switch) => self.switch(field_ref, field, switch, &segments, Some(slots)),
                };
                let stmt = self.array(field, &segments, stmt);
                self.condition(field, &segments, stmt)
            })
            .collect()
    }

    /// The site table of a use of the Type `ty` at the path `segments`, registering the
    /// `ProtoField`s of that use.
    fn site(&mut self, ty: &str, segments: &[&'p str]) -> Site {
        let slots = self.slots.get(ty).expect("every Type is lowered before any use of it").clone();
        let entries = slots
            .into_iter()
            .map(|slot| {
                let path: Vec<&str> = segments.iter().copied().chain(slot.segments).collect();
                let entry = match slot.kind {
                    SlotKind::Field(field) => SiteEntry::Field(self.proto_field(field, &path)),
                    SlotKind::Bit(container, bit) => SiteEntry::Field(self.proto_field_bit(container, bit, &path)),
                    SlotKind::Site(ty) => SiteEntry::Site(self.site(ty, &path)),
                };
                (slot.key, entry)
            })
            .collect();
        Site { path: segments.join("."), entries }
    }

    /// The statement calling the dissect function of the Type of `field`, a Field of a Type at
    /// `segments` whose `ProtoField` is `proto_field`, with the site table `site`.
    fn call(&mut self, proto_field: Ref, field: &Field, segments: &[&str], site: Ref) -> Stmt {
        let FieldKind::Type { name, context } = &field.kind else { unreachable!("only a Field of a Type is called") };
        let context = context.iter().map(|(key, reference)| (key.clone(), self.reference(reference))).collect();
        let result = self.plan.results.get(&owned(segments)).cloned();
        let (path, ty, hidden) = (segments.join("."), name.clone(), field.hidden);
        Stmt::Call { field: proto_field, path, hidden, ty, site, context, result }
    }

    /// How an Expression reads `reference`, using the prelude chunk a sub-Field needs.
    fn reference(&mut self, reference: &Reference) -> LuaExpr {
        if matches!(reference, Reference::Bits { .. }) {
            self.use_chunk(prelude::BITWISE);
        }
        self.plan.read(reference)
    }

    /// The statement reading a Field of a built-in type through `field`, at `segments`, hidden or
    /// not, with the `ProtoField`s of its sub-Fields when it is a bitfield.
    fn read(
        &mut self,
        field_value: &BuiltinField,
        field: Ref,
        segments: &[&str],
        hidden: bool,
        bits: Vec<(Ref, &Bit)>,
    ) -> Stmt {
        let length = match &field_value.length {
            field::Length::Expression { expr, references } => Length::Expression(self.computed(expr, references)),
            _ => length(field_value),
        };
        if matches!(length, Length::Terminator { .. }) {
            self.use_chunk(prelude::TERMINATED);
        }
        let value =
            self.plan.values.get(&owned(segments)).cloned().map(|local| Value { local, read: value_read(field_value) });
        if value.as_ref().is_some_and(|v| v.read == ValueRead::Bool) {
            self.use_chunk(prelude::LOGIC);
        }
        let little = field_value.endian == Endian::Little && field_value.ty.has_byte_order();
        let whole = LuaExpr::Local { local: "value".to_owned(), keys: Vec::new() };
        let path = segments.join(".");
        let expect = field_value.expect.as_ref().map(|e| expected(e, &path, whole.clone()));
        let bits: Vec<BitItem> = bits
            .into_iter()
            .map(|(field, bit)| {
                let expect = bit.expect.as_ref().map(|e| {
                    self.use_chunk(prelude::BITWISE);
                    expected(e, &format!("{path}.{}", bit.name), sub_field_value(whole.clone(), bit.shift, bit.width))
                });
                BitItem { field, hidden: hidden || bit.hidden, little, expect }
            })
            .collect();
        let checked = (expect.is_some() || bits.iter().any(|b| b.expect.is_some())).then(|| value_read(field_value));
        if checked.is_some() {
            self.use_chunk(prelude::UNEXPECTED);
        }
        if checked == Some(ValueRead::Bool) {
            self.use_chunk(prelude::LOGIC);
        }
        let decode = decode(field_value);
        Stmt::Read { field, length, decode, path, value, hidden, bits, checked, expect }
    }

    /// Compiles a `size:` or `count:` Expression whose paths read `references`, with the
    /// checks it needs: a value known only when the packet is read is reported when negative,
    /// under the `invalid` chunk.
    fn computed(&mut self, expr: &Expr, references: &BTreeMap<Vec<String>, Reference>) -> Computed {
        let checked = expr.constant().is_none();
        let faults = checked && can_fault(expr);
        if checked {
            self.use_chunk(prelude::INVALID);
        }
        Computed { value: self.expression(expr, references), checked, faults }
    }

    /// Adds a prelude chunk the Dissector needs, once.
    fn use_chunk(&mut self, chunk: &'static str) {
        if !self.chunks.contains(&chunk) {
            self.chunks.push(chunk);
        }
    }

    /// Compiles an Expression whose paths read `references` to helper calls, using the prelude
    /// chunks that define them.
    fn expression(&mut self, expr: &Expr, references: &BTreeMap<Vec<String>, Reference>) -> LuaExpr {
        let (helper, chunk, args) = match &expr.kind {
            ExprKind::Int(value) => return LuaExpr::Int(*value),
            ExprKind::Path(segments) => return self.reference(&references[segments]),
            ExprKind::Builtin(expr::Builtin::Offset) => return LuaExpr::Offset,
            ExprKind::Builtin(expr::Builtin::Remaining) => return LuaExpr::Remaining,
            ExprKind::Unary { op, operand } => {
                let (helper, chunk) = match op.value {
                    UnaryOp::Not => ("wd_not", prelude::LOGIC),
                    UnaryOp::Complement => ("wd_bnot", prelude::BITWISE),
                    UnaryOp::Negate => ("wd_neg", prelude::ARITHMETIC),
                };
                (helper, chunk, vec![operand])
            }
            ExprKind::Binary { op, left, right } => {
                let (helper, chunk) = match op.value {
                    BinaryOp::And | BinaryOp::Or => {
                        // `wd_bool` turns Lua's `and`/`or`, which short-circuit, into 1 or 0.
                        self.use_chunk(prelude::LOGIC);
                        let left = Box::new(self.expression(left, references));
                        let right = Box::new(self.expression(right, references));
                        return if op.value == BinaryOp::And {
                            LuaExpr::And(left, right)
                        } else {
                            LuaExpr::Or(left, right)
                        };
                    }
                    BinaryOp::Mul => ("wd_mul", prelude::ARITHMETIC),
                    BinaryOp::Add => ("wd_add", prelude::ARITHMETIC),
                    BinaryOp::Sub => ("wd_sub", prelude::ARITHMETIC),
                    BinaryOp::Div => ("wd_div", prelude::DIVISION),
                    BinaryOp::Rem => ("wd_mod", prelude::DIVISION),
                    BinaryOp::Shl => ("wd_shl", prelude::BITWISE),
                    BinaryOp::Shr => ("wd_shr", prelude::BITWISE),
                    BinaryOp::BitAnd => ("wd_band", prelude::BITWISE),
                    BinaryOp::BitXor => ("wd_bxor", prelude::BITWISE),
                    BinaryOp::BitOr => ("wd_bor", prelude::BITWISE),
                    BinaryOp::Eq => ("wd_eq", prelude::LOGIC),
                    BinaryOp::Ne => ("wd_ne", prelude::LOGIC),
                    BinaryOp::Lt => ("wd_lt", prelude::LOGIC),
                    BinaryOp::Le => ("wd_le", prelude::LOGIC),
                    BinaryOp::Gt => ("wd_gt", prelude::LOGIC),
                    BinaryOp::Ge => ("wd_ge", prelude::LOGIC),
                };
                (helper, chunk, vec![left, right])
            }
        };
        self.use_chunk(chunk);
        LuaExpr::Call { helper, args: args.into_iter().map(|arg| self.expression(arg, references)).collect() }
    }

    /// Registers the `ProtoField` of a Field at the path `segments`, returning its index. Fields
    /// reaching one path in several `switch` cases share it: validation checked that they match.
    fn proto_field(&mut self, field: &Field, segments: &[&str]) -> usize {
        let path = segments.join(".");
        let abbrev = format!("{}.{path}", self.filter_name);
        if let Some(index) = self.proto_fields.iter().position(|f| f.abbrev == abbrev) {
            return index;
        }
        let (field_type, strings) = match &field.kind {
            FieldKind::Builtin(value) => (
                field_type(value),
                value
                    .mapping
                    .as_ref()
                    .and_then(|m| strings(m, KeyRange::of(value.ty).as_ref(), self.enums, &mut self.tables)),
            ),
            FieldKind::Structure(_) | FieldKind::Type { .. } | FieldKind::Switch(_) => {
                (FieldType::new("none", Args::Plain), None)
            }
        };
        self.proto_fields.push(ProtoField {
            local: self.local(segments),
            abbrev,
            label: field.label.clone().unwrap_or_else(|| default_label(&field.name)),
            description: field.description.clone(),
            field_type,
            strings,
            mask: None,
        });
        self.proto_fields.len() - 1
    }

    /// Registers the `ProtoField` of the sub-Field `bit` of the bitfield `container` at the path
    /// `segments`, returning its index. It is masked, and declared as wide as the container, as
    /// Wireshark requires: an unsigned integer, or a boolean whose display is the container's
    /// number of bits.
    fn proto_field_bit(&mut self, container: &BuiltinField, bit: &Bit, segments: &[&str]) -> usize {
        let Builtin::Int { signed: false, bytes } = container.ty else {
            panic!("validation gives `bits` only to unsigned integers")
        };
        let abbrev = format!("{}.{}", self.filter_name, segments.join("."));
        if let Some(index) = self.proto_fields.iter().position(|f| f.abbrev == abbrev) {
            return index;
        }
        let (field_type, strings) = if let Some(display) = bit.display {
            let keys = KeyRange { range: 0..=(1_i128 << bit.width) - 1, signed32: false };
            let strings = bit.mapping.as_ref().and_then(|m| strings(m, Some(&keys), self.enums, &mut self.tables));
            (FieldType::new(field_type(container).constructor, Args::Display(base(display))), strings)
        } else {
            let (when_true, when_false) = match &bit.mapping {
                Some(Mapping::Bool { when_true, when_false }) => (when_true.clone(), when_false.clone()),
                _ => (None, None),
            };
            let strings = Strings::TrueFalse {
                when_true: when_true.unwrap_or_else(|| "Set".to_owned()),
                when_false: when_false.unwrap_or_else(|| "Not set".to_owned()),
            };
            (FieldType::new("bool", Args::Display(bool_width(bytes))), Some(strings))
        };
        self.proto_fields.push(ProtoField {
            local: self.local(segments),
            abbrev,
            label: bit.label.clone().unwrap_or_else(|| default_label(&bit.name)),
            description: bit.description.clone(),
            field_type,
            strings,
            mask: Some(Mask { bits: bit.mask(), bytes }),
        });
        self.proto_fields.len() - 1
    }

    /// The Lua local of the `ProtoField` at a path: `f_` then the segments joined by `__`
    /// (`f_options__ttl`).
    fn local(&self, segments: &[&str]) -> String {
        unique(&format!("f_{}", segments.join("__")), |name| self.proto_fields.iter().any(|f| f.local == name))
    }
}

/// A path as the plans key it.
fn owned(segments: &[&str]) -> Vec<String> {
    segments.iter().map(|s| (*s).to_owned()).collect()
}

/// Whether an Expression has an operator that can fault at runtime: `/`, `%`, `<<` or `>>`.
fn can_fault(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Int(_) | ExprKind::Path(_) | ExprKind::Builtin(_) => false,
        ExprKind::Unary { operand, .. } => can_fault(operand),
        ExprKind::Binary { op, left, right } => {
            matches!(op.value, BinaryOp::Div | BinaryOp::Rem | BinaryOp::Shl | BinaryOp::Shr)
                || can_fault(left)
                || can_fault(right)
        }
    }
}

/// `base`, or when `taken` says it is, `base` with the first free `_<n>` suffix. A Field name
/// can itself hold `__`, so two paths can mangle alike; filter names are never changed this way.
fn unique(base: &str, taken: impl Fn(&str) -> bool) -> String {
    if !taken(base) {
        return base.to_owned();
    }
    (2..=usize::MAX).map(|n| format!("{base}_{n}")).find(|name| !taken(name)).expect("some suffix is free")
}

/// The Wireshark field type a Field is shown as (spec §3.4.4, §3.4.6).
fn field_type(field: &BuiltinField) -> FieldType {
    match field.ty {
        Builtin::Int { signed, bytes } => {
            let constructor = match (signed, bytes) {
                (false, 1) => "uint8",
                (false, 2) => "uint16",
                (false, 3) => "uint24",
                (false, 4) => "uint32",
                (false, _) => "uint64",
                (true, 1) => "int8",
                (true, 2) => "int16",
                (true, 3) => "int24",
                (true, 4) => "int32",
                (true, _) => "int64",
            };
            let display = field.display.expect("validation gives every integer a display");
            FieldType::new(constructor, Args::Display(base(display)))
        }
        Builtin::Bool => FieldType::new("bool", Args::Display("base.NONE")),
        Builtin::Float32 => FieldType::new("float", Args::Plain),
        Builtin::Float64 => FieldType::new("double", Args::Plain),
        Builtin::Ipv4 => FieldType::new("ipv4", Args::Plain),
        Builtin::Ipv6 => FieldType::new("ipv6", Args::Plain),
        Builtin::Ether => FieldType::new("ether", Args::Plain),
        Builtin::Eui64 => FieldType::new("eui64", Args::Plain),
        Builtin::Guid => FieldType::new("guid", Args::Plain),
        // A `terminator: 0` string is what Wireshark calls a NUL-terminated string.
        Builtin::String if field.length == field::Length::Terminator(0) => {
            FieldType::new("stringz", Args::Base("base.NONE"))
        }
        Builtin::String => FieldType::new("string", Args::Base("base.NONE")),
        Builtin::Bytes => {
            let display = field.display.expect("validation gives `bytes` a display");
            FieldType::new("bytes", Args::Base(base(display)))
        }
        Builtin::AbsTime => {
            let display = field.display.expect("validation gives `abs_time` a display");
            FieldType::new("absolute_time", Args::Base(base(display)))
        }
        // Unlike `absolute_time`, `relative_time` takes no display: its blurb is the third argument.
        Builtin::RelTime => FieldType::new("relative_time", Args::Plain),
    }
}

/// The display of a boolean sub-Field's `ProtoField`: the number of bits of its container.
fn bool_width(bytes: usize) -> &'static str {
    match bytes {
        1 => "8",
        2 => "16",
        3 => "24",
        4 => "32",
        5 => "40",
        6 => "48",
        7 => "56",
        8 => "64",
        _ => panic!("validation gives `bits` only to integers of 1 to 8 bytes"),
    }
}

/// The values a Field's table keys can reach, as its `ProtoField` compares them.
#[derive(Debug, Clone)]
struct KeyRange {
    /// The values of the Field: its type's, or a sub-Field's.
    range: RangeInclusive<i128>,
    /// Whether it is a signed integer of 32 bits or fewer, whose negative values Wireshark
    /// compares as their 32-bit two's complement.
    signed32: bool,
}

impl KeyRange {
    /// The keys of a Field of type `ty`, `None` when it is not an integer.
    fn of(ty: Builtin) -> Option<Self> {
        let Builtin::Int { signed, bytes } = ty else { return None };
        Some(Self { range: ty.int_range()?, signed32: signed && bytes <= 4 })
    }
}

/// The labels of a Field whose table keys can reach `keys`. An Enum's table is shared by every
/// Field it lowers to the same table for. A table left empty by the type (every key
/// `unreachable-value`) gives no labels at all: an empty table would only make every value
/// "Unknown".
fn strings(
    mapping: &Mapping,
    keys: Option<&KeyRange>,
    enums: &BTreeMap<String, Table>,
    tables: &mut Vec<SharedTable>,
) -> Option<Strings> {
    let table_keys = || keys.expect("validation gives `values` only to integers");
    Some(match mapping {
        Mapping::Values(Values::Inline(table)) => {
            let lua = lua_table(table, table_keys());
            if lua.is_empty() {
                return None;
            }
            Strings::Table { table: TableRef::Inline(lua), range: mapping::has_range(table) }
        }
        Mapping::Values(Values::Enum(name)) => {
            let table = &enums[name];
            let lua = lua_table(table, table_keys());
            if lua.is_empty() {
                return None;
            }
            let index = tables.iter().position(|t| t.enum_name == *name && t.table == lua).unwrap_or_else(|| {
                // An Enum lowers to another table only when a Field's type cuts off some keys.
                let variants = tables.iter().filter(|t| t.enum_name == *name).count();
                let local =
                    if variants == 0 { format!("enum_{name}") } else { format!("enum_{name}_{}", variants + 1) };
                tables.push(SharedTable { local, enum_name: name.clone(), table: lua });
                tables.len() - 1
            });
            Strings::Table { table: TableRef::Shared(index), range: mapping::has_range(table) }
        }
        Mapping::Bool { when_true, when_false } => Strings::TrueFalse {
            when_true: when_true.clone().unwrap_or_else(|| "True".to_owned()),
            when_false: when_false.clone().unwrap_or_else(|| "False".to_owned()),
        },
        // Wireshark prints a unit right after the value, so the space comes with the unit.
        Mapping::Unit { singular, plural } => {
            Strings::Unit { singular: format!(" {singular}"), plural: plural.as_ref().map(|p| format!(" {p}")) }
        }
    })
}

/// A validated table as Wireshark reads it for a `ProtoField` whose values reach `keys`.
///
/// Wireshark converts each key and bound to an unsigned integer of the `ProtoField`'s width
/// (32 or 64 bits), so:
/// - keys outside the type are left out and ranges are cut to it: a wider key would be
///   truncated onto a value the type does hold;
/// - a key above `i64::MAX` is written as the negative Lua integer with the same 64 bits;
/// - a range string compares values as unsigned integers, so a range crossing zero is split in
///   two, and a negative bound of a 32-bit or narrower signed type is written as its 32-bit two's
///   complement, which is what the value is compared as.
fn lua_table(table: &[Entry], keys: &KeyRange) -> LuaTable {
    let (min, max) = (*keys.range.start(), *keys.range.end());
    let reachable = table.iter().filter_map(|e| {
        let (low, high) = (e.key.low.max(min), e.key.high.min(max));
        (low <= high).then(|| (low, high, e.label.clone()))
    });
    let wire = |value: i128| {
        let value = if value > i128::from(i64::MAX) { value - (1 << 64) } else { value };
        i64::try_from(value).expect("validation keeps keys within 64 bits")
    };
    if !mapping::has_range(table) {
        return LuaTable::Values(reachable.map(|(value, _, label)| (wire(value), label)).collect());
    }
    let unsigned = |value: i128| wire(if keys.signed32 && value < 0 { value + (1 << 32) } else { value });
    LuaTable::Ranges(
        reachable
            .flat_map(|(low, high, label)| {
                let halves = if low < 0 && high >= 0 { vec![(low, -1), (0, high)] } else { vec![(low, high)] };
                halves.into_iter().map(move |(l, h)| (unsigned(l), unsigned(h), label.clone()))
            })
            .collect(),
    )
}

/// The Lua `base` value of a display.
fn base(display: Display) -> &'static str {
    match display {
        Display::Dec => "base.DEC",
        Display::Hex => "base.HEX",
        Display::Oct => "base.OCT",
        Display::DecHex => "base.DEC_HEX",
        Display::HexDec => "base.HEX_DEC",
        Display::Plain => "base.NONE",
        Display::Dot => "base.DOT",
        Display::Dash => "base.DASH",
        Display::Colon => "base.COLON",
        Display::Space => "base.SPACE",
        Display::Local => "base.LOCAL",
        Display::Utc => "base.UTC",
        Display::DoyUtc => "base.DOY_UTC",
    }
}

/// Where a Field's value ends, with the Lua call that reads a `prefix:` count in its width
/// and byte order. A `prefix:` beyond 2^53 loses precision in `tonumber()`, but no packet is
/// that long, so the bounds check still fails it.
fn length(field: &BuiltinField) -> Length {
    match field.length {
        field::Length::Expression { .. } => unreachable!("`Lowering::read` compiles Expressions"),
        field::Length::Constant(size) => Length::Fixed(size),
        field::Length::Prefix(size) => {
            let read = match (size, size > 1 && field.endian == Endian::Little) {
                (1..=4, false) => "uint()",
                (1..=4, true) => "le_uint()",
                (_, false) => "uint64():tonumber()",
                (_, true) => "le_uint64():tonumber()",
            };
            Length::Prefix { size, read }
        }
        field::Length::Terminator(terminator) => {
            Length::Terminator { terminator, width: field.encoding.map_or(1, Encoding::unit) }
        }
    }
}

/// The `ENC_*` value Wireshark decodes a string or a timestamp with, before any byte order.
fn enc_value(encoding: Encoding) -> &'static str {
    match encoding {
        Encoding::Ascii => "ENC_ASCII",
        Encoding::Utf8 => "ENC_UTF_8",
        Encoding::Latin1 => "ENC_ISO_8859_1",
        Encoding::Utf16 => "ENC_UTF_16",
        Encoding::Ucs2 => "ENC_UCS_2",
        Encoding::Secs => "ENC_TIME_SECS",
        Encoding::SecsNsecs => "ENC_TIME_SECS_NSECS",
        Encoding::Ntp => "ENC_TIME_NTP",
        Encoding::Msecs => "ENC_TIME_MSECS",
        Encoding::Usecs => "ENC_TIME_USECS",
        Encoding::Nsecs => "ENC_TIME_NSECS",
    }
}

/// The `ENC_*` value of a byte order.
fn enc_endian(endian: Endian) -> &'static str {
    match endian {
        Endian::Big => "ENC_BIG_ENDIAN",
        Endian::Little => "ENC_LITTLE_ENDIAN",
    }
}

/// How an Expression reads the value of an integer or `bool` Field.
fn value_read(field: &BuiltinField) -> ValueRead {
    match field.ty {
        Builtin::Int { signed, bytes } => {
            let order = if field.endian == Endian::Little { '<' } else { '>' };
            ValueRead::Integer(format!("{order}{}{bytes}", if signed { 'i' } else { 'I' }))
        }
        Builtin::Bool => ValueRead::Bool,
        _ => unreachable!("validation references only integers and `bool`"),
    }
}

/// The value of a sub-Field `width` bits wide, `shift` bits above the least significant bit of
/// `container`: shifted down and masked, with the helpers of the bitwise prelude chunk.
fn sub_field_value(container: LuaExpr, shift: u32, width: u32) -> LuaExpr {
    let mut value = container;
    if shift > 0 {
        value = LuaExpr::Call { helper: "wd_shr", args: vec![value, LuaExpr::Int(u64::from(shift))] };
    }
    if width < 64 {
        value = LuaExpr::Call { helper: "wd_band", args: vec![value, LuaExpr::Int((1 << width) - 1)] };
    }
    value
}

/// The check of `expect` on `value`, the value of the Field or sub-Field at `path`.
fn expected(expect: &Expect, path: &str, value: LuaExpr) -> Expected {
    let ranges = expect.keys.iter().flat_map(|k| wire_ranges(k.low, k.high)).collect();
    Expected { path: path.to_owned(), value, ranges, text: expect.text.clone() }
}

fn decode(field: &BuiltinField) -> Decode {
    if let Some(enc) = field.encoding {
        let endian = enc.has_byte_order().then(|| enc_endian(field.endian));
        return Decode::Encoded { encoding: enc_value(enc), endian };
    }
    let little = field.endian == Endian::Little && field.ty.has_byte_order();
    match field.ty {
        Builtin::Int { signed, bytes: 5..=7 } => Decode::Lua(match (signed, little) {
            (false, false) => "uint64",
            (false, true) => "le_uint64",
            (true, false) => "int64",
            (true, true) => "le_int64",
        }),
        _ if little => Decode::Little,
        _ => Decode::Big,
    }
}

/// The labels of `table` a `switch` subject holding `range` can match, as `(low, high, label)`
/// over the signed 64-bit values the Expression reads.
fn names_entries(table: &[Entry], range: &RangeInclusive<i128>) -> Vec<(i64, i64, String)> {
    table
        .iter()
        .flat_map(|e| {
            let (low, high) = (e.key.low.max(*range.start()), e.key.high.min(*range.end()));
            let ranges = if low <= high { wire_ranges(low, high) } else { Vec::new() };
            ranges.into_iter().map(|(l, h)| (l, h, e.label.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{description, yaml};

    fn lowered(text: &str, source_name: &str) -> Dissector {
        let root = yaml::parse(text).unwrap();
        let (protocol, diagnostics) = description::check(&description::deserialize(root.as_ref()).unwrap());
        lower(&protocol.unwrap_or_else(|| panic!("{diagnostics:?}")), source_name)
    }

    /// How each top-level read ends and is decoded, for a layout of reads only.
    fn reads(d: &Dissector) -> Vec<(Length, Decode)> {
        d.layout
            .iter()
            .map(|stmt| match stmt {
                Stmt::Read { length, decode, .. } => (length.clone(), *decode),
                Stmt::Structure { path, .. }
                | Stmt::Call { path, .. }
                | Stmt::Array { path, .. }
                | Stmt::If { path, .. }
                | Stmt::Switch { path, .. } => {
                    panic!("{path} is not a read")
                }
                Stmt::Padding { .. } => panic!("padding is not a read"),
            })
            .collect()
    }

    fn tables(d: &Dissector) -> Vec<LuaTable> {
        d.proto_fields
            .iter()
            .map(|f| match &f.strings {
                Some(Strings::Table { table: TableRef::Inline(t), .. }) => t.clone(),
                Some(Strings::Table { table: TableRef::Shared(i), .. }) => d.tables[*i].table.clone(),
                other => panic!("{} has no table: {other:?}", f.local),
            })
            .collect()
    }

    fn label(text: &str) -> String {
        text.to_owned()
    }

    /// Wireshark truncates a key to the `ProtoField`'s width, so a key the type cannot hold would
    /// land on another value: it is left out, and a range is cut to the type.
    #[test]
    fn keys_outside_the_type_are_left_out() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: uint8, values: {1: One, 257: Wide, -1: Neg}}\n  - {name: b, type: uint8, values: {\"250-300\": High, \"400-500\": Never}}\n",
            "x",
        );
        assert_eq!(
            tables(&d),
            [LuaTable::Values(vec![(1, label("One"))]), LuaTable::Ranges(vec![(250, 255, label("High"))])]
        );
    }

    /// Checked in tshark 4.4 and 4.6: a range string compares a value as an unsigned integer of
    /// the `ProtoField`'s width (32 bits up to `int32`, 64 bits for `int64`).
    #[test]
    fn signed_ranges_follow_wiresharks_unsigned_comparison() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: int8, values: {\"-5--2\": Neg, \"-1-1\": Zero}}\n  - {name: b, type: int48, values: {\"-10-10\": Small}}\n  - {name: c, type: int16, values: {-1: MinusOne}}\n",
            "x",
        );
        assert_eq!(
            tables(&d),
            [
                LuaTable::Ranges(vec![
                    (4_294_967_291, 4_294_967_294, label("Neg")),
                    (4_294_967_295, 4_294_967_295, label("Zero")),
                    (0, 1, label("Zero")),
                ]),
                LuaTable::Ranges(vec![(-10, -1, label("Small")), (0, 10, label("Small"))]),
                LuaTable::Values(vec![(-1, label("MinusOne"))]),
            ]
        );
    }

    /// A table the type cuts to nothing gives no labels, rather than an empty table.
    #[test]
    fn a_table_with_no_reachable_key_gives_no_labels() {
        let d = lowered(
            "name: demo\nenums:\n  Big: {256: Wide}\nfields:\n  - {name: a, type: uint8, values: {256: Never}}\n  - {name: b, type: uint8, values: Big}\n",
            "x",
        );
        assert_eq!(d.proto_fields.iter().map(|f| f.strings.clone()).collect::<Vec<_>>(), [None, None]);
        assert_eq!(d.tables, []);
    }

    /// A `uint64` key above `i64::MAX` is written as the Lua integer with the same 64 bits.
    #[test]
    fn wide_unsigned_keys_keep_their_64_bits() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: uint64, values: {0xffffffffffffffff: Max, 0x8000000000000000: Half}}\n",
            "x",
        );
        assert_eq!(tables(&d), [LuaTable::Values(vec![(-1, label("Max")), (i64::MIN, label("Half"))])]);
    }

    /// Two Fields naming one Enum have equal mappings (spec §3.4.9), and share its table while
    /// their types keep the same keys.
    #[test]
    fn an_enum_is_shared_by_its_fields() {
        let root = yaml::parse(
            "name: demo\nenums:\n  Kind: {1: One, 300: Big}\nfields:\n  - {name: a, type: uint16, values: Kind}\n  - {name: b, type: uint16, values: Kind}\n  - {name: c, type: uint8, values: Kind}\n",
        )
        .unwrap();
        let (protocol, diagnostics) = description::check(&description::deserialize(root.as_ref()).unwrap());
        let protocol = protocol.unwrap_or_else(|| panic!("{diagnostics:?}"));
        let mapping = |field: &Field| match &field.kind {
            FieldKind::Builtin(value) => value.mapping.clone(),
            FieldKind::Structure(_) | FieldKind::Type { .. } | FieldKind::Switch(_) => None,
        };
        let fields: Vec<&Field> = protocol.fields.iter().filter_map(field::Entry::field).collect();
        assert_eq!(mapping(fields[0]), mapping(fields[1]));
        let d = lower(&protocol, "x");
        let locals: Vec<&str> = d.tables.iter().map(|t| t.local.as_str()).collect();
        assert_eq!(locals, ["enum_Kind", "enum_Kind_2"]);
        let refs: Vec<Option<Strings>> = d.proto_fields.iter().map(|f| f.strings.clone()).collect();
        let shared = |i| Some(Strings::Table { table: TableRef::Shared(i), range: false });
        assert_eq!(refs, [shared(0), shared(0), shared(1)]);
        assert_eq!(d.tables[1].table, LuaTable::Values(vec![(1, label("One"))]));
    }

    /// Units carry their leading space, and a missing state label keeps Wireshark's default.
    #[test]
    fn units_and_states_get_wiresharks_spelling() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: uint16, unit: [byte, bytes]}\n  - {name: b, type: float32, unit: m}\n  - {name: c, type: bool, false: Off}\n",
            "x",
        );
        let strings: Vec<Option<Strings>> = d.proto_fields.iter().map(|f| f.strings.clone()).collect();
        assert_eq!(
            strings,
            [
                Some(Strings::Unit { singular: label(" byte"), plural: Some(label(" bytes")) }),
                Some(Strings::Unit { singular: label(" m"), plural: None }),
                Some(Strings::TrueFalse { when_true: label("True"), when_false: label("Off") }),
            ]
        );
    }

    /// Spec §5.2: every shown Field, structures included, is filtered by its path.
    #[test]
    fn filter_names_follow_field_paths() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: id, type: uint8}\n  - name: options\n    fields:\n      - {name: ttl, type: uint8}\n      - name: inner\n        fields: [ {name: id, type: uint16} ]\n",
            "x",
        );
        let abbrevs: Vec<&str> = d.proto_fields.iter().map(|f| f.abbrev.as_str()).collect();
        assert_eq!(
            abbrevs,
            ["demo.id", "demo.options", "demo.options.ttl", "demo.options.inner", "demo.options.inner.id"]
        );
    }

    /// A path `a.b` and a Field named `a__b` would both mangle to `f_a__b`.
    #[test]
    fn locals_stay_unique_when_paths_mangle_alike() {
        let d = lowered(
            "name: demo\nfields:\n  - name: a\n    fields: [ {name: b, type: uint8} ]\n  - {name: a__b, type: uint8}\n",
            "x",
        );
        let names: Vec<(&str, &str)> = d.proto_fields.iter().map(|f| (f.local.as_str(), f.abbrev.as_str())).collect();
        assert_eq!(names, [("f_a", "demo.a"), ("f_a__b", "demo.a.b"), ("f_a__b_2", "demo.a__b")]);
    }

    /// Spec §3.11: a structure's `endian:` is the default of the Fields inside it.
    #[test]
    fn a_structure_sets_the_byte_order_inside_it() {
        let d = lowered(
            "name: demo\nfields:\n  - name: s\n    endian: little\n    fields:\n      - {name: a, type: uint16}\n      - {name: b, type: uint16, endian: big}\n      - name: t\n        fields: [ {name: c, type: uint16} ]\n  - {name: d, type: uint16}\n",
            "x",
        );
        assert_eq!(all_decodes(&d.layout), [Decode::Little, Decode::Big, Decode::Little, Decode::Big]);
    }

    /// How every read is decoded, structures included, in layout order.
    fn all_decodes(stmts: &[Stmt]) -> Vec<Decode> {
        stmts
            .iter()
            .flat_map(|stmt| match stmt {
                Stmt::Read { decode, .. } => vec![*decode],
                Stmt::Structure { body, .. } => all_decodes(body),
                Stmt::Array { element: inner, .. } | Stmt::If { body: inner, .. } => {
                    all_decodes(std::slice::from_ref(inner))
                }
                Stmt::Call { .. } | Stmt::Switch { .. } | Stmt::Padding { .. } => Vec::new(),
            })
            .collect()
    }

    /// A request and a response header of one Type, the Type using another Type.
    const TYPES: &str = "name: demo\nfields:\n  - {name: req, type: Header}\n  - {name: resp, type: Header}\ntypes:\n  Header:\n    fields:\n      - {name: len, type: uint16}\n      - {name: stamp, type: Stamp}\n  Stamp:\n    fields: [ {name: secs, type: uint32} ]\n";

    /// Spec §5.2: Type names never appear in filter names, and each use of a Type registers its
    /// own `ProtoField`s, so a request and a response header can be filtered apart.
    #[test]
    fn each_use_of_a_type_registers_its_own_proto_fields() {
        let d = lowered(TYPES, "x");
        let abbrevs: Vec<&str> = d.proto_fields.iter().map(|f| f.abbrev.as_str()).collect();
        assert_eq!(
            abbrevs,
            [
                "demo.req",
                "demo.req.len",
                "demo.req.stamp",
                "demo.req.stamp.secs",
                "demo.resp",
                "demo.resp.len",
                "demo.resp.stamp",
                "demo.resp.stamp.secs",
            ]
        );
    }

    /// Spec §7.3: one dissect function per Type, each defined before the functions calling it.
    #[test]
    fn types_are_defined_after_the_types_they_use() {
        let d = lowered(TYPES, "x");
        let names: Vec<&str> = d.types.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["Stamp", "Header"]);
    }

    /// Every `ProtoField` a Type's function reads through its site table is in the table of
    /// each use, and is that use's `ProtoField` for the same Field.
    #[test]
    fn each_site_holds_the_proto_fields_its_type_reads() {
        fn slots(stmts: &[Stmt]) -> Vec<(String, String)> {
            let slot = |r: &Ref, path: &str| match r {
                Ref::Slot(key) => (key.clone(), path.to_owned()),
                Ref::Local(_) => panic!("{path} reads a local inside a Type"),
            };
            stmts
                .iter()
                .flat_map(|stmt| match stmt {
                    Stmt::Read { field, path, .. } | Stmt::Call { field, path, .. } => vec![slot(field, path)],
                    Stmt::Structure { field, path, body, .. } => {
                        [slot(field, path)].into_iter().chain(slots(body)).collect()
                    }
                    Stmt::Switch { .. } | Stmt::Padding { .. } => Vec::new(),
                    Stmt::Array { element: inner, .. } | Stmt::If { body: inner, .. } => {
                        slots(std::slice::from_ref(inner))
                    }
                })
                .collect()
        }
        fn check(d: &Dissector, site: &Site, ty: &str) {
            let function = d.types.iter().find(|t| t.name == ty).unwrap();
            for (key, path) in slots(&function.body) {
                let entry = site.entries.iter().find(|(k, _)| *k == key).map(|(_, e)| e);
                let Some(SiteEntry::Field(index)) = entry else { panic!("{} has no `{key}`", site.path) };
                assert_eq!(d.proto_fields[*index].abbrev, format!("demo.{}.{path}", site.path));
            }
            for (_, entry) in &site.entries {
                if let SiteEntry::Site(nested) = entry {
                    check(d, nested, "Stamp");
                }
            }
        }
        let d = lowered(TYPES, "x");
        let paths: Vec<&str> = d.sites.iter().map(|s| s.site.path.as_str()).collect();
        assert_eq!(paths, ["req", "resp"]);
        for shared in &d.sites {
            check(&d, &shared.site, "Header");
        }
    }

    /// Spec §3.5, §3.11: a Type reads in its own byte order, else the top level's, whatever
    /// encloses the place it is used.
    #[test]
    fn a_type_reads_in_its_own_byte_order() {
        let d = lowered(
            "name: demo\nendian: little\nfields:\n  - name: s\n    endian: big\n    fields: [ {name: a, type: A}, {name: b, type: B} ]\ntypes:\n  A:\n    fields: [ {name: x, type: uint16} ]\n  B:\n    endian: big\n    fields: [ {name: y, type: uint16}, {name: z, type: uint16, endian: little} ]\n",
            "x",
        );
        let decodes: Vec<(&str, Vec<Decode>)> =
            d.types.iter().map(|t| (t.name.as_str(), all_decodes(&t.body))).collect();
        assert_eq!(decodes, [("A", vec![Decode::Little]), ("B", vec![Decode::Big, Decode::Little])]);
    }

    #[test]
    fn labels_come_from_names() {
        assert_eq!(default_label("msg_type"), "Msg type");
        assert_eq!(default_label("id"), "Id");
        assert_eq!(default_label("ip_v4_addr"), "Ip v4 addr");
    }

    #[test]
    fn names_follow_the_identity_rules() {
        let d = lowered("name: demo\nfields: [ {name: a, type: uint8} ]\n", "dir\\sub/demo.wirdigen.yaml");
        assert_eq!((d.filter_name.as_str(), d.short_name.as_str(), d.full_name.as_str()), ("demo", "DEMO", "DEMO"));
        assert_eq!(d.source_name, "demo.wirdigen.yaml");
        let d = lowered("name: demo\ntitle: The Demo\nfields: [ {name: a, type: uint8} ]\n", "x");
        assert_eq!(d.full_name, "The Demo");
    }

    #[test]
    fn byte_order_applies_only_where_bytes_have_an_order() {
        let d = lowered(
            "name: demo\nendian: little\nfields:\n  - {name: a, type: uint16}\n  - {name: b, type: uint16, endian: big}\n  - {name: c, type: uint8}\n  - {name: d, type: ether}\n  - {name: e, type: int48}\n  - {name: f, type: uint40, endian: big}\n",
            "x",
        );
        let decodes: Vec<Decode> = reads(&d).into_iter().map(|(_, decode)| decode).collect();
        assert_eq!(
            decodes,
            [Decode::Little, Decode::Big, Decode::Big, Decode::Big, Decode::Lua("le_int64"), Decode::Lua("uint64")]
        );
    }

    /// ADR 0010: every operator is a prelude helper call, and `&&`/`||` keep C's short-circuit.
    #[test]
    fn expressions_lower_to_helper_calls() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: bytes, size: \"4 / -2 + 3\"}\n  - {name: b, type: bytes, size: \"0 && 1 << 2\"}\n  - {name: c, type: bytes, size: \"(2)\"}\n",
            "x",
        );
        let call = |helper, args| LuaExpr::Call { helper, args };
        // A constant was checked by validation: it is evaluated as is.
        let constant = |value| Length::Expression(Computed::checked_already(value));
        let lengths: Vec<Length> = reads(&d).into_iter().map(|(length, _)| length).collect();
        assert_eq!(
            lengths,
            [
                constant(call(
                    "wd_add",
                    vec![call("wd_div", vec![LuaExpr::Int(4), call("wd_neg", vec![LuaExpr::Int(2)])]), LuaExpr::Int(3)]
                )),
                constant(LuaExpr::And(
                    Box::new(LuaExpr::Int(0)),
                    Box::new(call("wd_shl", vec![LuaExpr::Int(1), LuaExpr::Int(2)]))
                )),
                Length::Fixed(2),
            ]
        );
    }

    /// Spec §7.3: a Dissector carries only the operator chunks its Expressions use.
    #[test]
    fn expressions_select_only_the_chunks_they_use() {
        let chunks = |size: &str| {
            let d = lowered(&format!("name: demo\nfields: [ {{name: a, type: bytes, size: \"{size}\"}} ]\n"), "x");
            let operators = [prelude::ARITHMETIC, prelude::DIVISION, prelude::BITWISE, prelude::LOGIC];
            let mut used: Vec<&str> = d.chunks.into_iter().filter(|c| operators.contains(c)).collect();
            used.sort_unstable();
            used
        };
        assert_eq!(chunks("8"), Vec::<&str>::new());
        assert_eq!(chunks("1 + 2"), ["arithmetic"]);
        assert_eq!(chunks("4 % 3 * 2"), ["arithmetic", "division"]);
        assert_eq!(chunks("~0 & 3"), ["bitwise"]);
        assert_eq!(chunks("(1 < 2) + !0"), ["arithmetic", "logic"]);
        assert_eq!(chunks("1 || 0"), ["logic"]);
    }

    /// The statement reading or calling the Field at `path` among `stmts`, structures included.
    fn stmt<'d>(stmts: &'d [Stmt], path: &str) -> &'d Stmt {
        fn find<'d>(stmts: &'d [Stmt], path: &str) -> Option<&'d Stmt> {
            stmts.iter().find_map(|s| match s {
                Stmt::Read { path: p, .. } | Stmt::Call { path: p, .. } if p == path => Some(s),
                Stmt::Structure { body, .. } => find(body, path),
                Stmt::Array { element: inner, .. } | Stmt::If { body: inner, .. } => {
                    find(std::slice::from_ref(inner), path)
                }
                Stmt::Read { .. } | Stmt::Call { .. } | Stmt::Switch { .. } | Stmt::Padding { .. } => None,
            })
        }
        find(stmts, path).unwrap_or_else(|| panic!("no statement reads `{path}`"))
    }

    /// The Expression a `size:` at `path` among `stmts` compiles to.
    fn size<'d>(stmts: &'d [Stmt], path: &str) -> &'d LuaExpr {
        match stmt(stmts, path) {
            Stmt::Read { length: Length::Expression(Computed { value, .. }), .. } => value,
            other => panic!("`{path}` has no Expression: {other:?}"),
        }
    }

    fn local(name: &str, keys: &[&str]) -> LuaExpr {
        LuaExpr::Local { local: name.to_owned(), keys: keys.iter().map(|k| (*k).to_owned()).collect() }
    }

    fn function<'d>(d: &'d Dissector, ty: &str) -> &'d TypeFunction {
        d.types.iter().find(|t| t.name == ty).unwrap()
    }

    /// Spec §4.3: a name resolves to the nearest earlier Field, the structure's own before the
    /// enclosing ones, and a dotted path reaches into a structure read earlier.
    #[test]
    fn references_read_the_nearest_earlier_field() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: len, type: uint8}\n  - name: hdr\n    fields:\n      - {name: len, type: uint16}\n      - {name: body, type: bytes, size: len}\n  - {name: data, type: bytes, size: len}\n  - {name: tail, type: bytes, size: hdr.len}\n",
            "x",
        );
        assert_eq!(size(&d.layout, "hdr.body"), &local("v_hdr__len", &[]));
        assert_eq!(size(&d.layout, "data"), &local("v_len", &[]));
        assert_eq!(size(&d.layout, "tail"), &local("v_hdr__len", &[]));
    }

    /// Spec §7.3: locals only for the Fields Expressions read, each read as a signed 64-bit
    /// integer in the Field's byte order, a `bool` as 1 or 0.
    #[test]
    fn only_referenced_fields_keep_their_values() {
        let d = lowered(
            "name: demo\nendian: little\nfields:\n  - {name: a, type: uint8}\n  - {name: b, type: int48}\n  - {name: c, type: uint64, endian: big}\n  - {name: d, type: bool}\n  - {name: e, type: uint16}\n  - {name: data, type: bytes, size: \"b + c + d\"}\n",
            "x",
        );
        assert_eq!(d.locals, ["v_b", "v_c", "v_d"]);
        let values: Vec<(&str, Option<&Value>)> = ["a", "b", "c", "d", "e"]
            .into_iter()
            .map(|path| match stmt(&d.layout, path) {
                Stmt::Read { value, .. } => (path, value.as_ref()),
                other => panic!("{other:?}"),
            })
            .collect();
        let value = |local: &str, read| Value { local: local.to_owned(), read };
        assert_eq!(
            values,
            [
                ("a", None),
                ("b", Some(&value("v_b", ValueRead::Integer("<i6".to_owned())))),
                ("c", Some(&value("v_c", ValueRead::Integer(">I8".to_owned())))),
                ("d", Some(&value("v_d", ValueRead::Bool))),
                ("e", None),
            ]
        );
    }

    /// The built-ins read the offset and the bytes left where the Field starts (spec §4.5).
    #[test]
    fn builtins_read_the_offset_and_what_is_left() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: bytes, size: _offset}\n  - {name: b, type: bytes, size: _remaining}\n",
            "x",
        );
        assert_eq!((size(&d.layout, "a"), size(&d.layout, "b")), (&LuaExpr::Offset, &LuaExpr::Remaining));
    }

    /// A Type, the same at every use, with a name it does not declare and two uses where that
    /// name resolves to different Fields.
    const CONTEXT: &str = "name: demo\nfields:\n  - {name: len, type: uint8}\n  - {name: first, type: Record}\n  - name: inner\n    fields:\n      - {name: len, type: uint16}\n      - {name: second, type: Record}\ntypes:\n  Record:\n    fields:\n      - {name: count, type: uint8}\n      - {name: items, type: bytes, size: \"count + len\"}\n";

    /// Spec §3.5, §7.3: a Type reads its own Fields from locals, and a name it does not declare
    /// from the context table each use passes, resolved at that use.
    #[test]
    fn a_type_reads_outer_names_through_the_context_table_of_each_use() {
        let d = lowered(CONTEXT, "x");
        let record = function(&d, "Record");
        assert!(record.context);
        assert_eq!(record.locals, ["v_count"]);
        assert_eq!(
            size(&record.body, "items"),
            &LuaExpr::Call { helper: "wd_add", args: vec![local("v_count", &[]), LuaExpr::Context("len".to_owned())] }
        );
        let context = |path| match stmt(&d.layout, path) {
            Stmt::Call { context, .. } => context.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(context("first"), [("len".to_owned(), local("v_len", &[]))]);
        assert_eq!(context("inner.second"), [("len".to_owned(), local("v_inner__len", &[]))]);
    }

    /// A Type that does not resolve a name passes on the value its own caller gave.
    #[test]
    fn a_type_passes_on_names_it_does_not_declare() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: len, type: uint8}\n  - {name: outer, type: Outer}\ntypes:\n  Outer:\n    fields: [ {name: inner, type: Inner} ]\n  Inner:\n    fields: [ {name: data, type: bytes, size: len} ]\n",
            "x",
        );
        let outer = function(&d, "Outer");
        assert!(outer.context);
        match stmt(&outer.body, "inner") {
            Stmt::Call { context, .. } => {
                assert_eq!(context, &[("len".to_owned(), LuaExpr::Context("len".to_owned()))]);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(size(&function(&d, "Inner").body, "data"), &LuaExpr::Context("len".to_owned()));
    }

    /// A Type without names from outside takes no context table, and returns nothing more than
    /// the offset when no caller reads inside it.
    #[test]
    fn a_self_contained_type_takes_and_returns_only_the_offset() {
        let d = lowered(TYPES, "x");
        for t in &d.types {
            assert!(!t.context && t.locals.is_empty() && t.exports.is_empty(), "{}", t.name);
        }
    }

    /// Spec §4.3: a path into a Field of a Type reads what the Type returns, through each Type
    /// and inline structure on the way.
    #[test]
    fn reading_inside_a_type_reads_the_table_it_returns() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: o, type: Outer}\n  - {name: data, type: bytes, size: \"o.inner.n + o.opts.m\"}\ntypes:\n  Outer:\n    fields:\n      - {name: inner, type: Inner}\n      - name: opts\n        fields: [ {name: m, type: uint8} ]\n  Inner:\n    fields: [ {name: n, type: uint8} ]\n",
            "x",
        );
        assert_eq!(
            size(&d.layout, "data"),
            &LuaExpr::Call {
                helper: "wd_add",
                args: vec![local("v_o", &["inner", "n"]), local("v_o", &["opts", "m"])]
            }
        );
        match stmt(&d.layout, "o") {
            Stmt::Call { result, .. } => assert_eq!(result.as_deref(), Some("v_o")),
            other => panic!("{other:?}"),
        }
        let outer = function(&d, "Outer");
        assert_eq!(outer.locals, ["v_inner", "v_opts__m"]);
        let table = |entries: &[(&str, Export)]| {
            entries.iter().map(|(k, e)| ((*k).to_owned(), e.clone())).collect::<BTreeMap<_, _>>()
        };
        let export = |local: &str| Export::Local(local.to_owned());
        assert_eq!(
            outer.exports,
            table(&[("inner", export("v_inner")), ("opts", Export::Table(table(&[("m", export("v_opts__m"))])))])
        );
        assert_eq!(function(&d, "Inner").exports, table(&[("n", export("v_n"))]));
    }

    /// Spec §4.4, §7.3: a size known only at runtime is checked for a negative value, under the
    /// `invalid` chunk, and runs under `wd_evaluate` only when an operator can fault.
    #[test]
    fn runtime_sizes_select_their_checks_and_chunks() {
        let checks = |size: &str| {
            let d = lowered(
                &format!(
                    "name: demo\nfields:\n  - {{name: n, type: uint8}}\n  - {{name: a, type: bytes, size: \"{size}\"}}\n"
                ),
                "x",
            );
            let (checked, faults) = match stmt(&d.layout, "a") {
                Stmt::Read { length: Length::Expression(Computed { checked, faults, .. }), .. } => (*checked, *faults),
                other => panic!("{other:?}"),
            };
            (checked, faults, d.chunks.contains(&prelude::INVALID))
        };
        assert_eq!(checks("4 / 2"), (false, false, false));
        assert_eq!(checks("n * 2"), (true, false, true));
        assert_eq!(checks("_remaining - 1"), (true, false, true));
        assert_eq!(checks("n / 2"), (true, true, true));
        assert_eq!(checks("1 << n"), (true, true, true));
        assert_eq!(checks("-(n % 3)"), (true, true, true));
    }

    /// The array statement of the Field at `path` among `stmts`.
    fn array<'d>(stmts: &'d [Stmt], path: &str) -> (&'d Repeat, &'d Stmt) {
        stmts
            .iter()
            .find_map(|s| match s {
                Stmt::Array { path: p, repeat, element } if p == path => Some((repeat, element.as_ref())),
                _ => None,
            })
            .unwrap_or_else(|| panic!("`{path}` is not an array"))
    }

    /// Spec §3.7, §5.2: an array repeats its element's statement, and its elements share one set
    /// of `ProtoField`s. Its count is read like a size, and an element can read inside itself.
    #[test]
    fn an_array_repeats_its_element_with_one_set_of_proto_fields() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: n, type: uint8}\n  - name: items\n    count: n\n    fields:\n      - {name: len, type: uint8}\n      - {name: data, type: bytes, size: len}\n",
            "x",
        );
        let abbrevs: Vec<&str> = d.proto_fields.iter().map(|f| f.abbrev.as_str()).collect();
        assert_eq!(abbrevs, ["demo.n", "demo.items", "demo.items.len", "demo.items.data"]);
        let (repeat, element) = array(&d.layout, "items");
        assert_eq!(repeat, &Repeat::Count(Computed { value: local("v_n", &[]), checked: true, faults: false }));
        assert!(matches!(element, Stmt::Structure { path, .. } if path == "items"));
        assert_eq!(size(&d.layout, "items.data"), &local("v_items__len", &[]));
        assert!(d.chunks.contains(&prelude::INVALID), "an empty element is reported as malformed");
    }

    /// A constant count needs no runtime check; `repeat: to_end` has no count, and a Type repeats
    /// by calling its dissect function once per element.
    #[test]
    fn constant_counts_and_repeats_to_the_end() {
        let d = lowered(
            "name: demo\nfields:\n  - name: pair\n    count: 2\n    type: Item\n  - name: rest\n    repeat: to_end\n    fields: [ {name: id, type: uint8} ]\ntypes:\n  Item:\n    fields: [ {name: id, type: uint8} ]\n",
            "x",
        );
        let (repeat, element) = array(&d.layout, "pair");
        assert_eq!(repeat, &Repeat::Count(Computed::checked_already(LuaExpr::Int(2))));
        assert!(matches!(element, Stmt::Call { ty, .. } if ty == "Item"));
        assert_eq!(array(&d.layout, "rest").0, &Repeat::ToEnd);
    }

    /// Reading a `bool` for an Expression needs `wd_bool`.
    #[test]
    fn a_referenced_bool_brings_the_logic_chunk() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: f, type: bool}\n  - {name: a, type: bytes, size: \"f * 4\"}\n",
            "x",
        );
        assert!(d.chunks.contains(&prelude::LOGIC));
    }

    #[test]
    fn prefixes_follow_their_width_and_byte_order() {
        let d = lowered(
            "name: demo\nendian: little\nfields:\n  - {name: a, type: string, prefix: uint8}\n  - {name: b, type: bytes, prefix: uint16}\n  - {name: c, type: bytes, prefix: uint16, endian: big}\n  - {name: d, type: string, prefix: uint64}\n",
            "x",
        );
        let lengths: Vec<Length> = reads(&d).into_iter().map(|(length, _)| length).collect();
        assert_eq!(
            lengths,
            [
                Length::Prefix { size: 1, read: "uint()" },
                Length::Prefix { size: 2, read: "le_uint()" },
                Length::Prefix { size: 2, read: "uint()" },
                Length::Prefix { size: 8, read: "le_uint64():tonumber()" },
            ]
        );
    }

    #[test]
    fn terminators_bring_their_chunk_and_follow_the_code_unit() {
        let d = lowered("name: demo\nfields: [ {name: a, type: string, size: 2} ]\n", "x");
        assert!(!d.chunks.contains(&prelude::TERMINATED));
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: string, terminator: 0, encoding: ucs2}\n  - {name: b, type: bytes, terminator: 255}\n",
            "x",
        );
        assert!(d.chunks.contains(&prelude::TERMINATED));
        let lengths: Vec<Length> = reads(&d).into_iter().map(|(length, _)| length).collect();
        assert_eq!(
            lengths,
            [Length::Terminator { terminator: 0, width: 2 }, Length::Terminator { terminator: 255, width: 1 }]
        );
    }

    #[test]
    fn only_a_nul_terminated_string_is_a_stringz() {
        let d = lowered(
            "name: demo\nfields:\n  - {name: a, type: string, terminator: 0}\n  - {name: b, type: string, terminator: 10}\n  - {name: c, type: bytes, terminator: 0}\n",
            "x",
        );
        let constructors: Vec<&str> = d.proto_fields.iter().map(|f| f.field_type.constructor).collect();
        assert_eq!(constructors, ["stringz", "string", "bytes"]);
    }

    #[test]
    fn timestamps_size_and_byte_order_follow_their_encoding() {
        let d = lowered(
            "name: demo\nendian: little\nfields:\n  - {name: a, type: abs_time}\n  - {name: b, type: rel_time, encoding: nsecs, endian: big}\n  - {name: c, type: string, size: 2, encoding: latin1}\n",
            "x",
        );
        let reads: Vec<(Length, Decode)> = reads(&d);
        assert_eq!(
            reads,
            [
                (Length::Fixed(4), Decode::Encoded { encoding: "ENC_TIME_SECS", endian: Some("ENC_LITTLE_ENDIAN") }),
                (Length::Fixed(8), Decode::Encoded { encoding: "ENC_TIME_NSECS", endian: Some("ENC_BIG_ENDIAN") }),
                (Length::Fixed(2), Decode::Encoded { encoding: "ENC_ISO_8859_1", endian: None }),
            ]
        );
        let constructors: Vec<&str> = d.proto_fields.iter().map(|f| f.field_type.constructor).collect();
        assert_eq!(constructors, ["absolute_time", "relative_time", "string"]);
    }
}
