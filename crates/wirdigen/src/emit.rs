//! The emitter: prints the lowered model as Lua through an indenting writer (ADR 0010).
//!
//! The format is fixed here: 4-space indent, `\n` line endings, one trailing newline, no
//! timestamps or paths. Native bitwise operators and `//` are never printed (Lua 5.2 must parse
//! the file): each Expression operator is printed as a call of its prelude helper.
//!
//! The body, from the dissect functions on, is printed first. The prelude chunks it uses are
//! worked out from its text, and the header (the prelude, the `ProtoField`s, the expert infos)
//! is printed from them.
//!
//! No function may grow past Lua's limits of 200 locals, 255 upvalues and 255 registers,
//! however large the description (#199). So the main chunk keeps each of the Dissector's own
//! declarations (`ProtoField`s, value tables, site tables, field extractors, dissect functions)
//! in one table, `wd`, rather than in a local each; a dissect function keeps the values
//! Expressions read in one table, `v`; and a statement nested [`NESTING`] statements deep is a
//! part: a function of its own, defined before the function it is in. Lua's parser also limits
//! how deep blocks nest in the source (about 200 levels, counting each statement and
//! expression), so the part cannot be a closure written in place.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Write as _};

use crate::expr::{BinaryOp, UnaryOp};
use crate::lower::{
    Args, BitItem, Branch, Computed, Decode, Dissector, ExpectCheck, Export, Info, InfoPart, Length, LuaExpr, LuaTable,
    PortPreference, ProtoField, Ref, Repeat, Site, SiteEntry, Stmt, Strings, TableRef, ValueRead,
};
use crate::prelude::{self, Chunks};

const INDENT: &str = "    ";

/// Wirdigen's version, written in the header of every Dissector.
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
struct Writer {
    out: String,
    depth: usize,
    /// How many statements holding statements the line being written is in, in the current Lua
    /// function.
    nesting: usize,
    /// The dissect function being written.
    frame: Frame,
    /// The parts of the dissect function being written, function definitions in the order they
    /// are defined: each after the parts it calls. One buffer, reused from one dissect function
    /// to the next.
    parts: String,
    /// How many parts the Dissector has so far.
    part_count: usize,
}

/// A dissect function, as its parts see it.
#[derive(Default)]
struct Frame {
    /// Its key in `wd` (`dissect_top`).
    key: String,
    /// Its parameters (`tvb, pinfo, tree, offset`).
    params: String,
    /// Whether it keeps values Expressions read, in its table `v`.
    values: bool,
}

impl Frame {
    /// The arguments it passes its parts: its own parameters, and its values table.
    fn args(&self) -> String {
        if self.values { format!("{}, v", self.params) } else { self.params.clone() }
    }
}

impl Writer {
    /// Writes `text` as one line, indented unless it is empty, straight into `out`.
    fn line(&mut self, text: impl Display) {
        let start = self.out.len();
        for _ in 0..self.depth {
            self.out.push_str(INDENT);
        }
        let indented = self.out.len();
        write!(self.out, "{text}").expect("writing to a String");
        if self.out.len() == indented {
            self.out.truncate(start);
        }
        self.out.push('\n');
    }

    /// Writes a prelude line as is: the prelude carries its own indentation.
    fn raw(&mut self, text: &str) {
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn block(&mut self, open: impl Display, body: impl FnOnce(&mut Self), close: impl Display) {
        self.line(open);
        self.depth += 1;
        body(self);
        self.depth -= 1;
        self.line(close);
    }

    /// What `write` writes, from no indentation and no nesting, rather than into `out`. The frame
    /// and the parts are left as they are: a part belongs to the dissect function being written,
    /// and the parts it writes go to the same buffer.
    fn detached(&mut self, write: impl FnOnce(&mut Self)) -> String {
        let out = std::mem::take(&mut self.out);
        let depth = std::mem::replace(&mut self.depth, 0);
        let nesting = std::mem::replace(&mut self.nesting, 0);
        write(self);
        self.depth = depth;
        self.nesting = nesting;
        std::mem::replace(&mut self.out, out)
    }
}

/// How many statements holding statements (`if:`, `switch`, inline structures, arrays) nest in
/// one Lua function before the next one is a part. Each holds at most 10 locals and 4 levels of
/// blocks, so a function keeps well within Lua's 200 locals, 255 registers and 200 levels of
/// blocks, an Expression as deep as ADR 0018 allows included.
const NESTING: usize = 4;

/// The table holding the Dissector's own declarations, `wd.<key>`.
const fn own(key: &str) -> Place<'_> {
    Place::Own(key)
}

/// The Lua expression of a declaration: one of the Dissector's own, or a slot of the site table.
#[derive(Clone, Copy)]
enum Place<'a> {
    /// `wd.<key>`.
    Own(&'a str),
    /// `site.<key>`.
    Slot(&'a str),
}

impl Display for Place<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Place::Own(key) => write!(f, "wd.{key}"),
            Place::Slot(key) => write!(f, "site.{key}"),
        }
    }
}

/// Writes each of `items` as `write` says, separated by `separator`.
fn join<T>(
    f: &mut fmt::Formatter<'_>,
    items: impl IntoIterator<Item = T>,
    separator: &str,
    mut write: impl FnMut(&mut fmt::Formatter<'_>, T) -> fmt::Result,
) -> fmt::Result {
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            f.write_str(separator)?;
        }
        write(f, item)?;
    }
    Ok(())
}

/// Text that `write` writes when it is displayed, built from parts without a `String` of its own.
const fn display_with<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result>(write: F) -> DisplayWith<F> {
    DisplayWith(write)
}

/// What [`display_with`] returns.
#[derive(Clone, Copy)]
struct DisplayWith<F>(F);

impl<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result> Display for DisplayWith<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self.0)(f)
    }
}

/// The `wd_` names the emitter declares itself, outside the prelude.
#[cfg(test)]
const DECLARED: [&str; 10] = [
    "wd_proto",
    "wd_f_unmatched",
    "wd_ei_truncated",
    "wd_ei_invalid",
    "wd_ei_empty",
    "wd_ei_unmatched",
    "wd_ei_unexpected",
    "wd_ei_dissector",
    "wd_message_length",
    "wd_dissect_message",
];

pub(crate) fn emit(model: &Dissector) -> String {
    let mut out = body(model);
    let header = header(model, &Chunks::used_by(&out));
    // The header goes in front of the body in the body's own buffer, grown once to the exact
    // size: no second copy of the body is alive alongside it (#232).
    out.reserve_exact(header.len());
    out.insert_str(0, &header);
    out
}

/// The header: the prelude chunks `chunks`, the `ProtoField`s, the tables and the expert infos,
/// everything that comes before the body.
fn header(model: &Dissector, chunks: &Chunks) -> String {
    let mut w = Writer::default();
    w.line(format_args!("-- Generated by Wirdigen {VERSION} from {}", comment_text(&model.source_name)));
    w.line("-- Requires Wireshark >= 4.4");
    w.line("");
    for line in chunks.lines() {
        w.raw(line);
    }

    let proto = lua_string(&model.filter_name);
    w.line(format_args!("local wd_proto = Proto({proto}, {})", lua_string(&model.full_name)));
    w.line("-- The Dissector's own declarations");
    w.line("local wd = {}");
    w.line("");
    for shared in &model.tables {
        w.block(format_args!("{} = {{", own(&shared.key)), |w| table_entries(w, &shared.table), "}");
        w.line("");
    }
    if !model.names.is_empty() {
        w.line("-- The names of values, for switch Fields and the Info column");
        for names in &model.names {
            let entries = LuaTable::Ranges(names.entries.clone());
            w.block(format_args!("{} = {{", own(&names.key)), |w| table_entries(w, &entries), "}");
        }
        w.line("");
    }
    for field in &model.proto_fields {
        proto_field(&mut w, model, field);
    }
    let unmatched = chunks.contains(prelude::UNMATCHED);
    if unmatched {
        w.line(format_args!("local wd_f_unmatched = wd_field_unmatched({proto})"));
    }
    w.line("");
    w.block(
        "wd_proto.fields = {",
        |w| {
            model.proto_fields.iter().for_each(|f| w.line(format_args!("{},", own(&f.key))));
            if unmatched {
                w.line("wd_f_unmatched,");
            }
        },
        "}",
    );
    w.line("");
    if !model.extractors.is_empty() {
        w.line("-- The Fields the Info column shows, extracted from each packet once it is read");
        for extractor in &model.extractors {
            w.line(format_args!("{} = Field.new({})", own(&extractor.key), lua_string(&extractor.abbrev)));
        }
        w.line("");
    }
    if !model.sites.is_empty() {
        w.line("-- The ProtoFields of each use of a Type, passed to the Type's dissect function");
        for shared in &model.sites {
            w.block(format_args!("{} = {{", own(&shared.key)), |w| site_entries(w, model, &shared.site), "}");
        }
        w.line("");
    }
    experts(&mut w, chunks, proto);
    w.out
}

/// The dissect functions, the entry point and the registration: everything that comes after
/// the declarations the prelude chunks it uses decide.
fn body(model: &Dissector) -> String {
    let mut w = Writer::default();
    // Every dissect function returns the offset after what it read, or `nil` once it stopped
    // on a truncated or malformed packet, so that its callers stop too. A Type whose caller
    // reads inside it also returns the values read, in a table.
    for function in &model.types {
        let context = if function.context { ", ctx" } else { "" };
        let frame = Frame {
            key: format!("dissect_{}", function.name),
            params: format!("tvb, pinfo, tree, offset, site{context}"),
            values: !function.values.is_empty(),
        };
        dissect_function(&mut w, &format!("-- Type: {}", function.name), frame, |w| {
            for stmt in &function.body {
                statement(w, model, stmt, Scope::Type);
            }
            if function.exports.is_empty() {
                w.line("return offset");
            } else {
                return_exports(w, &function.exports);
            }
        });
    }

    let frame = Frame {
        key: "dissect_top".to_owned(),
        params: "tvb, pinfo, tree, offset".to_owned(),
        values: !model.values.is_empty(),
    };
    dissect_function(&mut w, "-- Layout", frame, |w| {
        for stmt in &model.layout {
            statement(w, model, stmt, Scope::Top);
        }
        w.line("return offset");
    });

    dissector(&mut w, model);
    w.line("");

    if !model.port_preferences.is_empty() {
        port_preferences(&mut w, &model.port_preferences);
    }
    w.line("-- Decode As");
    w.line("DissectorTable.get(\"udp.port\"):add_for_decode_as(wd_proto)");
    w.line("DissectorTable.get(\"tcp.port\"):add_for_decode_as(wd_proto)");
    w.out
}

/// Writes the dissect function `frame`, with the comment `comment`, running the statements
/// `body` writes. Its parts are defined before it.
fn dissect_function(w: &mut Writer, comment: &str, frame: Frame, body: impl FnOnce(&mut Writer)) {
    let open = format!("function wd.{}({})", frame.key, frame.params);
    let values = frame.values;
    w.frame = frame;
    // The function is written in place, and its parts, known once it is written, are put in
    // front of it: the function, as large as the Layout can make it, is never copied out of
    // `out` (#232).
    let start = w.out.len();
    w.line(comment);
    w.block(
        &open,
        |w| {
            declare(w, values);
            body(w);
        },
        "end",
    );
    w.out.insert_str(start, &w.parts);
    w.parts.clear();
    w.line("");
}

/// The Dissector's entry point: it sets the columns and reads the Message into the protocol's
/// tree. Under `framing:` and TCP, it reads each Message of the segment (spec §3.13).
fn dissector(w: &mut Writer, model: &Dissector) {
    let Some(framing) = &model.framing else {
        w.block(
            "function wd_proto.dissector(tvb, pinfo, tree)",
            |w| {
                w.line(format_args!("pinfo.cols.protocol = {}", lua_string(&model.short_name)));
                message(w, model);
                w.line("return tvb:len()");
            },
            "end",
        );
        return;
    };
    w.line(format_args!("-- Framing: the length of the Message at `offset`, from its {}-byte header", framing.header));
    w.block(
        "local function wd_message_length(tvb, offset)",
        |w| {
            w.line("local v = {}");
            for read in &framing.reads {
                let at = display_with(|f| write!(f, "offset + {}", read.offset));
                w.line(format_args!("{} = {}", kept(&read.key), read_value_at(&read.read, at, read.size)));
            }
            // The prelude evaluates it under `wd_evaluate`, which catches its faults.
            w.line(format_args!("return {}", lua_expr(&framing.length.value)));
        },
        "end",
    );
    w.line("");
    w.block(
        "local function wd_dissect_message(tvb, pinfo, tree, malformed)",
        |w| {
            w.block(
                "if malformed then",
                |w| {
                    w.line(root_line(model));
                    w.line("wd_invalid(root, wd_ei_invalid, malformed, \"framing\")");
                    w.line("return");
                },
                "end",
            );
            message(w, model);
        },
        "end",
    );
    w.line("");
    w.block(
        "function wd_proto.dissector(tvb, pinfo, tree)",
        |w| {
            w.line(format_args!("pinfo.cols.protocol = {}", lua_string(&model.short_name)));
            w.block(
                "if pinfo.port_type == wd_port_type_tcp then",
                |w| {
                    let header = framing.header;
                    w.line(format_args!(
                        "return wd_framed(tvb, pinfo, tree, {header}, wd_message_length, wd_dissect_message)"
                    ));
                },
                "end",
            );
            w.line("wd_dissect_message(tvb, pinfo, tree)");
            w.line("return tvb:len()");
        },
        "end",
    );
}

/// The line adding the protocol's tree root over the whole of `tvb`.
fn root_line(model: &Dissector) -> impl Display + '_ {
    display_with(|f| write!(f, "local root = tree:add(wd_proto, tvb(0, tvb:len()), {})", lua_string(&model.full_name)))
}

/// The lines reading one Message, the whole of `tvb`, under its own tree root, then setting the
/// Info column.
fn message(w: &mut Writer, model: &Dissector) {
    if model.info.as_ref().is_some_and(Info::shows_case) {
        w.line("wd_info_cases = {}");
    }
    if !model.extractors.is_empty() {
        let fields = display_with(|f| join(f, &model.extractors, ", ", |f, x| write!(f, "{}", own(&x.key))));
        w.line(format_args!("local before = wd_info_counts({{ {fields} }})"));
    }
    w.line(root_line(model));
    w.line("wd.dissect_top(tvb, pinfo, root, 0)");
    if let Some(info) = &model.info {
        info_column(w, model, info);
    }
}

/// Sets the Info column once the Message is read, however far it was read (spec §3.14), from
/// the values it read: `before` holds the extractors' counts from before it. The fence is cleared
/// first, so the text replaces what TCP reassembly fenced off from an earlier Message.
fn info_column(w: &mut Writer, model: &Dissector, info: &Info) {
    let case = |path| display_with(move |f| write!(f, "wd_info_cases[{}]", lua_string(path)));
    match info {
        Info::Template(parts) if parts.is_empty() => set_info(w, "\"\""),
        Info::Template(parts) => {
            let text = display_with(|f| {
                join(f, parts, " .. ", |f, part| match part {
                    InfoPart::Text(text) => write!(f, "{}", lua_string(text)),
                    InfoPart::Display(extractor) => {
                        write!(f, "wd_info_display({}, before)", own(&model.extractors[*extractor].key))
                    }
                    InfoPart::Label { extractor, names } => {
                        let extractor = own(&model.extractors[*extractor].key);
                        match names {
                            Some(n) => write!(f, "wd_info_label({extractor}, before, {})", own(&model.names[*n].key)),
                            None => write!(f, "wd_info_label({extractor}, before, {{}})"),
                        }
                    }
                    InfoPart::Case(path) => write!(f, "({} or \"\")", case(path)),
                })
            });
            set_info(w, text);
        }
        Info::Case(path) => {
            w.block(format_args!("if {} then", case(path)), |w| set_info(w, case(path)), "end");
        }
    }
}

/// Sets the Info column to the Lua expression `text`, clearing its fence first so the text
/// replaces the whole column (spec §3.14).
fn set_info(w: &mut Writer, text: impl Display) {
    w.line("pinfo.cols.info:clear_fence()");
    w.line(format_args!("pinfo.cols.info = {text}"));
}

/// Declares the range preferences and registers on the ports they hold (spec §3.12, §5.5).
fn port_preferences(w: &mut Writer, preferences: &[PortPreference]) {
    w.line("-- Registration");
    for p in preferences {
        w.line(format_args!(
            "wd_proto.prefs.{} = Pref.range({}, {}, {}, {})",
            p.name,
            lua_string(&p.label),
            lua_string(&p.default),
            lua_string(&p.description),
            u16::MAX,
        ));
    }
    let pairs: Vec<String> =
        preferences.iter().map(|p| format!("{{ {}, {} }}", lua_string(p.name), lua_string(p.table))).collect();
    w.line(format_args!("wd_register_ports(wd_proto, {{ {} }})", pairs.join(", ")));
    w.line("");
}

/// Declares the expert infos the Dissector reports, `proto` being its filter name as a Lua
/// string.
fn experts(w: &mut Writer, chunks: &Chunks, proto: LuaString<'_>) {
    /// The expert info of each chunk reporting one, the local holding it and its constructor.
    const EXPERTS: [(&str, &str, &str); 6] = [
        (prelude::MALFORMED, "wd_ei_truncated", "wd_expert_truncated"),
        (prelude::INVALID, "wd_ei_invalid", "wd_expert_invalid"),
        (prelude::EMPTY, "wd_ei_empty", "wd_expert_empty"),
        (prelude::UNMATCHED, "wd_ei_unmatched", "wd_expert_unmatched"),
        (prelude::UNEXPECTED, "wd_ei_unexpected", "wd_expert_unexpected"),
        (prelude::HANDOFF, "wd_ei_dissector", "wd_expert_dissector"),
    ];
    let mut experts = Vec::new();
    for (chunk, local, constructor) in EXPERTS {
        if chunks.contains(chunk) {
            w.line(format_args!("local {local} = {constructor}({proto})"));
            experts.push(local);
        }
    }
    w.line(format_args!("wd_proto.experts = {{ {} }}", experts.join(", ")));
    w.line("");
}

/// Writes the declaration of a `ProtoField`. An inline value table spans several lines.
fn proto_field(w: &mut Writer, model: &Dissector, field: &ProtoField) {
    // Whether a value string and a mask come between the display and the blurb. `float` and
    // `double` have no display: their unit table, if any, comes right after the label.
    let (display, mapping_slots) = match field.field_type.args {
        Args::Display(display) => (Some(display), true),
        Args::Base(display) => (Some(display), false),
        Args::Plain => (None, false),
    };
    let flag = match &field.strings {
        Some(Strings::Table { range: true, .. }) => " + base.RANGE_STRING",
        Some(Strings::Unit { .. }) if mapping_slots => " + base.UNIT_STRING",
        _ => "",
    };
    let inline = match &field.strings {
        Some(Strings::Table { table: TableRef::Inline(table), .. }) => Some(table),
        _ => None,
    };
    let open = display_with(|f| {
        write!(f, "{} = ProtoField.{}(", own(&field.key), field.field_type.constructor)?;
        write!(f, "{}, {}", lua_string(&field.abbrev), lua_string(&field.label))?;
        if let Some(display) = display {
            write!(f, ", {display}{flag}")?;
        }
        match &field.strings {
            None | Some(Strings::Table { table: TableRef::Inline(_), .. }) => Ok(()),
            Some(Strings::Table { table: TableRef::Shared(index), .. }) => {
                write!(f, ", {}", own(&model.tables[*index].key))
            }
            Some(Strings::Unit { singular, plural }) => {
                f.write_str(", { ")?;
                join(f, [Some(singular), plural.as_ref()].into_iter().flatten(), ", ", |f, form| {
                    write!(f, "{}", lua_string(form))
                })?;
                f.write_str(" }")
            }
            Some(Strings::TrueFalse { when_true, when_false }) => {
                write!(f, ", {{ {}, {} }}", lua_string(when_true), lua_string(when_false))
            }
        }
    });
    let close = display_with(|f| {
        if mapping_slots && (field.mask.is_some() || field.description.is_some()) {
            // Slots before the last one given that nothing fills stay `nil`: the value string,
            // the mask. A mask is written in hexadecimal, as wide as its container.
            if field.strings.is_none() {
                f.write_str(", nil")?;
            }
            match field.mask {
                Some(m) => write!(f, ", 0x{:0width$X}", m.bits, width = 2 * m.bytes)?,
                None => f.write_str(", nil")?,
            }
        }
        if let Some(description) = &field.description {
            write!(f, ", {}", lua_string(description))?;
        }
        Ok(())
    });
    match inline {
        Some(table) => w.block(format_args!("{open}, {{"), |w| table_entries(w, table), format_args!("}}{close})")),
        None => w.line(format_args!("{open}{close})")),
    }
}

/// The entries of a value table, one per line.
fn table_entries(w: &mut Writer, table: &LuaTable) {
    match table {
        LuaTable::Values(entries) => {
            for (key, label) in entries {
                w.line(format_args!("[{}] = {},", lua_integer(*key), lua_string(label)));
            }
        }
        LuaTable::Ranges(entries) => {
            for (low, high, label) in entries {
                w.line(format_args!("{{ {}, {}, {} }},", lua_integer(*low), lua_integer(*high), lua_string(label)));
            }
        }
    }
}

/// A Lua integer literal. `-9223372036854775808` would be the negation of a literal too large
/// for an integer, which Lua reads as a float, so the minimum is written as an expression.
const fn lua_integer(value: i64) -> LuaInteger {
    LuaInteger(value)
}

/// What [`lua_integer`] writes.
struct LuaInteger(i64);

impl Display for LuaInteger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == i64::MIN { f.write_str("(-9223372036854775807 - 1)") } else { write!(f, "{}", self.0) }
    }
}

/// The slots of a site table, one per line. A nested site table is declared before it, so
/// no table constructor nests in another, however deep Types use Types.
fn site_entries(w: &mut Writer, model: &Dissector, site: &Site) {
    w.line(format_args!("path = {},", lua_string(&site.path)));
    for (key, entry) in &site.entries {
        let value = match entry {
            SiteEntry::Field(index) => &model.proto_fields[*index].key,
            SiteEntry::Site(index) => &model.sites[*index].key,
        };
        w.line(format_args!("{key} = {},", own(value)));
    }
}

/// Declares, up front, the table a function keeps the values Expressions read in, when it keeps
/// any: values read inside a structure are read later, after the structure's `do` block has
/// ended.
fn declare(w: &mut Writer, values: bool) {
    if values {
        w.line("local v = {}");
    }
}

/// The Lua expression of the value kept under `key` in the function's values table.
fn kept(key: &str) -> impl Display + '_ {
    display_with(move |f| write!(f, "v{}", index(key)))
}

/// Writes the return of a Type's dissect function, with the table of what it `exports`. A table
/// nested in it, for an inline structure, is assigned once the table holding it exists, rather
/// than written as a nested table constructor: each would take a register and a level of
/// Lua's parser, however deep the structures nest.
fn return_exports(w: &mut Writer, exports: &BTreeMap<String, Export>) {
    if exports.values().all(|export| matches!(export, Export::Value(_))) {
        w.line(format_args!("return offset, {}", values_constructor(exports)));
        return;
    }
    w.line(format_args!("local exports = {}", values_constructor(exports)));
    nested_exports(w, "exports", exports);
    w.line("return offset, exports");
}

/// Assigns the tables nested in `table`, the export table at the Lua expression `access`.
fn nested_exports(w: &mut Writer, access: &str, table: &BTreeMap<String, Export>) {
    for (key, export) in table {
        if let Export::Table(inner) = export {
            let access = format!("{access}{}", index(key));
            w.line(format_args!("{access} = {}", values_constructor(inner)));
            nested_exports(w, &access, inner);
        }
    }
}

/// The table constructor of the values of an export table, without the tables nested in it.
fn values_constructor(table: &BTreeMap<String, Export>) -> impl Display + '_ {
    display_with(move |f| {
        let mut values = table.iter().filter_map(|(key, export)| match export {
            Export::Value(held) => Some((key, held)),
            Export::Table(_) => None,
        });
        if values.clone().next().is_none() {
            return f.write_str("{}");
        }
        f.write_str("{ ")?;
        join(f, &mut values, ", ", |f, (key, held)| write!(f, "{} = {}", table_key(key), kept(held)))?;
        f.write_str(" }")
    })
}

/// The Lua keywords, which cannot be written as plain table keys.
const LUA_KEYWORDS: [&str; 22] = [
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if", "in", "local", "nil",
    "not", "or", "repeat", "return", "then", "true", "until", "while",
];

/// Whether `key` can be written as a plain name: `t.key`, `{ key = ... }`.
fn is_plain_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !LUA_KEYWORDS.contains(&key)
}

/// A key in a table constructor: `key` or `["key"]`.
fn table_key(key: &str) -> impl Display + '_ {
    display_with(move |f| if is_plain_key(key) { f.write_str(key) } else { write!(f, "[{}]", lua_string(key)) })
}

/// An index into a table: `.key` or `["key"]`.
fn index(key: &str) -> impl Display + '_ {
    display_with(move |f| if is_plain_key(key) { write!(f, ".{key}") } else { write!(f, "[{}]", lua_string(key)) })
}

/// Which dissect function a statement is in, which says how its paths are reported.
#[derive(Clone, Copy)]
enum Scope {
    /// The top-level layout: paths are whole.
    Top,
    /// A Type's function: paths are relative to the Type, and extend the site table's path.
    Type,
}

/// The Lua expression of a `ProtoField`.
fn field_ref<'a>(model: &'a Dissector, r: &'a Ref) -> Place<'a> {
    match r {
        Ref::Local(index) => own(&model.proto_fields[*index].key),
        Ref::Slot(key) => Place::Slot(key),
    }
}

/// The Lua expression of a site table.
fn site_ref<'a>(model: &'a Dissector, r: &'a Ref) -> Place<'a> {
    match r {
        Ref::Local(index) => own(&model.sites[*index].key),
        Ref::Slot(key) => Place::Slot(key),
    }
}

/// The subtree of an inline structure or a Field of a Type, as the lines of a block: the
/// subtree item shadows `tree` and spans the rest of the packet until its Fields are read, so a
/// truncated one covers what is left of it. An array element's item also shows the element's
/// index, the Lua local `index` (spec §3.4.8).
fn subtree(w: &mut Writer, model: &Dissector, stmt: &Stmt, scope: Scope, index: Option<&str>) {
    let (Stmt::Structure { field, hidden, .. } | Stmt::Call { field, hidden, .. }) = stmt else {
        unreachable!("only structures and Fields of Types have a subtree")
    };
    w.line("local start = offset");
    open_subtree(w, model, field, *hidden);
    if let Some(index) = index {
        w.line(format_args!("tree:append_text(\" [\" .. {index} .. \"]\")"));
    }
    match stmt {
        Stmt::Structure { body, .. } => {
            for stmt in body {
                statement(w, model, stmt, scope);
            }
        }
        Stmt::Call { ty, site, context, result, .. } => call(w, model, ty, site, context, result.as_deref()),
        Stmt::Read { .. } | Stmt::Array { .. } | Stmt::If { .. } | Stmt::Switch { .. } | Stmt::Padding { .. } => {
            unreachable!("matched above")
        }
    }
    w.line("tree:set_len(offset - start)");
}

/// Adds the subtree item of `field`, which shadows `tree` and spans the rest of the packet until
/// its length is known, hiding it when `hidden` (spec §3.10): what it holds is hidden with it.
fn open_subtree(w: &mut Writer, model: &Dissector, field: &Ref, hidden: bool) {
    w.line(format_args!("local tree = tree:add({}, tvb(offset, tvb:len() - offset))", field_ref(model, field)));
    if hidden {
        w.line("tree:set_hidden(true)");
    }
}

/// Calls the dissect function of the Type `ty` into `tree`, passing the site table of this use
/// and the context table, and keeping the table it returns in `result` when the caller reads
/// inside it.
fn call(w: &mut Writer, model: &Dissector, ty: &str, site: &Ref, context: &[(String, LuaExpr)], result: Option<&str>) {
    let line = display_with(|f| {
        f.write_str("offset")?;
        if let Some(result) = result {
            write!(f, ", {}", kept(result))?;
        }
        write!(f, " = wd.dissect_{ty}(tvb, pinfo, tree, offset, {}", site_ref(model, site))?;
        if !context.is_empty() {
            f.write_str(", { ")?;
            join(f, context, ", ", |f, (key, value)| write!(f, "{} = {}", table_key(key), lua_expr(value)))?;
            f.write_str(" }")?;
        }
        f.write_str(")")
    });
    w.line(line);
    w.block("if not offset then", |w| w.line("return nil"), "end");
}

/// The fields of [`Stmt::Switch`] other than its path.
struct SwitchStmt<'s> {
    field: &'s Ref,
    hidden: bool,
    subject: &'s Computed,
    names: Option<usize>,
    info: bool,
    cases: &'s [(Vec<(i64, i64)>, Branch)],
    default: Option<&'s Branch>,
}

/// Writes a `switch` Field at `path` (spec §3.9): the subject is computed, then a subtree item
/// named after its value holds what the matching case reads. Without a match or a `default`, the
/// rest of the message is shown raw with a note, and the dissection stops: nothing says where
/// the unread layout ends.
fn switch(w: &mut Writer, model: &Dissector, path: &str, stmt: &SwitchStmt<'_>, scope: Scope) {
    let reported = reported_path(path, scope);
    let invalid = |w: &mut Writer, reason: &str| malformed(w, reported, reason);
    let branch = |w: &mut Writer, branch: &Branch| match branch {
        Branch::Fields(body) => body.iter().for_each(|stmt| statement(w, model, stmt, scope)),
        Branch::Call { ty, site, context } => call(w, model, ty, site, context, None),
    };
    w.line(format_args!("-- Switch: {path}"));
    w.block(
        "do",
        |w| {
            evaluate(w, "subject", "subject", stmt.subject, &invalid);
            w.line("local start = offset");
            open_subtree(w, model, stmt.field, stmt.hidden);
            let name = stmt.names.map_or_else(
                || "subject".to_owned(),
                |index| format!("wd_case_name({}, subject)", own(&model.names[index].key)),
            );
            if stmt.info {
                // The label of the subject's value is kept for the Info column, as text (spec §3.14).
                let name = if stmt.names.is_some() { name } else { format!("tostring({name})") };
                w.line(format_args!("local name = {name}"));
                w.line("tree:append_text(\": \" .. name)");
                w.line(format_args!("wd_info_cases[{reported}] = name"));
            } else {
                w.line(format_args!("tree:append_text(\": \" .. {name})"));
            }
            for (index, (ranges, body)) in stmt.cases.iter().enumerate() {
                let test = display_with(|f| {
                    join(f, ranges, " or ", |f, (low, high)| {
                        if low == high {
                            write!(f, "subject == {}", lua_integer(*low))
                        } else {
                            write!(f, "(subject >= {} and subject <= {})", lua_integer(*low), lua_integer(*high))
                        }
                    })
                });
                let keyword = if index == 0 { "if" } else { "elseif" };
                w.line(format_args!("{keyword} {test} then"));
                w.depth += 1;
                branch(w, body);
                w.depth -= 1;
            }
            w.block(
                "else",
                |w| {
                    if let Some(body) = stmt.default {
                        branch(w, body);
                    } else {
                        w.line(format_args!(
                            "wd_unmatched(tree, wd_f_unmatched, wd_ei_unmatched, tvb, offset, subject, {reported})"
                        ));
                        w.line("return nil");
                    }
                },
                "end",
            );
            w.line("tree:set_len(offset - start)");
        },
        "end",
    );
}

/// Evaluates a `size:` or `count:` Expression into the Lua local `local`, stopping the
/// dissection with `invalid` when it has no value or, when it is checked, is negative (spec
/// §4.4). `noun` names the value in that report.
fn evaluate(w: &mut Writer, local: &str, noun: &str, computed: &Computed, invalid: &dyn Fn(&mut Writer, &str)) {
    let Computed { value, checked, faults } = computed;
    if *faults {
        w.line(format_args!("local {local}, fault = wd_evaluate(function() return {} end)", lua_expr(value)));
        w.block(format_args!("if not {local} then"), |w| invalid(w, "fault"), "end");
    } else {
        w.line(format_args!("local {local} = {}", lua_expr(value)));
    }
    if *checked {
        let reason = format!("\"{noun} \" .. {local} .. \" is negative\"");
        w.block(format_args!("if {local} < 0 then"), |w| invalid(w, &reason), "end");
    }
}

/// The Lua expression of the value of a `size`-byte read at `offset`, read as `read` says.
fn read_value(read: &ValueRead, size: usize) -> impl Display + '_ {
    read_value_at(read, "offset", size)
}

/// The Lua expression of the value of a `size`-byte read at the Lua expression `at`.
fn read_value_at<'a>(read: &'a ValueRead, at: impl Display + 'a, size: usize) -> impl Display + 'a {
    display_with(move |f| match read {
        ValueRead::Integer(format) => write!(f, "string.unpack({}, tvb:raw({at}, {size}))", lua_string(format)),
        ValueRead::Bool => write!(f, "wd_bool(tvb({at}, {size}):uint() ~= 0)"),
    })
}

/// The line running `check` on `item_expr`, the Lua expression of the checked item (spec §3.10).
fn expect_line<'a>(item_expr: impl Display + 'a, check: &'a ExpectCheck, scope: Scope) -> impl Display + 'a {
    display_with(move |f| {
        let reported = reported_path(&check.path, scope);
        let bounds = check.ranges.iter().flat_map(|(l, h)| [lua_integer(*l), lua_integer(*h)]);
        let (value, text) = (lua_expr(&check.value), lua_string(&check.text));
        write!(f, "wd_expect({item_expr}, {value}, {{ ")?;
        join(f, bounds, ", ", |f, bound| write!(f, "{bound}"))?;
        write!(f, " }}, {text}, wd_ei_unexpected, {reported})")
    })
}

/// The Lua expression of the path a malformed-packet report names: inside a Type, the path of
/// the use extended by the path in the Type.
fn reported_path(path: &str, scope: Scope) -> impl Display + Copy + '_ {
    display_with(move |f| match scope {
        Scope::Top => write!(f, "{}", lua_string(path)),
        Scope::Type => {
            f.write_str("site.path .. \".")?;
            escape(f, path)?;
            f.write_char('"')
        }
    })
}

/// Writes the lines reporting a malformed packet for the Field whose path is `reported`, with
/// the Lua expression `reason`, and stopping.
fn malformed(w: &mut Writer, reported: impl Display, reason: &str) {
    w.line(format_args!("wd_invalid(tree, wd_ei_invalid, {reason}, {reported})"));
    w.line("return nil");
}

/// Writes `body`, the statement reading the Field at `path`, run only when `condition` is not
/// zero (spec §3.9). The condition's local is scoped by `do`, so locals never pile up against
/// Lua's limit of 200 per function.
fn conditional(w: &mut Writer, model: &Dissector, path: &str, condition: &Computed, body: &Stmt, scope: Scope) {
    let reported = reported_path(path, scope);
    let invalid = |w: &mut Writer, reason: &str| malformed(w, reported, reason);
    w.line(format_args!("-- If: {path}"));
    w.block(
        "do",
        |w| {
            evaluate(w, "condition", "condition", condition, &invalid);
            w.block("if condition ~= 0 then", |w| statement(w, model, body, scope), "end");
        },
        "end",
    );
}

/// Writes the array at `path`, repeating `element` (spec §3.7). Each element is its own subtree
/// item; one that reads no bytes would repeat forever under `repeat: to_end`, so it stops the
/// array as malformed.
fn array(w: &mut Writer, model: &Dissector, path: &str, repeat: &Repeat, element: &Stmt, scope: Scope) {
    let reported = reported_path(path, scope);
    let invalid = |w: &mut Writer, reason: &str| malformed(w, reported, reason);
    let read_element = |w: &mut Writer| {
        subtree(w, model, element, scope, Some("i"));
        w.block(
            "if offset == start then",
            |w| {
                w.line(format_args!("wd_empty(tree, wd_ei_empty, i, {reported})"));
                w.line("return nil");
            },
            "end",
        );
    };
    w.line(format_args!("-- Field: {path}"));
    w.block(
        "do",
        |w| match repeat {
            Repeat::Count(count) => {
                evaluate(w, "count", "count", count, &invalid);
                w.block("for i = 0, count - 1 do", read_element, "end");
            }
            Repeat::ToEnd => {
                w.line("local i = 0");
                w.block(
                    "while offset < tvb:len() do",
                    |w| {
                        read_element(w);
                        w.line("i = i + 1");
                    },
                    "end",
                );
            }
        },
        "end",
    );
}

/// Writes a padding in the structure at `parent` (spec §3.10): the bytes are skipped and shown
/// as one text item, "Padding", which has no `ProtoField` and so no filter name. Having no path
/// of its own, it is reported as the padding of its structure.
fn padding(w: &mut Writer, parent: &str, length: &Length, scope: Scope) {
    let label = if parent.is_empty() { "Padding".to_owned() } else { format!("Padding in {parent}") };
    let reported = match scope {
        Scope::Top => lua_string(&label).to_string(),
        Scope::Type if parent.is_empty() => "\"Padding in \" .. site.path".to_owned(),
        Scope::Type => format!("\"Padding in \" .. {}", reported_path(parent, scope)),
    };
    let reported = reported.as_str();
    let truncated = |w: &mut Writer| {
        w.line(format_args!("wd_truncated(tree, wd_ei_truncated, {reported})"));
        w.line("return nil");
    };
    let invalid = |w: &mut Writer, reason: &str| malformed(w, reported, reason);
    w.line(format_args!("-- {label}"));
    match length {
        Length::Fixed(size) => {
            w.block(format_args!("if not wd_fits(tvb, offset, {size}) then"), truncated, "end");
            w.line(format_args!("tree:add(tvb(offset, {size}), \"Padding\")"));
            w.line(format_args!("offset = offset + {size}"));
        }
        Length::Expression(size) => w.block(
            "do",
            |w| {
                evaluate(w, "len", "padding", size, &invalid);
                w.block("if not wd_fits(tvb, offset, len) then", truncated, "end");
                w.line("tree:add(tvb(offset, len), \"Padding\")");
                w.line("offset = offset + len");
            },
            "end",
        ),
        Length::Prefix { .. } | Length::Terminator { .. } => unreachable!("padding is a number of bytes"),
    }
}

/// Writes `stmt`. A statement holding statements, [`NESTING`] such statements deep in the
/// current Lua function, is a part: a function of its own, which starts again from no locals
/// and no nesting. It takes what the dissect function it is part of takes, and its values
/// table, and returns the offset after what it read, or `nil` once it stopped the dissection.
/// No statement reads a local of the statements around it, so it needs nothing else.
fn statement(w: &mut Writer, model: &Dissector, stmt: &Stmt, scope: Scope) {
    if !stmt.nests() {
        return plain_statement(w, model, stmt, scope);
    }
    if w.nesting < NESTING {
        w.nesting += 1;
        plain_statement(w, model, stmt, scope);
        w.nesting -= 1;
        return;
    }
    w.part_count += 1;
    let key = format!("part_{}", w.part_count);
    let args = w.frame.args();
    let comment = format!("-- Part of {}, nested too deep to stay in it", w.frame.key);
    let part = w.detached(|w| {
        w.line(comment);
        w.block(
            format_args!("function wd.{key}({args})"),
            |w| {
                w.nesting = 1;
                plain_statement(w, model, stmt, scope);
                w.line("return offset");
            },
            "end",
        );
        w.line("");
    });
    w.parts.push_str(&part);
    w.line(format_args!("offset = wd.{key}({args})"));
    w.block("if not offset then", |w| w.line("return nil"), "end");
}

/// Writes `stmt` in the current Lua function.
fn plain_statement(w: &mut Writer, model: &Dissector, stmt: &Stmt, scope: Scope) {
    match stmt {
        Stmt::Padding { parent, length } => padding(w, parent, length, scope),
        Stmt::If { path, condition, body } => conditional(w, model, path, condition, body, scope),
        Stmt::Switch { field, path, hidden, subject, names, info, cases, default } => {
            let (hidden, names, info, default) = (*hidden, *names, *info, default.as_ref());
            switch(w, model, path, &SwitchStmt { field, hidden, subject, names, info, cases, default }, scope);
        }
        Stmt::Structure { path, .. } | Stmt::Call { path, .. } => {
            w.line(format_args!("-- Field: {path}"));
            w.block("do", |w| subtree(w, model, stmt, scope, None), "end");
        }
        Stmt::Array { path, repeat, element } => array(w, model, path, repeat, element, scope),
        Stmt::Read { field, length, decode, path, value, hidden, bits, check_read, expect, handoff } => {
            let local = field_ref(model, field);
            let reported = reported_path(path, scope);
            let truncated = |w: &mut Writer| {
                w.line(format_args!("wd_truncated(tree, wd_ei_truncated, {reported})"));
                w.line("return nil");
            };
            let invalid = |w: &mut Writer, reason: &str| malformed(w, reported, reason);
            // Only a fixed-size read can be a bitfield, whose item `add_item` keeps.
            let add_line = |w: &mut Writer, range: &str| {
                w.line(format_args!("{}{}", add_call(decode, local, &range), hide(*hidden)));
            };
            // The handed-off dissector's layer follows the item, in the same structure, whether
            // the item is hidden or not (spec §3.10).
            let handoff_line = |w: &mut Writer, range: &dyn Display| {
                if let Some(name) = handoff {
                    let name = lua_string(name);
                    w.line(format_args!("wd_handoff({name}, {range}, pinfo, tree, wd_ei_dissector, {reported})"));
                }
            };
            w.line(format_args!("-- Field: {path}"));
            // A variable length goes in a `len` local, scoped by `do` so locals never pile up
            // against Lua's limit of 200 per function.
            match length {
                Length::Fixed(size) => {
                    w.block(format_args!("if not wd_fits(tvb, offset, {size}) then"), truncated, "end");
                    let range = display_with(|f| write!(f, "tvb(offset, {size})"));
                    let check_read = check_read.as_ref().map(|read| read_value(read, *size));
                    let item = Item {
                        add: &add_call(decode, local, &range),
                        range: &range,
                        hidden: *hidden,
                        bits,
                        check_read: check_read.as_ref().map(|read| read as &dyn Display),
                        expect: expect.as_ref(),
                    };
                    add_item(w, model, &item, scope);
                    handoff_line(w, &range);
                    if let Some(value) = value {
                        w.line(format_args!("{} = {}", kept(&value.key), read_value(&value.read, *size)));
                    }
                    w.line(format_args!("offset = offset + {size}"));
                }
                Length::Expression(size) => w.block(
                    "do",
                    |w| {
                        evaluate(w, "len", "size", size, &invalid);
                        w.block("if not wd_fits(tvb, offset, len) then", truncated, "end");
                        add_line(w, "tvb(offset, len)");
                        handoff_line(w, &"tvb(offset, len)");
                        w.line("offset = offset + len");
                    },
                    "end",
                ),
                Length::Prefix { size, read } => w.block(
                    "do",
                    |w| {
                        w.block(format_args!("if not wd_fits(tvb, offset, {size}) then"), truncated, "end");
                        w.line(format_args!("local len = tvb(offset, {size}):{read}"));
                        w.line(format_args!("offset = offset + {size}"));
                        w.block("if not wd_fits(tvb, offset, len) then", truncated, "end");
                        add_line(w, "tvb(offset, len)");
                        handoff_line(w, &"tvb(offset, len)");
                        w.line("offset = offset + len");
                    },
                    "end",
                ),
                Length::Terminator { terminator, width } => w.block(
                    "do",
                    |w| {
                        w.line(format_args!("local len = wd_terminated(tvb, offset, {terminator}, {width})"));
                        w.block("if not len then", truncated, "end");
                        add_line(w, "tvb(offset, len)");
                        handoff_line(w, &"tvb(offset, len)");
                        w.line(format_args!("offset = offset + len + {width}"));
                    },
                    "end",
                ),
            }
        }
    }
}

/// The call adding the item of `local`, read from the `TvbRange` `range` as `decode` says.
fn add_call<'a>(decode: &'a Decode, local: Place<'a>, range: &'a dyn Display) -> impl Display + 'a {
    display_with(move |f| match decode {
        Decode::Big => write!(f, "tree:add({local}, {range})"),
        Decode::Little => write!(f, "tree:add_le({local}, {range})"),
        Decode::Encoded { encoding, endian: None } => write!(f, "tree:add_packet_field({local}, {range}, {encoding})"),
        Decode::Encoded { encoding, endian: Some(e) } => {
            write!(f, "tree:add_packet_field({local}, {range}, {encoding} + {e})")
        }
        Decode::Lua(method) => write!(f, "tree:add({local}, {range}, {range}:{method}())"),
    })
}

/// The item of a fixed-size read.
struct Item<'s> {
    /// The call adding it.
    add: &'s dyn Display,
    /// The `TvbRange` it is added from.
    range: &'s dyn Display,
    hidden: bool,
    /// The sub-Fields of a bitfield, added from the same range.
    bits: &'s [BitItem],
    /// When the Field or a sub-Field has `expect:`, the Lua expression of the value they check,
    /// kept in the local `value` (spec §3.10).
    check_read: Option<&'s dyn Display>,
    /// The check of the Field's own `expect:`.
    expect: Option<&'s ExpectCheck>,
}

/// Adds `item`, the item of a Field read in `scope`. A bitfield's sub-Fields go under it, each
/// from the same bytes, which Wireshark masks and shifts (spec §3.8), and the `expect:` checks
/// read the value into the local `value` (§3.10). The item and the value are then kept in locals scoped by `do`, so locals never pile up against
/// Lua's limit of 200 per function.
fn add_item(w: &mut Writer, model: &Dissector, item: &Item<'_>, scope: Scope) {
    if item.bits.is_empty() && item.check_read.is_none() {
        w.line(format_args!("{}{}", item.add, hide(item.hidden)));
        return;
    }
    w.block(
        "do",
        |w| {
            w.line(format_args!("local item = {}", item.add));
            if item.hidden {
                w.line("item:set_hidden(true)");
            }
            if let Some(read) = item.check_read {
                w.line(format_args!("local value = {read}"));
            }
            if let Some(check) = item.expect {
                w.line(expect_line("item", check, scope));
            }
            for bit in item.bits {
                let method = if bit.little { "add_le" } else { "add" };
                let add = display_with(|f| {
                    write!(f, "item:{method}({}, {}){}", field_ref(model, &bit.field), item.range, hide(bit.hidden))
                });
                match &bit.expect {
                    Some(check) => w.line(expect_line(add, check, scope)),
                    None => w.line(add),
                }
            }
        },
        "end",
    );
}

/// What follows a call adding an item to hide it, when `hidden` (spec §3.10).
const fn hide(hidden: bool) -> &'static str {
    if hidden { ":set_hidden(true)" } else { "" }
}

/// The prelude helper computing a unary operator (ADR 0007).
const fn unary_helper(op: UnaryOp) -> &'static str {
    match op {
        UnaryOp::Not => "wd_not",
        UnaryOp::Complement => "wd_bnot",
        UnaryOp::Negate => "wd_neg",
    }
}

/// The prelude helper computing a binary operator (ADR 0007), `None` for `&&` and `||`, which
/// are Lua's own short-circuiting `and` and `or`.
const fn binary_helper(op: BinaryOp) -> Option<&'static str> {
    Some(match op {
        BinaryOp::Mul => "wd_mul",
        BinaryOp::Add => "wd_add",
        BinaryOp::Sub => "wd_sub",
        BinaryOp::Div => "wd_div",
        BinaryOp::Rem => "wd_mod",
        BinaryOp::Shl => "wd_shl",
        BinaryOp::Shr => "wd_shr",
        BinaryOp::BitAnd => "wd_band",
        BinaryOp::BitXor => "wd_bxor",
        BinaryOp::BitOr => "wd_bor",
        BinaryOp::Eq => "wd_eq",
        BinaryOp::Ne => "wd_ne",
        BinaryOp::Lt => "wd_lt",
        BinaryOp::Le => "wd_le",
        BinaryOp::Gt => "wd_gt",
        BinaryOp::Ge => "wd_ge",
        BinaryOp::And | BinaryOp::Or => return None,
    })
}

/// A Lua integer literal for an Expression. A decimal literal above `i64::MAX` would be a
/// float; a hexadecimal one wraps.
fn expr_integer(value: u64) -> impl Display {
    display_with(move |f| if i64::try_from(value).is_ok() { write!(f, "{value}") } else { write!(f, "0x{value:X}") })
}

/// An Expression as Lua: helper calls, and Lua's short-circuit `and`/`or` for `&&`/`||`, turned
/// into 1 or 0 by `wd_bool`.
const fn lua_expr(expr: &LuaExpr) -> Lua<'_> {
    Lua(expr)
}

/// What [`lua_expr`] writes.
struct Lua<'a>(&'a LuaExpr);

impl Display for Lua<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            LuaExpr::Int(value) => write!(f, "{}", expr_integer(*value)),
            LuaExpr::Unary { op, operand } => write!(f, "{}({})", unary_helper(*op), lua_expr(operand)),
            LuaExpr::Binary { op, left, right } => {
                let (left, right) = (lua_expr(left), lua_expr(right));
                match (op, binary_helper(*op)) {
                    (_, Some(helper)) => write!(f, "{helper}({left}, {right})"),
                    (BinaryOp::And, None) => write!(f, "wd_bool({left} ~= 0 and {right} ~= 0)"),
                    (_, None) => write!(f, "wd_bool({left} ~= 0 or {right} ~= 0)"),
                }
            }
            LuaExpr::SubField { value, shift, width } => {
                let masked = *width < 64;
                if masked {
                    f.write_str("wd_band(")?;
                }
                if *shift > 0 {
                    write!(f, "wd_shr({}, {shift})", lua_expr(value))?;
                } else {
                    write!(f, "{}", lua_expr(value))?;
                }
                if masked {
                    write!(f, ", {})", expr_integer((1_u64 << width) - 1))?;
                }
                Ok(())
            }
            LuaExpr::Value { key, keys } => {
                write!(f, "{}", kept(key))?;
                keys.iter().try_for_each(|k| write!(f, "{}", index(k)))
            }
            LuaExpr::Checked => f.write_str("value"),
            LuaExpr::Context(key) => write!(f, "ctx{}", index(key)),
            LuaExpr::Offset => f.write_str("offset"),
            LuaExpr::Remaining => f.write_str("tvb:len() - offset"),
        }
    }
}

/// A Lua string literal. Control characters become decimal escapes, so one literal is one line.
const fn lua_string(text: &str) -> LuaString<'_> {
    LuaString(text)
}

/// What [`lua_string`] writes.
#[derive(Clone, Copy)]
struct LuaString<'a>(&'a str);

impl Display for LuaString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('"')?;
        escape(f, self.0)?;
        f.write_char('"')
    }
}

/// Writes `text` as the inside of a Lua string literal.
fn escape(f: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
    let mut rest = text;
    // Every character escaped is ASCII, one byte long.
    while let Some(at) = rest.find(|c: char| matches!(c, '"' | '\\') || c.is_ascii_control()) {
        f.write_str(&rest[..at])?;
        match rest.as_bytes()[at] {
            b'"' => f.write_str("\\\"")?,
            b'\\' => f.write_str("\\\\")?,
            control => write!(f, "\\{control:03}")?,
        }
        rest = &rest[at + 1..];
    }
    f.write_str(rest)
}

/// Text for a one-line comment: anything that could end the line is replaced.
fn comment_text(text: &str) -> impl Display + '_ {
    display_with(move |f| {
        text.chars().try_for_each(|c| {
            f.write_char(if c.is_control() || matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}') { '?' } else { c })
        })
    })
}

#[cfg(test)]
mod tests {
    use proptest::test_runner::TestCaseError;

    use super::*;

    #[test]
    fn strings_are_escaped_onto_one_line() {
        assert_eq!(lua_string("a\"b\\c\nd").to_string(), "\"a\\\"b\\\\c\\010d\"");
        assert_eq!(lua_string("é").to_string(), "\"é\"");
    }

    #[test]
    fn comments_cannot_span_lines() {
        assert_eq!(comment_text("a\nb\rc").to_string(), "a?b?c");
    }

    /// Each `wd_` name `lua` uses is defined by a chunk it includes, or is one of the emitter's
    /// own names and declared at the top level of `lua`.
    fn assert_closed(name: &str, lua: &str) -> Result<(), String> {
        let defined = Chunks::named(&prelude::chunks_in(lua)).defined();
        let declared: Vec<&str> =
            lua.lines().flat_map(prelude::definitions).filter(|name| DECLARED.contains(name)).collect();
        let undefined: Vec<&str> = prelude::names_used(lua)
            .into_iter()
            .filter(|used| !defined.contains(used) && !declared.contains(used))
            .collect();
        if undefined.is_empty() { Ok(()) } else { Err(format!("{name} uses undefined {undefined:?}")) }
    }

    /// ADR 0010: a Dissector holds the definition of every helper it calls.
    #[test]
    fn every_golden_defines_the_names_it_uses() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases");
        let mut cases = 0;
        for entry in std::fs::read_dir(root).unwrap() {
            let dir = entry.unwrap().path();
            let case = dir.file_name().unwrap().to_str().unwrap().to_owned();
            let name = format!("{case}.wirdigen.yaml");
            let source = crate::Source::new(&name, std::fs::read_to_string(dir.join(&name)).unwrap());
            let lua = crate::validate(&source).unwrap_or_else(|d| panic!("{case}: {d}")).generate();
            assert_closed(&case, &lua).unwrap();
            cases += 1;
        }
        assert!(cases > 0, "the corpus is found");
    }

    /// ADR 0010: the Dissector of a random valid description holds the definition of every
    /// helper it calls.
    #[test]
    fn every_random_dissector_defines_the_names_it_uses() {
        crate::random::check(|text| {
            let source = crate::Source::new("random.wirdigen.yaml", text);
            let lua = crate::validate(&source).map_err(|d| TestCaseError::fail(d.to_string()))?.generate();
            assert_closed("random.lua", &lua).map_err(TestCaseError::fail)
        });
    }

    /// Each operator is printed as its prelude helper, `&&` and `||` short-circuiting.
    #[test]
    fn operators_are_printed_as_helper_calls() {
        let int = |value| Box::new(LuaExpr::Int(value));
        let binary = |op, left, right| LuaExpr::Binary { op, left, right };
        let expr = binary(
            BinaryOp::Or,
            Box::new(binary(
                BinaryOp::Rem,
                int(7),
                Box::new(LuaExpr::Unary { op: UnaryOp::Complement, operand: int(1) }),
            )),
            Box::new(LuaExpr::SubField { value: int(u64::MAX), shift: 4, width: 3 }),
        );
        assert_eq!(
            lua_expr(&expr).to_string(),
            "wd_bool(wd_mod(7, wd_bnot(1)) ~= 0 or wd_band(wd_shr(0xFFFFFFFFFFFFFFFF, 4), 7) ~= 0)"
        );
        let whole = LuaExpr::SubField { value: int(1), shift: 0, width: 64 };
        assert_eq!(lua_expr(&whole).to_string(), "1");
    }
}
