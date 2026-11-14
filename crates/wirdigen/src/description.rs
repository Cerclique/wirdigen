//! Stage 2 (strict deserialization of the top level) and the first semantic checks.

use std::collections::BTreeMap;

use crate::builtin;
use crate::depth;
use crate::diagnostic::{Diagnostic, Name, Severity, record};
use crate::expr::Expr;
use crate::field::{self, Endian, Entry, Parse, RawEntry};
use crate::filter;
use crate::framing::{self, Framing, RawFraming};
use crate::info::{self, RawInfo, Template};
use crate::keys::{Spanned, expect_string, is_single_line, read_keys, wrong_type};
use crate::mapping::{self, Enums, RawEnum, Table};
use crate::registration::{self, Ports, RawRegistration};
use crate::types::{self, NamedTypes, RawType};
use crate::yaml::{Node, Value};

/// The shortest protocol name Wireshark registers: it refuses one-character filter names
/// (spec §3.3, ADR 0014).
pub(crate) const MIN_NAME_LEN: usize = 2;
/// The longest protocol name Wireshark filters accept here (spec §3.3, ADR 0014).
pub(crate) const MAX_NAME_LEN: usize = 32;

/// The ten top-level keys, in documentation order (spec §3.2).
pub(crate) const KEYS: [&str; 10] =
    ["name", "title", "registration", "framing", "endian", "info", "fields", "types", "enums", "allow"];

/// The top level of a Protocol Description, as written.
#[derive(Debug, Clone)]
pub(crate) struct Description<E = Expr> {
    pub(crate) name: Spanned<String>,
    pub(crate) title: Option<Spanned<String>>,
    /// The ports of `registration:`, none when it is left out.
    pub(crate) registration: RawRegistration,
    /// The `framing:` of TCP Messages, when written (spec §3.13).
    pub(crate) framing: Option<RawFraming<E>>,
    pub(crate) endian: Option<Spanned<String>>,
    /// The `info:` template, when written (spec §3.14).
    pub(crate) info: Option<RawInfo>,
    /// The top-level Fields, in order.
    pub(crate) fields: Vec<RawEntry<E>>,
    /// The Types of `types:`, in order.
    pub(crate) types: Vec<RawType<E>>,
    /// The Enums of `enums:`, in order.
    pub(crate) enums: Vec<RawEnum>,
    /// The `allow:` entries, as written.
    pub(crate) allow: Vec<Spanned<String>>,
}

impl Description<Parse> {
    /// Stage 3: the description with every Expression parsed, in the top-level layout, in the
    /// Types and in `framing:`, and its `info:` template checked; else every syntax error.
    pub(crate) fn parsed(self) -> Result<Description, Vec<Diagnostic>> {
        let mut errors: Vec<Diagnostic> = self.info.iter().filter_map(RawInfo::syntax_error).cloned().collect();
        let framing = self.framing.and_then(|framing| framing.parsed(&mut errors));
        let fields = field::parsed(self.fields, &mut errors);
        let types = self.types.into_iter().map(|ty| ty.parsed(&mut errors)).collect();
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(Description {
            name: self.name,
            title: self.title,
            registration: self.registration,
            framing,
            endian: self.endian,
            info: self.info,
            fields,
            types,
            enums: self.enums,
            allow: self.allow,
        })
    }
}

impl Description {
    /// Whether `allow:` silences this Diagnostic. Errors are never silenced (spec §6.4).
    pub(crate) fn allows(&self, diagnostic: &Diagnostic) -> bool {
        diagnostic.severity() == Severity::Warning && self.allow.iter().any(|a| a.value == diagnostic.name())
    }
}

/// A Protocol Description that passed every check: what lowering reads.
#[derive(Debug, Clone)]
pub(crate) struct Protocol {
    pub(crate) name: String,
    pub(crate) title: Option<String>,
    /// The ports the Dissector registers on by default, per transport.
    pub(crate) ports: Vec<Ports>,
    pub(crate) fields: Vec<Entry>,
    pub(crate) types: NamedTypes,
    /// The tables of the Enums, by name.
    pub(crate) enums: BTreeMap<String, Table>,
    /// The `info:` template, when written; without one, the Info column shows the outermost
    /// `switch` Field's case (spec §3.14).
    pub(crate) info: Option<Template>,
    /// How TCP Messages are found, when `framing:` is written (spec §3.13).
    pub(crate) framing: Option<Framing>,
}

/// Stage 2: unknown and duplicate keys, required keys and value kinds.
pub(crate) fn deserialize(root: Option<&Node>) -> Result<Description<Parse>, Vec<Diagnostic>> {
    let Some(root) = root else {
        return Err(vec![Diagnostic::new(
            Name::MissingKey,
            0..0,
            "the description is empty: `name` and `fields` are required",
        )]);
    };
    let Value::Mapping(entries) = &root.value else {
        return Err(vec![wrong_type(
            root.span.clone(),
            "a Protocol Description is a mapping with at least `name` and `fields`",
        )]);
    };

    let mut errors = Vec::new();
    let keys = read_keys(entries, &KEYS, &mut errors);
    for required in ["name", "fields"] {
        if keys.get(required).is_none() && !keys.misspelt(required) {
            errors.push(Diagnostic::new(
                Name::MissingKey,
                root.span.clone(),
                format!("missing required key `{required}`"),
            ));
        }
    }

    let mut string_value =
        |key: &str, invalid: Name| keys.get(key).and_then(|n| record(expect_string(n, key, invalid), &mut errors));
    let name = string_value("name", Name::InvalidProtocolName);
    let title = string_value("title", Name::InvalidProtocolTitle);
    let endian = string_value("endian", Name::InvalidEndian);
    let info = keys.get("info").and_then(|node| info::read(node, &mut errors));
    let registration =
        keys.get("registration").map_or_else(RawRegistration::default, |node| registration::read(node, &mut errors));
    let framing = keys.get("framing").and_then(|node| framing::read(node, &mut errors));
    let layout = keys.get("fields").and_then(|fields| field::read_structure(fields, &mut errors)).unwrap_or_default();

    let types = keys.get("types").map_or_else(Vec::new, |node| types::read(node, &mut errors));
    let enums = keys.get("enums").map_or_else(Vec::new, |node| mapping::read_enums(node, &mut errors));
    let allow = keys.get("allow").map_or_else(Vec::new, |node| read_allow(node, &mut errors));

    match name {
        Some(name) if errors.is_empty() => {
            Ok(Description { name, title, registration, framing, endian, info, fields: layout, types, enums, allow })
        }
        _ => Err(errors),
    }
}

/// Reads `allow:`, a list of strings. Whether each names a warning is a semantic check.
fn read_allow(node: &Node, errors: &mut Vec<Diagnostic>) -> Vec<Spanned<String>> {
    let Value::Sequence(items) = &node.value else {
        errors.push(wrong_type(node.span.clone(), "`allow` must be a list of warning names"));
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| record(expect_string(item, "an `allow` entry", Name::WrongValueType), errors))
        .collect()
}

/// Stage 4: semantic checks on a deserialized description.
///
/// Returns every Diagnostic, and the checked [`Protocol`] when none of them is an error.
pub(crate) fn check(description: &Description) -> (Option<Protocol>, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let name = &description.name;
    if !is_protocol_name(&name.value) {
        diagnostics.push(
            Diagnostic::new(
                Name::InvalidProtocolName,
                name.span.clone(),
                format!("`{}` is not a valid protocol name", name.value),
            )
            .with_note(
                format!(
                    "a name is a lowercase letter then lowercase letters, digits, `_` or `-`, \
                     {MIN_NAME_LEN} to {MAX_NAME_LEN} characters"
                ),
                None,
            ),
        );
    }
    if let Some(title) = &description.title {
        if title.value.trim().is_empty() || !is_single_line(&title.value) {
            diagnostics.push(Diagnostic::new(
                Name::InvalidProtocolTitle,
                title.span.clone(),
                "a title must be a non-empty single line",
            ));
        }
    }
    // Only a well-formed name and title are compared with Wireshark's: the Diagnostics so far
    // are their errors.
    if diagnostics.is_empty() {
        builtin::check(name, description.title.as_ref(), &mut diagnostics);
    }
    for entry in &description.allow {
        let message = match Name::from_token(&entry.value) {
            Some(name) if name.severity() == Severity::Warning => continue,
            Some(_) => format!("`{}` is an error, and errors cannot be silenced", entry.value),
            None => format!("there is no warning named `{}`", entry.value),
        };
        diagnostics.push(Diagnostic::new(Name::UnknownAllow, entry.span.clone(), message));
    }
    let ports = registration::check(&description.registration, description.framing.is_some(), &mut diagnostics);
    let endian = Endian::resolve(description.endian.as_ref(), Endian::default(), &mut diagnostics);
    let mut enums = Enums::check(&description.enums, &mut diagnostics);
    let (fields, types) = types::check(&description.types, &description.fields, endian, &mut enums, &mut diagnostics);
    // Depth is counted through every use of a Type, which needs Types without cycles. A Field
    // too deep stops the checks below, which recurse once per level (ADR 0020).
    if !diagnostics.iter().any(|d| d.name() == Name::RecursiveType.as_str()) {
        depth::check(&name.value, &fields, &types, &mut diagnostics);
    }
    let enums = enums.finish(&mut diagnostics);
    // Filter names are walked through every use of every Type, which needs Types without cycles.
    // The `info:` template is resolved in the checked layout too, where no Field is in error.
    let mut info = None;
    let mut framing = None;
    if !diagnostics.iter().any(|d| d.severity() == Severity::Error) {
        filter::check(&fields, &types, &mut diagnostics);
        info = description.info.as_ref().and_then(|raw| info::check(raw, &fields, &types, &mut diagnostics));
        framing = description.framing.as_ref().and_then(|raw| framing::check(raw, &fields, &types, &mut diagnostics));
    }
    let has_errors = diagnostics.iter().any(|d| d.severity() == Severity::Error);
    let protocol = (!has_errors).then(|| Protocol {
        name: description.name.value.clone(),
        title: description.title.as_ref().map(|t| t.value.clone()),
        ports,
        fields,
        types,
        enums,
        info,
        framing,
    });
    (protocol, diagnostics)
}

fn is_protocol_name(name: &str) -> bool {
    let mut chars = name.chars();
    (MIN_NAME_LEN..=MAX_NAME_LEN).contains(&name.len())
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

#[cfg(test)]
impl Description {
    /// Records everything the description uses.
    pub(crate) fn cover(&self, coverage: &mut crate::coverage::Coverage<'_>) {
        self.registration.cover(coverage);
        if let Some(framing) = &self.framing {
            framing.cover(coverage);
        }
        if let Some(endian) = &self.endian {
            field::cover_endian(endian, coverage);
        }
        if let Some(info) = &self.info {
            info.cover(coverage);
        }
        self.fields.iter().for_each(|entry| entry.cover(coverage));
        self.types.iter().for_each(|ty| ty.cover(coverage));
    }
}
