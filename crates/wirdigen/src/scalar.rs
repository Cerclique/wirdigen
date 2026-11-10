//! YAML 1.2 core-schema resolution of plain scalars.
//!
//! Only `true` and `false` are booleans, so `no` and `on` stay strings.

/// What a plain scalar resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Null,
    Bool,
    Int,
    Float,
    Str,
}

pub(crate) fn resolve_plain(s: &str) -> Kind {
    match s {
        "" | "~" | "null" | "Null" | "NULL" => Kind::Null,
        "true" | "True" | "TRUE" | "false" | "False" | "FALSE" => Kind::Bool,
        ".nan" | ".NaN" | ".NAN" => Kind::Float,
        _ if is_int(s) => Kind::Int,
        _ if is_float(s) => Kind::Float,
        _ => Kind::Str,
    }
}

/// The value of an integer literal as YAML's core schema spells it (`12`, `-4`, `0x1F`, `0o17`),
/// or `None` for anything else or a value beyond `i128`.
pub(crate) fn parse_int(s: &str) -> Option<i128> {
    if !is_int(s) {
        return None;
    }
    let (negative, body) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (digits, radix) = if let Some(hex) = body.strip_prefix("0x") {
        (hex, 16)
    } else if let Some(oct) = body.strip_prefix("0o") {
        (oct, 8)
    } else {
        (body, 10)
    };
    let magnitude = i128::from_str_radix(digits, radix).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

fn is_int(s: &str) -> bool {
    if let Some(hex) = s.strip_prefix("0x") {
        return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    if let Some(oct) = s.strip_prefix("0o") {
        return !oct.is_empty() && oct.bytes().all(|b| (b'0'..=b'7').contains(&b));
    }
    let digits = s.strip_prefix(['-', '+']).unwrap_or(s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

fn is_float(s: &str) -> bool {
    let body = s.strip_prefix(['-', '+']).unwrap_or(s);
    if matches!(body, ".inf" | ".Inf" | ".INF") {
        return true;
    }
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };
    if let Some(exp) = exponent {
        let digits = exp.strip_prefix(['-', '+']).unwrap_or(exp);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    let (int, frac) = match mantissa.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (mantissa, None),
    };
    let all_digits = |t: &str| t.bytes().all(|b| b.is_ascii_digit());
    if !all_digits(int) {
        return false;
    }
    match frac {
        // `1.5`, `1.` and `.5` are floats, a lone `.` is not.
        Some(f) => all_digits(f) && !(int.is_empty() && f.is_empty()),
        // Without a dot an exponent is required (`1e3`), else it would be an int.
        None => !int.is_empty() && exponent.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_core_schema_scalars() {
        for (text, kind) in [
            ("", Kind::Null),
            ("null", Kind::Null),
            ("true", Kind::Bool),
            ("False", Kind::Bool),
            ("no", Kind::Str),
            ("on", Kind::Str),
            ("yes", Kind::Str),
            ("12", Kind::Int),
            ("-3", Kind::Int),
            ("0x1F", Kind::Int),
            ("0o17", Kind::Int),
            ("1.5", Kind::Float),
            (".5", Kind::Float),
            ("1e3", Kind::Float),
            ("-.inf", Kind::Float),
            (".nan", Kind::Float),
            (".", Kind::Str),
            ("1.2.3", Kind::Str),
            ("0x", Kind::Str),
            ("demo", Kind::Str),
        ] {
            assert_eq!(resolve_plain(text), kind, "{text:?}");
        }
    }

    #[test]
    fn parses_integer_literals() {
        assert_eq!(parse_int("12"), Some(12));
        assert_eq!(parse_int("+7"), Some(7));
        assert_eq!(parse_int("-4"), Some(-4));
        assert_eq!(parse_int("0x1F"), Some(31));
        assert_eq!(parse_int("0o17"), Some(15));
        assert_eq!(parse_int("18446744073709551615"), Some(18_446_744_073_709_551_615));
        assert_eq!(parse_int("1.5"), None);
        assert_eq!(parse_int("abc"), None);
        assert_eq!(parse_int(""), None);
    }
}
