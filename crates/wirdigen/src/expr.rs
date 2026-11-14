//! Expressions (spec §4, ADR 0007): parsing the mini-language of `size:` and the other
//! Expression keys, and evaluating constant Expressions with C's integer semantics.
//!
//! Parsing is stage 3 of validation (spec §6.1). It reports the first syntax error of an
//! Expression with a span on the offending token; resolving references is a semantic check.

use std::fmt;
use std::ops::Range;

use crate::diagnostic::{Diagnostic, Name};
use crate::yaml::Node;

/// A parsed Expression. Spans are byte offsets: into the Expression's text after
/// [`parse_text`], into the source after [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expr {
    pub(crate) kind: ExprKind,
    /// The whole sub-Expression, parentheses excluded.
    pub(crate) span: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// What an Expression node is.
pub(crate) enum ExprKind {
    /// An integer literal. Literals above `i64::MAX` wrap to negative values (spec §4.4).
    Int(u64),
    /// A Field Path, by its dotted segments (`hdr.len`).
    Path(Vec<String>),
    Builtin(Builtin),
    /// A unary operator; its span is the operator token's.
    Unary {
        op: Spanned<UnaryOp>,
        operand: Box<Expr>,
    },
    /// A binary operator; its span is the operator token's.
    Binary {
        op: Spanned<BinaryOp>,
        left: Box<Expr>,
        right: Box<Expr>,
    },
}

/// A value with its span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Spanned<T> {
    pub(crate) value: T,
    pub(crate) span: Range<usize>,
}

/// A built-in (spec §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Builtin {
    /// `_offset`: bytes from the start of the message.
    Offset,
    /// `_remaining`: bytes left in the innermost structure with a known size, or the message.
    Remaining,
}

impl Builtin {
    /// Every built-in, for the note of an unknown one and for tests.
    pub(crate) const ALL: [Self; 2] = [Self::Offset, Self::Remaining];

    /// The name as written, `_` included.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Offset => "_offset",
            Self::Remaining => "_remaining",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A unary operator (spec §4.2).
pub(crate) enum UnaryOp {
    /// `!`: 1 for zero, else 0.
    Not,
    /// `~`: bitwise complement.
    Complement,
    /// `-`: negation, wrapping.
    Negate,
}

impl UnaryOp {
    /// The operator as written.
    pub(crate) const fn symbol(self) -> &'static str {
        match self {
            Self::Not => "!",
            Self::Complement => "~",
            Self::Negate => "-",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A binary operator (spec §4.2).
pub(crate) enum BinaryOp {
    Mul,
    Div,
    Rem,
    Add,
    Sub,
    Shl,
    Shr,
    BitAnd,
    BitXor,
    BitOr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

impl BinaryOp {
    /// Every binary operator, for the lexer and for tests.
    pub(crate) const ALL: [Self; 18] = [
        Self::Mul,
        Self::Div,
        Self::Rem,
        Self::Add,
        Self::Sub,
        Self::Shl,
        Self::Shr,
        Self::BitAnd,
        Self::BitXor,
        Self::BitOr,
        Self::Eq,
        Self::Ne,
        Self::Lt,
        Self::Le,
        Self::Gt,
        Self::Ge,
        Self::And,
        Self::Or,
    ];

    /// The operator as written.
    pub(crate) const fn symbol(self) -> &'static str {
        match self {
            Self::Mul => "*",
            Self::Div => "/",
            Self::Rem => "%",
            Self::Add => "+",
            Self::Sub => "-",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::BitAnd => "&",
            Self::BitXor => "^",
            Self::BitOr => "|",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::And => "&&",
            Self::Or => "||",
        }
    }

    /// Binding strength, higher is tighter: Rust/Python order, not C's (ADR 0007). Unary
    /// operators bind tighter than all of these.
    const fn precedence(self) -> u8 {
        match self {
            Self::Mul | Self::Div | Self::Rem => 9,
            Self::Add | Self::Sub => 8,
            Self::Shl | Self::Shr => 7,
            Self::BitAnd => 6,
            Self::BitXor => 5,
            Self::BitOr => 4,
            Self::Eq | Self::Ne | Self::Lt | Self::Le | Self::Gt | Self::Ge => 3,
            Self::And => 2,
            Self::Or => 1,
        }
    }

    /// Comparisons do not associate: `a < b < c` is an error.
    const fn is_comparison(self) -> bool {
        self.precedence() == 3
    }
}

/// A syntax error, with the span of the offending token in the Expression's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SyntaxError {
    pub(crate) name: Name,
    pub(crate) span: Range<usize>,
    pub(crate) message: String,
    pub(crate) note: Option<String>,
}

impl SyntaxError {
    fn new(span: Range<usize>, message: impl Into<String>) -> Self {
        Self::named(Name::ExpressionSyntax, span, message)
    }

    /// An error with its own Diagnostic name, not `expression-syntax`.
    fn named(name: Name, span: Range<usize>, message: impl Into<String>) -> Self {
        Self { name, span, message: message.into(), note: None }
    }

    fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// Parses the Expression written in the string scalar `node`, whose value is `text`. Spans,
/// the error's included, point into the source: at the token in a string spelled verbatim,
/// else at the whole value (spec §6.4).
pub(crate) fn parse(node: &Node, text: &str) -> Result<Expr, Diagnostic> {
    match parse_text(text) {
        Ok(mut expr) => {
            expr.map_spans(&|span| node.token_span(span));
            Ok(expr)
        }
        Err(error) => {
            let diagnostic = Diagnostic::new(error.name, node.token_span(error.span), error.message);
            Err(match error.note {
                Some(hint) => diagnostic.with_note(hint, None),
                None => diagnostic,
            })
        }
    }
}

/// Parses an Expression, with spans into `text`.
pub(crate) fn parse_text(text: &str) -> Result<Expr, SyntaxError> {
    let tokens = lex(text)?;
    let mut parser = Parser { tokens: &tokens, next: 0, end: text.len(), depth: 0 };
    if tokens.is_empty() {
        return Err(SyntaxError::new(0..text.len(), "the Expression is empty"));
    }
    let Parsed { expr, .. } = parser.binary(1)?;
    match parser.peek() {
        None => Ok(expr),
        Some(Token { kind: TokenKind::Close, span }) => {
            Err(SyntaxError::new(span.clone(), "this `)` closes no `(`").with_note("remove it, or add a `(` before it"))
        }
        Some(token) => Err(SyntaxError::new(token.span.clone(), format!("expected an operator, found {}", token.kind))),
    }
}

/// Why an Expression has no value (spec §4.4). At runtime each is a malformed packet; in a
/// constant Expression, validation reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// `/` or `%` by zero.
    DivisionByZero,
    /// A shift count outside 0..63.
    ShiftOutOfRange(i64),
}

impl Expr {
    /// The Field Paths and built-ins the Expression reads, in source order.
    pub(crate) fn references(&self) -> Vec<&Expr> {
        match &self.kind {
            ExprKind::Int(_) => Vec::new(),
            ExprKind::Path(_) | ExprKind::Builtin(_) => vec![self],
            ExprKind::Unary { operand, .. } => operand.references(),
            ExprKind::Binary { left, right, .. } => {
                let mut found = left.references();
                found.extend(right.references());
                found
            }
        }
    }

    /// The value of an Expression without references, with C's integer semantics (ADR 0007), or
    /// the fault at its operator; `None` when it reads a Field or a built-in.
    pub(crate) fn constant(&self) -> Option<Result<i64, Spanned<Fault>>> {
        if !self.references().is_empty() {
            return None;
        }
        Some(self.evaluate())
    }

    fn evaluate(&self) -> Result<i64, Spanned<Fault>> {
        let truth = |b: bool| i64::from(b);
        match &self.kind {
            #[expect(clippy::cast_possible_wrap, reason = "literals above `i64::MAX` wrap (spec §4.4)")]
            ExprKind::Int(value) => Ok(*value as i64),
            ExprKind::Path(_) | ExprKind::Builtin(_) => unreachable!("`constant` rules references out"),
            ExprKind::Unary { op, operand } => {
                let value = operand.evaluate()?;
                Ok(match op.value {
                    UnaryOp::Not => truth(value == 0),
                    UnaryOp::Complement => !value,
                    UnaryOp::Negate => value.wrapping_neg(),
                })
            }
            ExprKind::Binary { op, left, right } => {
                let a = left.evaluate()?;
                // `&&` and `||` evaluate their right side only when needed, as in C.
                match op.value {
                    BinaryOp::And if a == 0 => return Ok(0),
                    BinaryOp::Or if a != 0 => return Ok(1),
                    _ => {}
                }
                let b = right.evaluate()?;
                let fault = |fault| Err(Spanned { value: fault, span: op.span.clone() });
                let shift = || u32::try_from(b).ok().filter(|n| *n < 64);
                Ok(match op.value {
                    BinaryOp::Div | BinaryOp::Rem if b == 0 => return fault(Fault::DivisionByZero),
                    BinaryOp::Shl | BinaryOp::Shr if shift().is_none() => return fault(Fault::ShiftOutOfRange(b)),
                    BinaryOp::Mul => a.wrapping_mul(b),
                    BinaryOp::Div => a.wrapping_div(b),
                    BinaryOp::Rem => a.wrapping_rem(b),
                    BinaryOp::Add => a.wrapping_add(b),
                    BinaryOp::Sub => a.wrapping_sub(b),
                    BinaryOp::Shl => a << shift().expect("checked above"),
                    BinaryOp::Shr => a >> shift().expect("checked above"),
                    BinaryOp::BitAnd => a & b,
                    BinaryOp::BitXor => a ^ b,
                    BinaryOp::BitOr => a | b,
                    BinaryOp::Eq => truth(a == b),
                    BinaryOp::Ne => truth(a != b),
                    BinaryOp::Lt => truth(a < b),
                    BinaryOp::Le => truth(a <= b),
                    BinaryOp::Gt => truth(a > b),
                    BinaryOp::Ge => truth(a >= b),
                    BinaryOp::And | BinaryOp::Or => truth(b != 0),
                })
            }
        }
    }

    fn map_spans(&mut self, f: &impl Fn(Range<usize>) -> Range<usize>) {
        self.span = f(self.span.clone());
        match &mut self.kind {
            ExprKind::Int(_) | ExprKind::Path(_) | ExprKind::Builtin(_) => {}
            ExprKind::Unary { op, operand } => {
                op.span = f(op.span.clone());
                operand.map_spans(f);
            }
            ExprKind::Binary { op, left, right } => {
                op.span = f(op.span.clone());
                left.map_spans(f);
                right.map_spans(f);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// What a token of an Expression is.
enum TokenKind {
    Int(u64),
    Path(Vec<String>),
    Builtin(Builtin),
    Unary(UnaryOp),
    Binary(BinaryOp),
    Open,
    Close,
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(value) => write!(f, "the number `{value}`"),
            Self::Path(segments) => write!(f, "`{}`", segments.join(".")),
            Self::Builtin(builtin) => write!(f, "`{}`", builtin.as_str()),
            Self::Unary(op) => write!(f, "`{}`", op.symbol()),
            Self::Binary(op) => write!(f, "`{}`", op.symbol()),
            Self::Open => f.write_str("`(`"),
            Self::Close => f.write_str("`)`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A token, with its span in the Expression's text.
struct Token {
    kind: TokenKind,
    span: Range<usize>,
}

/// Splits `text` into tokens. `-` is always lexed as subtraction; the parser reads it as
/// negation where an operand is expected.
fn lex(text: &str) -> Result<Vec<Token>, SyntaxError> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        let c = bytes[at];
        let kind = if c.is_ascii_whitespace() {
            at += 1;
            continue;
        } else if c.is_ascii_digit() {
            at = word_end(bytes, at);
            TokenKind::Int(literal(&text[start..at], start..at)?)
        } else if c.is_ascii_alphabetic() || c == b'_' {
            at = word_end(bytes, at);
            let mut segments = vec![text[start..at].to_owned()];
            while bytes.get(at) == Some(&b'.') {
                let segment = at + 1;
                at = word_end(bytes, segment);
                if segment == at || !(bytes[segment].is_ascii_alphabetic()) {
                    return Err(SyntaxError::new(start..at.max(segment), "expected a Field name after `.`")
                        .with_note("a Field Path is names separated by `.`, as in `header.length`"));
                }
                segments.push(text[segment..at].to_owned());
            }
            builtin_or_path(segments, start..at)?
        } else {
            let two = text.get(at..at + 2).unwrap_or("");
            let (kind, len) =
                if let Some(op) = BinaryOp::ALL.iter().find(|op| op.symbol().len() == 2 && op.symbol() == two) {
                    (TokenKind::Binary(*op), 2)
                } else {
                    let kind = match c {
                        b'(' => TokenKind::Open,
                        b')' => TokenKind::Close,
                        b'!' => TokenKind::Unary(UnaryOp::Not),
                        b'~' => TokenKind::Unary(UnaryOp::Complement),
                        _ => match BinaryOp::ALL.iter().find(|op| op.symbol().as_bytes() == [c]) {
                            Some(op) => TokenKind::Binary(*op),
                            None => return Err(unexpected_character(text, at)),
                        },
                    };
                    (kind, 1)
                };
            at += len;
            kind
        };
        tokens.push(Token { kind, span: start..at });
    }
    Ok(tokens)
}

/// The end of the run of letters, digits and `_` starting at `at`.
fn word_end(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_') {
        at += 1;
    }
    at
}

/// The error for a character at `at` that starts no token.
fn unexpected_character(text: &str, at: usize) -> SyntaxError {
    let c = text[at..].chars().next().expect("`at` is inside `text`");
    let span = at..at + c.len_utf8();
    let error = SyntaxError::new(span, format!("unexpected `{c}` in an Expression"));
    match c {
        '=' => error.with_note("compare with `==`"),
        '"' | '\'' => error.with_note("an Expression has no strings"),
        _ => error
            .with_note("an Expression holds integers, Field Paths, `_offset`, `_remaining`, operators and parentheses"),
    }
}

/// A name starting with `_` is a built-in; any other is a Field Path.
fn builtin_or_path(segments: Vec<String>, span: Range<usize>) -> Result<TokenKind, SyntaxError> {
    if !segments[0].starts_with('_') {
        return Ok(TokenKind::Path(segments));
    }
    let names: Vec<&str> = Builtin::ALL.iter().map(|b| b.as_str()).collect();
    match Builtin::ALL.iter().find(|b| b.as_str() == segments[0]) {
        Some(_) if segments.len() > 1 => Err(SyntaxError::new(span, format!("`{}` has no Fields", segments[0]))),
        Some(builtin) => Ok(TokenKind::Builtin(*builtin)),
        None => Err(SyntaxError::new(span, format!("there is no built-in `{}`", segments[0]))
            .with_note(format!("the built-ins are {}; Field names cannot start with `_`", names.join(" and ")))),
    }
}

/// The value of an integer literal: decimal, `0x` or `0b`, with `_` separators (spec §4.2).
fn literal(word: &str, span: Range<usize>) -> Result<u64, SyntaxError> {
    let prefix = word.get(..2);
    let (digits, radix, kind) = match prefix {
        Some(p) if p.eq_ignore_ascii_case("0x") => (&word[2..], 16, "hexadecimal"),
        Some(p) if p.eq_ignore_ascii_case("0b") => (&word[2..], 2, "binary"),
        _ => (word, 10, "decimal"),
    };
    if radix == 10 && word.len() > 1 && word.starts_with('0') && word.bytes().all(|b| b.is_ascii_digit() || b == b'_') {
        // The decimal number a reader most likely meant, the zeros dropped.
        let decimal = word.trim_start_matches(['0', '_']);
        let decimal = if decimal.is_empty() { "0" } else { decimal };
        return Err(SyntaxError::named(Name::LeadingZeroLiteral, span, format!("`{word}` starts with a zero"))
            .with_note(format!(
                "write `{decimal}` for a decimal number, or `0x`/`0b` for hexadecimal or binary; octal does not exist"
            )));
    }
    if let Some(bad) = digits.chars().find(|c| *c != '_' && !c.is_digit(radix)) {
        let bad = bad.to_ascii_lowercase();
        return Err(SyntaxError::new(span, format!("`{bad}` is not a {kind} digit in `{word}`")));
    }
    // Every character is now a digit or a `_`: the digits, the `_`s skipped.
    let mut values = digits.chars().filter_map(|c| c.to_digit(radix)).peekable();
    if values.peek().is_none() {
        return Err(SyntaxError::new(span, format!("`{word}` has no digits")));
    }
    values
        .try_fold(0_u64, |value, digit| value.checked_mul(u64::from(radix))?.checked_add(u64::from(digit)))
        .ok_or_else(|| SyntaxError::new(span, format!("`{word}` does not fit in 64 bits")))
}

/// How deep an Expression may nest (ADR 0018): a deeper one makes a Dissector Lua cannot load.
const MAX_DEPTH: usize = 64;

/// A precedence-climbing parser over the tokens of one Expression.
///
/// It measures depth as it goes: each `(`, unary operator and value is one level below what
/// encloses it, and each binary operator one level above both its operands, so a flat chain
/// `a+a+…+a` of k operands is k deep. Past [`MAX_DEPTH`] it stops, which also bounds its
/// recursion and that of every pass walking the tree after it.
struct Parser<'t> {
    tokens: &'t [Token],
    /// The index of the next token to read.
    next: usize,
    /// The length of the text, where a missing token is reported.
    end: usize,
    /// How many levels enclose the sub-Expression being read.
    depth: usize,
}

/// A parsed sub-Expression and how many levels it spans.
struct Parsed {
    expr: Expr,
    /// Its depth, its parentheses included: 1 for a value.
    levels: usize,
}

impl Parser<'_> {
    /// The next token, without reading it.
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.next)
    }

    /// Fails at `span` if a sub-Expression spanning `levels` here would be too deep (ADR 0018).
    fn ensure_depth(&self, levels: usize, span: &Range<usize>) -> Result<(), SyntaxError> {
        if self.depth + levels <= MAX_DEPTH {
            return Ok(());
        }
        Err(SyntaxError::named(
            Name::ExpressionTooDeep,
            span.clone(),
            format!("the Expression is nested more than {MAX_DEPTH} levels deep"),
        )
        .with_note(format!(
            "Expressions are limited to {MAX_DEPTH} levels: a deeper one makes a Dissector that Lua cannot load"
        )))
    }

    /// Reads with `read` one level deeper, after checking that `span` may open that level.
    fn nested(
        &mut self,
        span: &Range<usize>,
        read: impl FnOnce(&mut Self) -> Result<Parsed, SyntaxError>,
    ) -> Result<Parsed, SyntaxError> {
        self.ensure_depth(1, span)?;
        self.depth += 1;
        let parsed = read(self);
        self.depth -= 1;
        parsed
    }

    /// An Expression whose binary operators bind at least as tightly as `min`.
    fn binary(&mut self, min: u8) -> Result<Parsed, SyntaxError> {
        let Parsed { expr: mut left, mut levels } = self.unary()?;
        // Whether `left` is a comparison this loop built, so another one chains it.
        let mut compared = false;
        while let Some(Token { kind: TokenKind::Binary(op), span }) = self.peek().cloned() {
            if op.precedence() < min {
                break;
            }
            if compared && op.is_comparison() {
                return Err(SyntaxError::named(Name::ChainedComparison, span, "comparisons cannot be chained")
                    .with_note("join two comparisons with `&&`, as in `a < b && b < c`, or add parentheses"));
            }
            // The operator pushes everything read so far one level down.
            self.ensure_depth(levels + 1, &span)?;
            self.next += 1;
            let Parsed { expr: right, levels: right_levels } =
                self.nested(&span, |parser| parser.binary(op.precedence() + 1))?;
            levels = 1 + levels.max(right_levels);
            compared = op.is_comparison();
            let whole = left.span.start..right.span.end;
            left = Expr {
                kind: ExprKind::Binary {
                    op: Spanned { value: op, span },
                    left: Box::new(left),
                    right: Box::new(right),
                },
                span: whole,
            };
        }
        Ok(Parsed { expr: left, levels })
    }

    /// A unary operator applied to an operand, or an operand.
    fn unary(&mut self) -> Result<Parsed, SyntaxError> {
        let op = match self.peek().map(|t| &t.kind) {
            Some(TokenKind::Unary(op)) => *op,
            Some(TokenKind::Binary(BinaryOp::Sub)) => UnaryOp::Negate,
            _ => return self.operand(),
        };
        let span = self.peek().expect("just peeked").span.clone();
        self.next += 1;
        let Parsed { expr: operand, levels } = self.nested(&span, Self::unary)?;
        let whole = span.start..operand.span.end;
        let expr =
            Expr { kind: ExprKind::Unary { op: Spanned { value: op, span }, operand: Box::new(operand) }, span: whole };
        Ok(Parsed { expr, levels: levels + 1 })
    }

    /// A literal, a Field Path, a built-in or a parenthesized Expression.
    fn operand(&mut self) -> Result<Parsed, SyntaxError> {
        let Some(token) = self.peek().cloned() else {
            return Err(SyntaxError::new(self.end..self.end, "the Expression ends early: expected a value"));
        };
        if matches!(token.kind, TokenKind::Int(_) | TokenKind::Path(_) | TokenKind::Builtin(_)) {
            self.ensure_depth(1, &token.span)?;
        }
        self.next += 1;
        let kind = match token.kind {
            TokenKind::Int(value) => ExprKind::Int(value),
            TokenKind::Path(segments) => ExprKind::Path(segments),
            TokenKind::Builtin(builtin) => ExprKind::Builtin(builtin),
            TokenKind::Open => {
                let Parsed { expr: inner, levels } = self.nested(&token.span, |parser| parser.binary(1))?;
                return match self.peek() {
                    Some(Token { kind: TokenKind::Close, .. }) => {
                        self.next += 1;
                        Ok(Parsed { expr: inner, levels: levels + 1 })
                    }
                    Some(other) => {
                        Err(SyntaxError::new(other.span.clone(), format!("expected `)`, found {}", other.kind)))
                    }
                    None => Err(SyntaxError::new(token.span, "this `(` is never closed")
                        .with_note("add a `)` where the parenthesized part ends")),
                };
            }
            other => return Err(SyntaxError::new(token.span, format!("expected a value, found {other}"))),
        };
        Ok(Parsed { expr: Expr { kind, span: token.span }, levels: 1 })
    }
}

impl Expr {
    /// The tree as an S-expression, for tests: `(+ 1 (* 2 3))`.
    #[cfg(test)]
    fn shape(&self) -> String {
        match &self.kind {
            ExprKind::Int(value) => value.to_string(),
            ExprKind::Path(segments) => segments.join("."),
            ExprKind::Builtin(builtin) => builtin.as_str().to_owned(),
            ExprKind::Unary { op, operand } => format!("({} {})", op.value.symbol(), operand.shape()),
            ExprKind::Binary { op, left, right } => {
                format!("({} {} {})", op.value.symbol(), left.shape(), right.shape())
            }
        }
    }
}

/// Prints the Expression with only the parentheses its tree needs, for the round-trip tests.
#[cfg(test)]
impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ExprKind::Int(value) => write!(f, "{value}"),
            ExprKind::Path(segments) => f.write_str(&segments.join(".")),
            ExprKind::Builtin(builtin) => f.write_str(builtin.as_str()),
            ExprKind::Unary { op, operand } => match operand.kind {
                ExprKind::Binary { .. } => write!(f, "{}({operand})", op.value.symbol()),
                _ => write!(f, "{}{operand}", op.value.symbol()),
            },
            ExprKind::Binary { op, left, right } => {
                let precedence = |e: &Expr| match &e.kind {
                    ExprKind::Binary { op, .. } => op.value.precedence(),
                    _ => u8::MAX,
                };
                let own = op.value.precedence();
                // Left-associative, and comparisons not at all.
                let left_parens = precedence(left) < own || (op.value.is_comparison() && precedence(left) == own);
                let wrap = |e: &Expr, parens: bool| if parens { format!("({e})") } else { e.to_string() };
                write!(f, "{} {} {}", wrap(left, left_parens), op.value.symbol(), wrap(right, precedence(right) <= own))
            }
        }
    }
}

#[cfg(test)]
impl Expr {
    /// Records the kinds of the Expression's tokens and nodes, its operators and its built-ins.
    pub(crate) fn cover(&self, coverage: &mut crate::coverage::Coverage<'_>) {
        use crate::coverage::variants;
        let source = coverage.source;
        for token in lex(&source[self.span.clone()]).expect("a parsed Expression lexes") {
            variants!(coverage, "TokenKind", &token.kind, {
                TokenKind::Int(_) => "Int",
                TokenKind::Path(_) => "Path",
                TokenKind::Builtin(_) => "Builtin",
                TokenKind::Unary(_) => "Unary",
                TokenKind::Binary(_) => "Binary",
                TokenKind::Open => "Open",
                TokenKind::Close => "Close",
            });
        }
        self.cover_nodes(coverage);
    }

    fn cover_nodes(&self, coverage: &mut crate::coverage::Coverage<'_>) {
        use crate::coverage::variants;
        variants!(coverage, "ExprKind", &self.kind, {
            ExprKind::Int(_) => "Int",
            ExprKind::Path(_) => "Path",
            ExprKind::Builtin(_) => "Builtin",
            ExprKind::Unary { .. } => "Unary",
            ExprKind::Binary { .. } => "Binary",
        });
        match &self.kind {
            ExprKind::Int(_) | ExprKind::Path(_) => {}
            ExprKind::Builtin(builtin) => variants!(coverage, "Builtin", builtin, {
                Builtin::Offset => "Offset",
                Builtin::Remaining => "Remaining",
            }),
            ExprKind::Unary { op, operand } => {
                variants!(coverage, "UnaryOp", &op.value, {
                    UnaryOp::Not => "Not",
                    UnaryOp::Complement => "Complement",
                    UnaryOp::Negate => "Negate",
                });
                operand.cover_nodes(coverage);
            }
            ExprKind::Binary { op, left, right } => {
                variants!(coverage, "BinaryOp", &op.value, {
                    BinaryOp::Mul => "Mul",
                    BinaryOp::Div => "Div",
                    BinaryOp::Rem => "Rem",
                    BinaryOp::Add => "Add",
                    BinaryOp::Sub => "Sub",
                    BinaryOp::Shl => "Shl",
                    BinaryOp::Shr => "Shr",
                    BinaryOp::BitAnd => "BitAnd",
                    BinaryOp::BitXor => "BitXor",
                    BinaryOp::BitOr => "BitOr",
                    BinaryOp::Eq => "Eq",
                    BinaryOp::Ne => "Ne",
                    BinaryOp::Lt => "Lt",
                    BinaryOp::Le => "Le",
                    BinaryOp::Gt => "Gt",
                    BinaryOp::Ge => "Ge",
                    BinaryOp::And => "And",
                    BinaryOp::Or => "Or",
                });
                left.cover_nodes(coverage);
                right.cover_nodes(coverage);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Any Expression tree, with empty spans.
    fn any_expr() -> impl Strategy<Value = Expr> {
        let leaf = prop_oneof![
            any::<u64>().prop_map(ExprKind::Int),
            prop::sample::select(vec!["a", "len", "hdr.len", "x.y_2.z"])
                .prop_map(|p| ExprKind::Path(p.split('.').map(str::to_owned).collect())),
            prop::sample::select(Builtin::ALL.to_vec()).prop_map(ExprKind::Builtin),
        ]
        .prop_map(|kind| Expr { kind, span: 0..0 });
        leaf.prop_recursive(6, 48, 2, |inner| {
            prop_oneof![
                (prop::sample::select(vec![UnaryOp::Not, UnaryOp::Complement, UnaryOp::Negate]), inner.clone())
                    .prop_map(|(op, operand)| ExprKind::Unary {
                        op: Spanned { value: op, span: 0..0 },
                        operand: Box::new(operand)
                    }),
                (prop::sample::select(BinaryOp::ALL.to_vec()), inner.clone(), inner).prop_map(|(op, left, right)| {
                    ExprKind::Binary {
                        op: Spanned { value: op, span: 0..0 },
                        left: Box::new(left),
                        right: Box::new(right),
                    }
                }),
            ]
            .prop_map(|kind| Expr { kind, span: 0..0 })
        })
    }

    proptest! {
        /// Printing a tree with minimal parentheses and parsing it back gives the same tree, so
        /// the parser agrees with the precedence and associativity the printer assumes.
        #[test]
        fn printed_expressions_parse_back_to_the_same_tree(expr in any_expr()) {
            let text = expr.to_string();
            let parsed = parse_text(&text).map_err(|e| TestCaseError::fail(format!("{text}: {}", e.message)))?;
            prop_assert_eq!(parsed.shape(), expr.shape(), "{}", text);
        }

        /// Whatever the text, the parser returns, and an error's span lies within the text.
        #[test]
        fn any_text_parses_or_fails_inside_it(text in "[-+*/%<>=!&|^~()a-z_.0-9xX ]{0,24}") {
            if let Err(error) = parse_text(&text) {
                prop_assert!(error.span.start <= error.span.end && error.span.end <= text.len());
            }
        }
    }

    /// The shape of `text`'s tree as an S-expression, or the error's message.
    fn shape(text: &str) -> String {
        match parse_text(text) {
            Ok(expr) => expr.shape(),
            Err(error) => format!("error: {}", error.message),
        }
    }

    #[test]
    fn multiplication_binds_tighter_than_addition() {
        assert_eq!(shape("1 + 2 * 3"), "(+ 1 (* 2 3))");
    }

    /// Spec §4.2, tightest first: unary, `* / %`, `+ -`, `<< >>`, `&`, `^`, `|`, comparisons,
    /// `&&`, `||`. Each pair checks one level against the next, both ways round.
    #[test]
    fn operators_bind_in_rust_order_not_c_order() {
        for (text, expected) in [
            ("-a * b", "(* (- a) b)"),
            ("a * -b", "(* a (- b))"),
            ("!a + ~b", "(+ (! a) (~ b))"),
            ("a * b + c", "(+ (* a b) c)"),
            ("a + b * c", "(+ a (* b c))"),
            ("a / b % c", "(% (/ a b) c)"),
            ("a + b << c", "(<< (+ a b) c)"),
            ("a << b - c", "(<< a (- b c))"),
            ("a << b & c", "(& (<< a b) c)"),
            ("a & b >> c", "(& a (>> b c))"),
            ("a & b ^ c", "(^ (& a b) c)"),
            ("a ^ b & c", "(^ a (& b c))"),
            ("a ^ b | c", "(| (^ a b) c)"),
            ("a | b ^ c", "(| a (^ b c))"),
            ("flags & 0x80 == 0x80", "(== (& flags 128) 128)"),
            ("a == b | c", "(== a (| b c))"),
            ("a < b && c >= d", "(&& (< a b) (>= c d))"),
            ("a && b || c", "(|| (&& a b) c)"),
            ("a || b && c", "(|| a (&& b c))"),
        ] {
            assert_eq!(shape(text), expected, "{text}");
        }
    }

    #[test]
    fn binary_operators_associate_left_and_parentheses_override() {
        assert_eq!(shape("a - b - c"), "(- (- a b) c)");
        assert_eq!(shape("a / b * c"), "(* (/ a b) c)");
        assert_eq!(shape("a || b || c"), "(|| (|| a b) c)");
        assert_eq!(shape("a - (b - c)"), "(- a (- b c))");
        assert_eq!(shape("(a + b) * c"), "(* (+ a b) c)");
        assert_eq!(shape("((a))"), "a");
        assert_eq!(shape("- -a"), "(- (- a))");
        assert_eq!(shape("!!a"), "(! (! a))");
    }

    #[test]
    fn comparisons_do_not_chain_unless_parenthesized() {
        assert_eq!(shape("a < b < c"), "error: comparisons cannot be chained");
        assert_eq!(shape("a == b != c"), "error: comparisons cannot be chained");
        assert_eq!(shape("(a < b) < c"), "(< (< a b) c)");
        assert_eq!(shape("a < (b < c)"), "(< a (< b c))");
        assert_eq!(shape("a < b == (c < d)"), "error: comparisons cannot be chained");
        let error = parse_text("a < b <= c").unwrap_err();
        assert_eq!((error.name, error.span), (Name::ChainedComparison, 6..8));
    }

    #[test]
    fn literals_are_decimal_hex_or_binary_with_separators() {
        for (text, expected) in [
            ("0", "0"),
            ("42", "42"),
            ("1_000_000", "1000000"),
            ("0x1F", "31"),
            ("0X1f", "31"),
            ("0xFF_FF", "65535"),
            ("0b1010", "10"),
            ("0B1_0", "2"),
            ("0x00ff", "255"),
            ("18446744073709551615", "18446744073709551615"),
            ("0xFFFF_FFFF_FFFF_FFFF", "18446744073709551615"),
            ("0b_1__1_", "3"),
            ("0x0000_0000_0000_0000_0001", "1"),
        ] {
            assert_eq!(shape(text), expected, "{text}");
        }
    }

    #[test]
    fn leading_zero_literals_are_errors() {
        for text in ["010", "00", "0_7", "007 + 1"] {
            let error = parse_text(text).unwrap_err();
            assert_eq!(error.name, Name::LeadingZeroLiteral, "{text}");
        }
        let error = parse_text("1 + 010").unwrap_err();
        assert_eq!(error.span, 4..7);
        assert_eq!(error.note.as_deref().map(|n| n.starts_with("write `10`")), Some(true));
    }

    #[test]
    fn names_are_field_paths_or_builtins() {
        assert_eq!(shape("hdr.len + flags.ext"), "(+ hdr.len flags.ext)");
        assert_eq!(shape("_remaining - _offset"), "(- _remaining _offset)");
        assert_eq!(shape("len2_x"), "len2_x");
    }

    /// Each error's message and the text its span covers.
    #[test]
    fn syntax_errors_point_at_the_offending_token() {
        for (text, message, at) in [
            ("", "the Expression is empty", ""),
            ("   ", "the Expression is empty", "   "),
            ("1 +", "the Expression ends early: expected a value", ""),
            ("(1 + 2", "this `(` is never closed", "("),
            ("((1) + 2", "this `(` is never closed", "("),
            ("(1 2)", "expected `)`, found the number `2`", "2"),
            ("1 + 2)", "this `)` closes no `(`", ")"),
            ("len 4", "expected an operator, found the number `4`", "4"),
            ("1 + * 2", "expected a value, found `*`", "*"),
            ("()", "expected a value, found `)`", ")"),
            ("a = 1", "unexpected `=` in an Expression", "="),
            ("a ? b : c", "unexpected `?` in an Expression", "?"),
            ("a + é", "unexpected `é` in an Expression", "é"),
            ("12ab", "`a` is not a decimal digit in `12ab`", "12ab"),
            ("0b102", "`2` is not a binary digit in `0b102`", "0b102"),
            ("0xG", "`g` is not a hexadecimal digit in `0xG`", "0xG"),
            ("0x", "`0x` has no digits", "0x"),
            ("0x_", "`0x_` has no digits", "0x_"),
            ("0B__", "`0B__` has no digits", "0B__"),
            ("12AB", "`a` is not a decimal digit in `12AB`", "12AB"),
            ("0X_1G", "`g` is not a hexadecimal digit in `0X_1G`", "0X_1G"),
            ("0b2", "`2` is not a binary digit in `0b2`", "0b2"),
            (
                "0x1_0000_0000_0000_0000G",
                "`g` is not a hexadecimal digit in `0x1_0000_0000_0000_0000G`",
                "0x1_0000_0000_0000_0000G",
            ),
            ("0x1_0000_0000_0000_0000", "`0x1_0000_0000_0000_0000` does not fit in 64 bits", "0x1_0000_0000_0000_0000"),
            (
                "1_8446_7440_7370_9551_616",
                "`1_8446_7440_7370_9551_616` does not fit in 64 bits",
                "1_8446_7440_7370_9551_616",
            ),
            ("18446744073709551616", "`18446744073709551616` does not fit in 64 bits", "18446744073709551616"),
            ("2 * _size", "there is no built-in `_size`", "_size"),
            ("_offset.x", "`_offset` has no Fields", "_offset.x"),
            ("hdr.", "expected a Field name after `.`", "hdr."),
            ("hdr._x", "expected a Field name after `.`", "hdr._x"),
            ("hdr..len", "expected a Field name after `.`", "hdr."),
        ] {
            let error = parse_text(text).expect_err(text);
            assert_eq!((error.name, error.message.as_str(), &text[error.span]), (Name::ExpressionSyntax, message, at));
        }
    }

    fn value(text: &str) -> Result<i64, (Fault, String)> {
        let expr = parse_text(text).unwrap();
        expr.constant().expect("no references").map_err(|f| (f.value, text[f.span].to_owned()))
    }

    /// ADR 0007: C's truncating `/` and dividend-signed `%`, arithmetic `>>`, wrapping overflow,
    /// 1 or 0 from comparisons and logic.
    #[test]
    fn constants_evaluate_with_c_integer_semantics() {
        for (text, expected) in [
            ("1 + 2 * 3", 7),
            ("-7 / 2", -3),
            ("7 / -2", -3),
            ("-7 % 2", -1),
            ("7 % -2", 1),
            ("-8 >> 1", -4),
            ("-1 >> 63", -1),
            ("1 << 63", i64::MIN),
            ("0xFFFF_FFFF_FFFF_FFFF", -1),
            ("9223372036854775807 + 1", i64::MIN),
            ("-9223372036854775808", i64::MIN),
            ("-9223372036854775808 / -1", i64::MIN),
            ("-9223372036854775808 % -1", 0),
            ("~0", -1),
            ("!0 + !5", 1),
            ("0xF0 & 0x3C | 1 ^ 3", 0x32),
            ("3 < 4", 1),
            ("3 >= 4", 0),
            ("2 == 2 && 3 != 3", 0),
            ("0 || -1", 1),
        ] {
            assert_eq!(value(text), Ok(expected), "{text}");
        }
    }

    #[test]
    fn logic_short_circuits_like_c() {
        assert_eq!(value("0 && 1 / 0"), Ok(0));
        assert_eq!(value("1 || 1 % 0"), Ok(1));
        assert_eq!(value("1 && 1 / 0"), Err((Fault::DivisionByZero, "/".to_owned())));
    }

    #[test]
    fn faults_point_at_their_operator() {
        assert_eq!(value("4 % (2 - 2)"), Err((Fault::DivisionByZero, "%".to_owned())));
        assert_eq!(value("1 << 64"), Err((Fault::ShiftOutOfRange(64), "<<".to_owned())));
        assert_eq!(value("1 >> -1"), Err((Fault::ShiftOutOfRange(-1), ">>".to_owned())));
    }

    #[test]
    fn references_make_an_expression_non_constant() {
        let expr = parse_text("2 * (len + _offset)").unwrap();
        assert!(expr.constant().is_none());
        let found: Vec<String> = expr.references().iter().map(|r| r.shape()).collect();
        assert_eq!(found, ["len", "_offset"]);
    }

    /// The text a too-deep error's span covers, or `None` when `text` parses.
    fn too_deep_at(text: &str) -> Option<String> {
        let error = parse_text(text).err()?;
        assert_eq!(error.name, Name::ExpressionTooDeep, "{}", error.message);
        Some(text[error.span].to_owned())
    }

    #[test]
    fn expressions_up_to_depth_64_parse() {
        let unary = format!("{}a", "-".repeat(63));
        let flat = format!("a{}", " + a".repeat(63));
        let parenthesized = format!("{}a{}", "(".repeat(63), ")".repeat(63));
        for text in [unary, flat, parenthesized] {
            assert!(parse_text(&text).is_ok(), "{text}");
        }
    }

    #[test]
    fn depth_65_is_too_deep_at_the_token_that_reaches_it() {
        // Each `(` and unary operator is a level, and so is the value they enclose.
        assert_eq!(too_deep_at(&format!("{}x", "-".repeat(64))).as_deref(), Some("x"));
        assert_eq!(too_deep_at(&format!("{}x{}", "(".repeat(64), ")".repeat(64))).as_deref(), Some("x"));
        assert_eq!(too_deep_at(&format!("{}x", "(".repeat(65))).as_deref(), Some("("));
        // A flat chain of k operands is k deep: the operator adding the 65th one reaches 65.
        assert_eq!(too_deep_at(&format!("a{} - a", " + a".repeat(63))).as_deref(), Some("-"));
        assert_eq!(too_deep_at(&format!("a{} * a", " + a".repeat(63))), None);
        // An operator that wraps a deep left side deepens everything already in it.
        let mixed = format!("{}a{} + b + c + d + e", "(".repeat(60), ")".repeat(60));
        let error = parse_text(&mixed).unwrap_err();
        assert_eq!((error.name, error.span.start), (Name::ExpressionTooDeep, mixed.rfind('+').unwrap()));
    }

    #[test]
    fn far_too_deep_expressions_fail_without_overflowing_the_stack() {
        let flat = format!("a{} > 0", "+a".repeat(99_999));
        for text in ["(".repeat(30_000) + "1" + &")".repeat(30_000), "-".repeat(30_000) + "1", flat] {
            assert!(too_deep_at(&text).is_some());
        }
    }

    #[test]
    fn a_too_deep_expression_states_the_limit_and_why() {
        let error = parse_text(&format!("{}1", "-".repeat(64))).unwrap_err();
        assert_eq!(error.message, "the Expression is nested more than 64 levels deep");
        assert_eq!(
            error.note.as_deref(),
            Some("Expressions are limited to 64 levels: a deeper one makes a Dissector that Lua cannot load")
        );
    }
}
