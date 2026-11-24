//! Fenced code in message bodies.
//!
//! Messages are plain text on the wire. A body containing CommonMark-style
//! fences (``` or ~~~) is split into text and code blocks here: text keeps the
//! usual mention/link styling, code is rendered unwrapped with its own small
//! highlighter (no extra dependency, works offline for any labelled language).

use super::Message;
use crate::theme;
use iced::widget::span;
use iced::widget::text::Span;
use iced::Color;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Block<'a> {
    Text(&'a str),
    Code { lang: Option<&'a str>, code: &'a str },
}

/// Split a message body into text and fenced-code blocks. A fence that is
/// never closed runs to the end of the message, as CommonMark requires.
pub(super) fn blocks(content: &str) -> Vec<Block<'_>> {
    if !content.contains("```") && !content.contains("~~~") {
        return vec![Block::Text(content)];
    }

    let mut out = Vec::new();
    let mut open: Option<Open<'_>> = None;
    let mut text_start = 0;
    let mut i = 0;
    while i < content.len() {
        let end = content[i..].find('\n').map(|n| i + n).unwrap_or(content.len());
        let line = content[i..end].trim_end_matches('\r');
        match open {
            Some(ref fence) if closes(line, fence.ch, fence.len) => {
                let code = trim_one_newline(&content[fence.start..i]);
                out.push(Block::Code { lang: fence.lang, code });
                open = None;
                text_start = (end + 1).min(content.len());
            }
            Some(_) => {}
            None => {
                if let Some((ch, len, lang)) = opens(line) {
                    let text = text_body(&content[text_start..i]);
                    if !text.trim().is_empty() {
                        out.push(Block::Text(text));
                    }
                    open = Some(Open { ch, len, lang, start: (end + 1).min(content.len()) });
                }
            }
        }
        i = (end + 1).min(content.len());
    }
    match open {
        Some(fence) => out.push(Block::Code { lang: fence.lang, code: trim_one_newline(&content[fence.start..]) }),
        None => {
            let text = text_body(&content[text_start..]);
            if !text.trim().is_empty() {
                out.push(Block::Text(text));
            }
        }
    }
    if out.is_empty() {
        out.push(Block::Text(content));
    }
    out
}

struct Open<'a> {
    ch: char,
    len: usize,
    lang: Option<&'a str>,
    /// Byte offset where the code body begins.
    start: usize,
}

/// Up to three spaces of indent, then three or more backticks/tildes. A
/// backtick fence's info string may not contain backticks.
fn opens(line: &str) -> Option<(char, usize, Option<&str>)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let rest = &line[indent..];
    let ch = rest.chars().next().filter(|c| *c == '`' || *c == '~')?;
    let len = rest.chars().take_while(|c| *c == ch).count();
    if len < 3 {
        return None;
    }
    let info = &rest[len..];
    if ch == '`' && info.contains('`') {
        return None;
    }
    let lang = info
        .split_whitespace()
        .next()
        .map(|word| word.trim_matches(|c: char| matches!(c, '{' | '}' | '.' | ',')))
        .filter(|word| !word.is_empty() && word.len() <= 24);
    Some((ch, len, lang))
}

fn closes(line: &str, ch: char, at_least: usize) -> bool {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return false;
    }
    let rest = &line[indent..];
    let len = rest.chars().take_while(|c| *c == ch).count();
    len >= at_least && rest[len..].trim().is_empty()
}

fn trim_one_newline(text: &str) -> &str {
    text.strip_suffix("\r\n").or_else(|| text.strip_suffix('\n')).unwrap_or(text)
}

/// Text next to a fence loses the structural newline that separated it, so
/// the rendered blocks sit at the column's own spacing instead of a gap.
fn text_body(text: &str) -> &str {
    let text = text.strip_prefix("\r\n").or_else(|| text.strip_prefix('\n')).unwrap_or(text);
    text.strip_suffix("\r\n").or_else(|| text.strip_suffix('\n')).unwrap_or(text)
}

/// Syntax-highlighted spans for one code block. Unknown or unlabelled
/// languages still get strings, numbers and C-style comments coloured.
pub(super) fn spans(code: &str, lang: Option<&str>) -> Vec<Span<'static, Message>> {
    let profile = Profile::for_lang(lang);
    let mut spans: Vec<Span<'static, Message>> = Vec::new();
    let mut plain_from = 0;
    let mut i = 0;
    while i < code.len() {
        match token_at(code, i, &profile) {
            Some((end, kind)) if end > i => {
                if let Some(kind) = kind {
                    if plain_from < i {
                        spans.push(plain(&code[plain_from..i]));
                    }
                    spans.push(span(code[i..end].to_string()).color(kind.color()));
                    plain_from = end;
                }
                i = end;
            }
            _ => i += char_len(code, i),
        }
    }
    if plain_from < code.len() {
        spans.push(plain(&code[plain_from..]));
    }
    if spans.is_empty() {
        spans.push(plain(""));
    }
    spans
}

fn plain(text: &str) -> Span<'static, Message> {
    span(text.to_string()).color(theme::GREEN_SOFT)
}

fn char_len(s: &str, i: usize) -> usize {
    s[i..].chars().next().map_or(1, char::len_utf8)
}

fn token_at(s: &str, i: usize, profile: &Profile) -> Option<(usize, Option<Kind>)> {
    let rest = &s[i..];
    let prev = s[..i].chars().next_back();

    if let Some((open, close)) = profile.block {
        if let Some(body) = rest.strip_prefix(open) {
            let end = body.find(close).map_or(s.len(), |n| i + open.len() + n + close.len());
            return Some((end, Some(Kind::Comment)));
        }
    }

    for marker in profile.line {
        if rest.starts_with(marker) {
            if *marker == "#" && !at_word_start(prev) {
                continue;
            }
            let end = rest.find('\n').map_or(s.len(), |n| i + n);
            return Some((end, Some(Kind::Comment)));
        }
    }

    let c = rest.chars().next()?;

    if profile.raw_strings && (c == 'r' || (c == 'b' && rest[1..].starts_with('r'))) {
        if let Some(end) = raw_string_end(s, i) {
            return Some((end, Some(Kind::String)));
        }
    }

    if c == '"' || c == '\'' || c == '`' {
        let char_literal = c == '\'' && profile.char_literals && char_literal_end(s, i).is_some();
        let lifetime = c == '\'' && profile.char_literals && !char_literal;
        if !lifetime {
            let triple = profile.triple_quotes;
            if let Some(end) = quoted_end(s, i, c, triple) {
                return Some((end, Some(Kind::String)));
            }
        }
    }

    if c.is_ascii_digit() {
        let bytes = s.as_bytes();
        let mut end = i;
        while end < bytes.len() {
            let b = bytes[end];
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' {
                if b == b'.' && bytes.get(end + 1) == Some(&b'.') {
                    break;
                }
                end += 1;
            } else if (b == b'+' || b == b'-') && end > i && matches!(bytes[end - 1], b'e' | b'E' | b'p' | b'P') {
                end += 1;
            } else {
                break;
            }
        }
        return Some((end, Some(Kind::Number)));
    }

    if c.is_alphabetic() || c == '_' {
        let mut end = i;
        while end < s.len() {
            let ch = s[end..].chars().next()?;
            if ch.is_alphanumeric() || ch == '_' {
                end += ch.len_utf8();
            } else {
                break;
            }
        }
        let word = &s[i..end];
        if profile.keywords.iter().any(|k| k.eq_ignore_ascii_case(word)) {
            return Some((end, Some(Kind::Keyword)));
        }
        let mut after = end;
        while after < s.len() && s.as_bytes()[after].is_ascii_whitespace() {
            after += 1;
        }
        if s.as_bytes().get(after) == Some(&b'(') {
            return Some((end, Some(Kind::Function)));
        }
        // Skip the whole identifier: colouring it as plain would only add
        // spans, and skipping keeps the scanner linear.
        return Some((end, None));
    }

    None
}

fn at_word_start(prev: Option<char>) -> bool {
    prev.is_none_or(|c| c.is_whitespace() || matches!(c, '(' | ')' | '{' | '}' | '[' | ']' | ';' | ','))
}

/// `end` is just past the closing quote; unterminated strings stop at the
/// newline (or at the end of the block).
fn quoted_end(s: &str, i: usize, quote: char, triple_quotes: bool) -> Option<usize> {
    let bytes = s.as_bytes();
    let q = quote as u8;
    let triple = triple_quotes && quote != '`' && bytes.get(i + 1) == Some(&q) && bytes.get(i + 2) == Some(&q);
    let delim = if triple { 3 } else { 1 };
    let mut end = i + delim;
    while end < bytes.len() {
        match bytes[end] {
            b'\\' => {
                end += 1;
                if end < bytes.len() {
                    end += char_len(s, end);
                }
            }
            b'\n' if !triple && quote != '`' => return Some(end),
            b if b == q => {
                if triple {
                    if bytes.get(end + 1) == Some(&q) && bytes.get(end + 2) == Some(&q) {
                        return Some(end + 3);
                    }
                } else {
                    return Some(end + 1);
                }
            }
            _ => end += char_len(s, end),
        }
    }
    Some(bytes.len())
}

/// Rust character literals: `'a'`, `'\n'`, `'\u{1F980}'`. A bare lifetime
/// (`'a`) has no closing quote and is left plain.
fn char_literal_end(s: &str, i: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut end = i + 1;
    let limit = bytes.len().min(i + 16);
    while end < limit {
        match bytes[end] {
            b'\\' => {
                end += 1;
                if end < bytes.len() {
                    end += char_len(s, end);
                }
            }
            b'\'' => return Some(end + 1),
            b'\n' => return None,
            _ => end += char_len(s, end),
        }
    }
    None
}

/// Rust raw strings: `r"..."`, `r#"..."#`, `br##"..."##`.
fn raw_string_end(s: &str, i: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut pos = i;
    if bytes.get(pos) == Some(&b'b') {
        pos += 1;
    }
    if bytes.get(pos) != Some(&b'r') {
        return None;
    }
    pos += 1;
    let mut hashes = 0;
    while bytes.get(pos) == Some(&b'#') {
        hashes += 1;
        pos += 1;
    }
    if bytes.get(pos) != Some(&b'"') {
        return None;
    }
    pos += 1;
    while pos < bytes.len() {
        if bytes[pos] == b'"' {
            let after = pos + 1;
            let closes = after + hashes <= bytes.len() && bytes[after..after + hashes].iter().all(|b| *b == b'#');
            if closes {
                return Some(after + hashes);
            }
        }
        pos += char_len(s, pos);
    }
    Some(bytes.len())
}

#[derive(Clone, Copy)]
enum Kind {
    Comment,
    String,
    Keyword,
    Function,
    Number,
}

impl Kind {
    fn color(self) -> Color {
        match self {
            Self::Comment => theme::CODE_COMMENT,
            Self::String => theme::CODE_STRING,
            Self::Keyword => theme::CODE_KEYWORD,
            Self::Function => theme::CODE_FUNCTION,
            Self::Number => theme::CODE_NUMBER,
        }
    }
}

#[derive(Clone, Copy)]
struct Profile {
    line: &'static [&'static str],
    block: Option<(&'static str, &'static str)>,
    keywords: &'static [&'static str],
    raw_strings: bool,
    char_literals: bool,
    triple_quotes: bool,
}

const PLAIN: Profile =
    Profile { line: &[], block: None, keywords: &[], raw_strings: false, char_literals: false, triple_quotes: false };

const C_STYLE: Profile = Profile {
    line: &["//"],
    block: Some(("/*", "*/")),
    keywords: C_FAMILY,
    raw_strings: false,
    char_literals: true,
    triple_quotes: false,
};

impl Profile {
    fn for_lang(lang: Option<&str>) -> Self {
        let lang = lang.unwrap_or_default().to_ascii_lowercase();
        match lang.as_str() {
            "rust" | "rs" => Profile {
                line: &["//"],
                block: Some(("/*", "*/")),
                keywords: RUST,
                raw_strings: true,
                char_literals: true,
                triple_quotes: false,
            },
            "python" | "py" => Profile { line: &["#"], keywords: PYTHON, triple_quotes: true, ..PLAIN },
            "javascript" | "js" | "mjs" | "jsx" | "typescript" | "ts" | "tsx" => {
                Profile { line: &["//"], block: Some(("/*", "*/")), keywords: JS, ..PLAIN }
            }
            "c" | "h" | "cpp" | "cc" | "cxx" | "hpp" | "cs" | "csharp" | "java" | "kotlin" | "kt" | "scala"
            | "dart" => C_STYLE,
            "go" => Profile {
                line: &["//"],
                block: Some(("/*", "*/")),
                keywords: GO,
                raw_strings: false,
                char_literals: true,
                triple_quotes: false,
            },
            "swift" => Profile { keywords: SWIFT, ..C_STYLE },
            "ruby" | "rb" => Profile { line: &["#"], keywords: RUBY, ..PLAIN },
            "shell" | "sh" | "bash" | "zsh" => Profile { line: &["#"], keywords: SHELL, ..PLAIN },
            "powershell" | "ps1" => Profile { line: &["#"], block: Some(("<#", "#>")), keywords: POWERSHELL, ..PLAIN },
            "sql" => Profile { line: &["--"], block: Some(("/*", "*/")), keywords: SQL, ..PLAIN },
            "html" | "htm" | "xml" | "svg" => Profile { block: Some(("<!--", "-->")), keywords: HTML, ..PLAIN },
            "css" | "scss" | "less" => Profile { block: Some(("/*", "*/")), keywords: CSS, ..PLAIN },
            "json" => Profile { keywords: JSON, ..PLAIN },
            "toml" => Profile { line: &["#"], keywords: JSON, ..PLAIN },
            "yaml" | "yml" => Profile { line: &["#"], keywords: JSON, ..PLAIN },
            "lua" => Profile { line: &["--"], keywords: LUA, ..PLAIN },
            "r" => Profile { line: &["#"], keywords: R, ..PLAIN },
            "zig" => Profile { line: &["//"], keywords: ZIG, ..PLAIN },
            "haskell" | "hs" => {
                Profile { line: &["--"], block: Some(("{-", "-}")), keywords: HASKELL, char_literals: true, ..PLAIN }
            }
            "elixir" | "ex" | "exs" => Profile { line: &["#"], keywords: ELIXIR, triple_quotes: true, ..PLAIN },
            _ => PLAIN,
        }
    }
}

const RUST: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn",
    "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self",
    "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while", "yield",
];

const PYTHON: &[&str] = &[
    "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else", "except",
    "False", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "None", "nonlocal", "not", "or",
    "pass", "raise", "return", "True", "try", "while", "with", "yield",
];

const JS: &[&str] = &[
    "as",
    "async",
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "from",
    "function",
    "if",
    "implements",
    "import",
    "in",
    "instanceof",
    "interface",
    "let",
    "new",
    "null",
    "of",
    "private",
    "protected",
    "public",
    "return",
    "static",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "type",
    "typeof",
    "undefined",
    "var",
    "void",
    "while",
    "with",
    "yield",
];

const C_FAMILY: &[&str] = &[
    "abstract",
    "assert",
    "async",
    "auto",
    "await",
    "bool",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "decimal",
    "default",
    "delegate",
    "delete",
    "do",
    "double",
    "else",
    "enum",
    "event",
    "extends",
    "extern",
    "false",
    "final",
    "finally",
    "float",
    "for",
    "friend",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "lock",
    "long",
    "namespace",
    "native",
    "new",
    "null",
    "nullptr",
    "object",
    "operator",
    "out",
    "package",
    "params",
    "private",
    "protected",
    "public",
    "readonly",
    "record",
    "ref",
    "return",
    "sealed",
    "short",
    "signed",
    "sizeof",
    "static",
    "string",
    "struct",
    "super",
    "switch",
    "synchronized",
    "template",
    "this",
    "throw",
    "throws",
    "transient",
    "true",
    "try",
    "typedef",
    "uint",
    "ulong",
    "union",
    "unsigned",
    "unsafe",
    "ushort",
    "using",
    "value",
    "var",
    "virtual",
    "void",
    "volatile",
    "where",
    "while",
    "yield",
];

const GO: &[&str] = &[
    "break",
    "case",
    "chan",
    "const",
    "continue",
    "default",
    "defer",
    "else",
    "fallthrough",
    "false",
    "for",
    "func",
    "go",
    "goto",
    "if",
    "import",
    "interface",
    "map",
    "nil",
    "package",
    "range",
    "return",
    "select",
    "struct",
    "switch",
    "true",
    "type",
    "var",
];

const SWIFT: &[&str] = &[
    "as",
    "associatedtype",
    "break",
    "case",
    "catch",
    "class",
    "continue",
    "default",
    "defer",
    "deinit",
    "do",
    "else",
    "enum",
    "extension",
    "fallthrough",
    "false",
    "fileprivate",
    "for",
    "func",
    "guard",
    "if",
    "import",
    "in",
    "indirect",
    "init",
    "inout",
    "internal",
    "is",
    "let",
    "nil",
    "open",
    "operator",
    "private",
    "protocol",
    "public",
    "repeat",
    "rethrows",
    "return",
    "self",
    "Self",
    "static",
    "struct",
    "subscript",
    "super",
    "switch",
    "throw",
    "throws",
    "true",
    "try",
    "typealias",
    "var",
    "where",
    "while",
];

const RUBY: &[&str] = &[
    "alias", "and", "begin", "break", "case", "class", "def", "defined?", "do", "else", "elsif", "end", "ensure",
    "false", "for", "if", "in", "module", "next", "nil", "not", "or", "redo", "rescue", "retry", "return", "self",
    "super", "then", "true", "undef", "unless", "until", "when", "while", "yield",
];

const SHELL: &[&str] = &[
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "function", "in",
    "select", "time", "coproc", "local", "export", "readonly", "return", "break", "continue",
];

const POWERSHELL: &[&str] = &[
    "begin",
    "break",
    "catch",
    "class",
    "continue",
    "data",
    "do",
    "dynamicparam",
    "else",
    "elseif",
    "end",
    "enum",
    "exit",
    "filter",
    "finally",
    "for",
    "foreach",
    "from",
    "function",
    "hidden",
    "if",
    "in",
    "param",
    "process",
    "return",
    "static",
    "switch",
    "throw",
    "trap",
    "try",
    "until",
    "using",
    "var",
    "while",
];

const SQL: &[&str] = &[
    "select",
    "from",
    "where",
    "and",
    "or",
    "not",
    "null",
    "insert",
    "into",
    "values",
    "update",
    "set",
    "delete",
    "create",
    "table",
    "drop",
    "alter",
    "join",
    "left",
    "right",
    "inner",
    "outer",
    "on",
    "group",
    "by",
    "order",
    "having",
    "limit",
    "offset",
    "as",
    "distinct",
    "union",
    "all",
    "case",
    "when",
    "then",
    "else",
    "end",
    "primary",
    "key",
    "foreign",
    "references",
    "index",
    "view",
    "with",
    "begin",
    "commit",
    "rollback",
];

const HTML: &[&str] = &["html", "head", "body", "div", "span", "class", "id", "href", "src", "style", "script"];

const CSS: &[&str] = &["important", "media", "import", "supports", "keyframes", "from", "to"];

const JSON: &[&str] = &["true", "false", "null"];

const LUA: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if", "in", "local", "nil",
    "not", "or", "repeat", "return", "then", "true", "until", "while",
];

const R: &[&str] = &[
    "if",
    "else",
    "repeat",
    "while",
    "function",
    "for",
    "in",
    "next",
    "break",
    "TRUE",
    "FALSE",
    "NULL",
    "Inf",
    "NaN",
    "NA",
    "NA_integer_",
    "NA_real_",
    "NA_character_",
];

const ZIG: &[&str] = &[
    "align",
    "allowzero",
    "and",
    "anyframe",
    "anytype",
    "asm",
    "async",
    "await",
    "break",
    "catch",
    "comptime",
    "const",
    "continue",
    "defer",
    "else",
    "enum",
    "errdefer",
    "error",
    "export",
    "extern",
    "fn",
    "for",
    "if",
    "inline",
    "noalias",
    "noinline",
    "nosuspend",
    "opaque",
    "or",
    "orelse",
    "packed",
    "pub",
    "resume",
    "return",
    "struct",
    "suspend",
    "switch",
    "test",
    "threadlocal",
    "try",
    "union",
    "unreachable",
    "usingnamespace",
    "var",
    "volatile",
    "while",
];

const HASKELL: &[&str] = &[
    "case", "class", "data", "default", "deriving", "do", "else", "if", "import", "in", "infix", "infixl", "infixr",
    "instance", "let", "module", "newtype", "of", "then", "type", "where",
];

const ELIXIR: &[&str] = &[
    "after",
    "alias",
    "and",
    "case",
    "catch",
    "cond",
    "def",
    "defmodule",
    "defp",
    "do",
    "else",
    "end",
    "false",
    "fn",
    "for",
    "if",
    "import",
    "in",
    "nil",
    "not",
    "or",
    "raise",
    "receive",
    "require",
    "rescue",
    "true",
    "try",
    "unless",
    "use",
    "when",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_and_inline_code_stay_text() {
        assert_eq!(blocks("hello `x` world"), [Block::Text("hello `x` world")]);
        assert_eq!(blocks("no fences at all"), [Block::Text("no fences at all")]);
    }

    #[test]
    fn splits_multiple_fenced_blocks_and_languages() {
        let body = "before\n```rust\nfn main() {}\n```\nmiddle\n~~~python\nprint(1)\n~~~\nafter";
        assert_eq!(
            blocks(body),
            [
                Block::Text("before"),
                Block::Code { lang: Some("rust"), code: "fn main() {}" },
                Block::Text("middle"),
                Block::Code { lang: Some("python"), code: "print(1)" },
                Block::Text("after"),
            ]
        );
    }

    #[test]
    fn unclosed_and_indented_fences() {
        assert_eq!(blocks("```py\nx = 1"), [Block::Code { lang: Some("py"), code: "x = 1" }]);
        assert_eq!(blocks("  ```js\nx\n  ```"), [Block::Code { lang: Some("js"), code: "x" }]);
        assert_eq!(
            blocks("    ```js\nx\n    ```"),
            [Block::Text("    ```js\nx\n    ```")],
            "4 spaces is code, not a fence"
        );
    }

    #[test]
    fn a_longer_fence_contains_shorter_ones() {
        let body = "````md\n```rust\nfn x() {}\n```\n````";
        assert_eq!(blocks(body), [Block::Code { lang: Some("md"), code: "```rust\nfn x() {}\n```" }]);
    }

    #[test]
    fn handles_crlf() {
        assert_eq!(
            blocks("hi\r\n```rs\r\nlet x = 1;\r\n```\r\nbye"),
            [Block::Text("hi"), Block::Code { lang: Some("rs"), code: "let x = 1;" }, Block::Text("bye"),]
        );
    }

    fn highlight(code: &str, lang: &str) -> Vec<(String, Option<Color>)> {
        spans(code, Some(lang)).into_iter().map(|s| (s.text.into_owned(), s.color)).collect()
    }

    #[test]
    fn colours_keywords_strings_comments_and_numbers() {
        let out = highlight("fn main() { let x = 42; // hi\n}", "rust");
        assert!(out.iter().any(|(t, c)| t == "fn" && *c == Some(theme::CODE_KEYWORD)));
        assert!(out.iter().any(|(t, c)| t == "42" && *c == Some(theme::CODE_NUMBER)));
        assert!(out.iter().any(|(t, c)| t == "// hi" && *c == Some(theme::CODE_COMMENT)));
        let out = highlight("let s = \"a \\\" b\";", "rust");
        assert!(out.iter().any(|(t, c)| t == "\"a \\\" b\"" && *c == Some(theme::CODE_STRING)));
    }

    #[test]
    fn lifetimes_are_not_strings() {
        let out = highlight("fn f<'a>(x: &'a str) -> &'a str { x }", "rust");
        assert!(!out.iter().any(|(t, c)| t == "'a" && *c == Some(theme::CODE_STRING)));
        let out = highlight("let c = 'a';", "rust");
        assert!(out.iter().any(|(t, c)| t == "'a'" && *c == Some(theme::CODE_STRING)));
        let out = highlight("'x'", "rust");
        assert!(out.iter().any(|(t, c)| t == "'x'" && *c == Some(theme::CODE_STRING)));
    }

    #[test]
    fn python_hashes_and_triple_quotes() {
        let out = highlight("# note\nx = \"\"\"a\nb\"\"\"", "python");
        assert!(out.iter().any(|(t, c)| t == "# note" && *c == Some(theme::CODE_COMMENT)));
        assert!(out.iter().any(|(t, c)| t == "\"\"\"a\nb\"\"\"" && *c == Some(theme::CODE_STRING)));
    }
}
