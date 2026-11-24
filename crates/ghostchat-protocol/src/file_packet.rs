//! File transfer payload (`MessageType::FileTransfer`, and the body of
//! `NoisePayloadType::PrivateFile`): TLVs 0x01 name, 0x02 size (4 bytes),
//! 0x03 MIME, 0x04 content (4-byte length). Mirrors iOS `BitchatFilePacket`
//! plus its MIME allow-list and magic-byte checks.

/// iOS `FileTransferLimits.maxPayloadBytes`.
pub const MAX_FILE_BYTES: usize = 1024 * 1024;

const TAG_NAME: u8 = 0x01;
const TAG_SIZE: u8 = 0x02;
const TAG_MIME: u8 = 0x03;
const TAG_CONTENT: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePacket {
    pub name: Option<String>,
    pub mime: Option<String>,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Image,
    Audio,
    File,
}

impl MediaKind {
    /// Chat-line prefix iOS uses for media (`[image] `, `[voice] `, `[file] `).
    pub fn label(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Audio => "voice",
            Self::File => "file",
        }
    }
}

impl FilePacket {
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.content.is_empty() || self.content.len() > MAX_FILE_BYTES {
            return None;
        }
        let mut out = Vec::with_capacity(self.content.len() + 64);
        if let Some(name) = self.name.as_deref().filter(|n| n.len() <= u16::MAX as usize) {
            out.push(TAG_NAME);
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        out.push(TAG_SIZE);
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&(self.content.len() as u32).to_be_bytes());
        if let Some(mime) = self.mime.as_deref().filter(|m| m.len() <= u16::MAX as usize) {
            out.push(TAG_MIME);
            out.extend_from_slice(&(mime.len() as u16).to_be_bytes());
            out.extend_from_slice(mime.as_bytes());
        }
        out.push(TAG_CONTENT);
        out.extend_from_slice(&(self.content.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.content);
        Some(out)
    }

    /// Tolerates the legacy 8-byte size and 2-byte content length, like iOS.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut cur = 0usize;
        let (mut name, mut mime, mut content) = (None, None, Vec::new());
        let read_len = |cur: &mut usize, bytes: usize| -> Option<usize> {
            let slice = data.get(*cur..*cur + bytes)?;
            *cur += bytes;
            Some(slice.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize))
        };
        while cur < data.len() {
            let tag = data[cur];
            cur += 1;
            let len = if tag == TAG_CONTENT {
                let snapshot = cur;
                match read_len(&mut cur, 4) {
                    Some(n) if n <= data.len() - cur => n,
                    _ => {
                        cur = snapshot;
                        read_len(&mut cur, 2)?
                    }
                }
            } else {
                read_len(&mut cur, 2)?
            };
            let value = data.get(cur..cur.checked_add(len)?)?;
            cur += len;
            match tag {
                TAG_NAME => name = String::from_utf8(value.to_vec()).ok(),
                TAG_SIZE => {
                    if (len == 4 || len == 8)
                        && value.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64) > MAX_FILE_BYTES as u64
                    {
                        return None;
                    }
                }
                TAG_MIME => mime = String::from_utf8(value.to_vec()).ok(),
                TAG_CONTENT => {
                    if content.len() + value.len() > MAX_FILE_BYTES {
                        return None;
                    }
                    content.extend_from_slice(value);
                }
                _ => {}
            }
        }
        if content.is_empty() {
            return None;
        }
        Some(Self { name, mime, content })
    }

    /// Accept only allow-listed MIME types whose bytes look like that type.
    /// Returns the kind and the canonical file extension.
    pub fn validate(&self) -> Option<(MediaKind, &'static str)> {
        let (kind, ext) = mime_info(self.mime.as_deref()?)?;
        magic_matches(ext, &self.content).then_some((kind, ext))
    }
}

/// Every extension `mime_for_extension` accepts, for file pickers and hints.
pub const SENDABLE_EXTENSIONS: &[&str] = &[
    // Photos, voice notes and documents.
    "jpg", "jpeg", "png", "gif", "webp", "m4a", "mp3", "wav", "ogg",
    "pdf", // Notebooks and source files. Users share code in chat, so these travel
    // the same 1 MiB BitChat file path as everything else.
    "ipynb", "rs", "py", "js", "mjs", "jsx", "ts", "tsx", "c", "h", "cpp", "hpp", "cs", "java", "kt", "go", "rb", "php",
    "swift", "sh", "ps1", "sql", "html", "htm", "css", "json", "toml", "yaml", "yml", "xml", "md", "txt", "csv", "lua",
    "r", "scala", "dart", "zig", "hs", "ex", "exs",
];

/// MIME type for a file extension we are willing to send.
pub fn mime_for_extension(ext: &str) -> Option<&'static str> {
    Some(match ext.to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "m4a" => "audio/m4a",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        "ipynb" => "application/x-ipynb+json",
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        "js" | "mjs" => "application/javascript",
        "jsx" => "text/x-jsx",
        "ts" => "text/x-typescript",
        "tsx" => "text/x-tsx",
        "c" => "text/x-c",
        "h" => "text/x-chdr",
        "cpp" => "text/x-c++src",
        "hpp" => "text/x-c++hdr",
        "cs" => "text/x-csharp",
        "java" => "text/x-java-source",
        "kt" => "text/x-kotlin",
        "go" => "text/x-go",
        "rb" => "text/x-ruby",
        "php" => "text/x-php",
        "swift" => "text/x-swift",
        "sh" => "text/x-shellscript",
        "ps1" => "text/x-powershell",
        "sql" => "application/sql",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "json" => "application/json",
        "toml" => "application/toml",
        "yaml" | "yml" => "application/yaml",
        "xml" => "text/xml",
        "md" => "text/markdown",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "lua" => "text/x-lua",
        "r" => "text/x-r",
        "scala" => "text/x-scala",
        "dart" => "text/x-dart",
        "zig" => "text/x-zig",
        "hs" => "text/x-haskell",
        "ex" | "exs" => "text/x-elixir",
        _ => return None,
    })
}

fn mime_info(mime: &str) -> Option<(MediaKind, &'static str)> {
    Some(match mime.to_ascii_lowercase().as_str() {
        "image/jpeg" | "image/jpg" => (MediaKind::Image, "jpg"),
        "image/png" => (MediaKind::Image, "png"),
        "image/gif" => (MediaKind::Image, "gif"),
        "image/webp" => (MediaKind::Image, "webp"),
        "audio/mp4" | "audio/m4a" | "audio/aac" | "audio/x-m4a" => (MediaKind::Audio, "m4a"),
        "audio/mpeg" | "audio/mp3" => (MediaKind::Audio, "mp3"),
        "audio/wav" | "audio/x-wav" => (MediaKind::Audio, "wav"),
        "audio/ogg" => (MediaKind::Audio, "ogg"),
        "application/pdf" => (MediaKind::File, "pdf"),
        "application/octet-stream" => (MediaKind::File, "bin"),
        "application/x-ipynb+json" => (MediaKind::File, "ipynb"),
        "text/x-rust" => (MediaKind::File, "rs"),
        "text/x-python" => (MediaKind::File, "py"),
        "application/javascript" | "text/javascript" => (MediaKind::File, "js"),
        "text/x-jsx" => (MediaKind::File, "jsx"),
        "text/x-typescript" => (MediaKind::File, "ts"),
        "text/x-tsx" => (MediaKind::File, "tsx"),
        "text/x-c" => (MediaKind::File, "c"),
        "text/x-chdr" => (MediaKind::File, "h"),
        "text/x-c++src" => (MediaKind::File, "cpp"),
        "text/x-c++hdr" => (MediaKind::File, "hpp"),
        "text/x-csharp" => (MediaKind::File, "cs"),
        "text/x-java-source" => (MediaKind::File, "java"),
        "text/x-kotlin" => (MediaKind::File, "kt"),
        "text/x-go" => (MediaKind::File, "go"),
        "text/x-ruby" => (MediaKind::File, "rb"),
        "text/x-php" => (MediaKind::File, "php"),
        "text/x-swift" => (MediaKind::File, "swift"),
        "text/x-shellscript" => (MediaKind::File, "sh"),
        "text/x-powershell" => (MediaKind::File, "ps1"),
        "application/sql" => (MediaKind::File, "sql"),
        "text/html" => (MediaKind::File, "html"),
        "text/css" => (MediaKind::File, "css"),
        "application/json" => (MediaKind::File, "json"),
        "application/toml" => (MediaKind::File, "toml"),
        "application/yaml" | "text/yaml" => (MediaKind::File, "yaml"),
        "text/xml" => (MediaKind::File, "xml"),
        "text/markdown" => (MediaKind::File, "md"),
        "text/plain" => (MediaKind::File, "txt"),
        "text/csv" => (MediaKind::File, "csv"),
        "text/x-lua" => (MediaKind::File, "lua"),
        "text/x-r" => (MediaKind::File, "r"),
        "text/x-scala" => (MediaKind::File, "scala"),
        "text/x-dart" => (MediaKind::File, "dart"),
        "text/x-zig" => (MediaKind::File, "zig"),
        "text/x-haskell" => (MediaKind::File, "hs"),
        "text/x-elixir" => (MediaKind::File, "ex"),
        _ => return None,
    })
}

fn magic_matches(ext: &str, d: &[u8]) -> bool {
    let starts = |p: &[u8]| d.starts_with(p);
    let riff = |tag: &[u8]| d.len() >= 12 && starts(b"RIFF") && &d[8..12] == tag;
    match ext {
        "jpg" => starts(&[0xFF, 0xD8, 0xFF]),
        "png" => starts(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]),
        "gif" => starts(b"GIF87a") || starts(b"GIF89a"),
        "webp" => riff(b"WEBP"),
        "wav" => riff(b"WAVE"),
        "m4a" => d.len() > 100,
        "mp3" => starts(b"ID3") || (d.len() >= 2 && d[0] == 0xFF && d[1] & 0xE0 == 0xE0),
        "ogg" => starts(b"OggS"),
        "pdf" => starts(b"%PDF"),
        "bin" => !d.is_empty(),
        "ipynb" => notebook_bytes(d),
        "rs" | "py" | "js" | "mjs" | "jsx" | "ts" | "tsx" | "c" | "h" | "cpp" | "hpp" | "cs" | "java" | "kt" | "go"
        | "rb" | "php" | "swift" | "sh" | "ps1" | "sql" | "html" | "htm" | "css" | "json" | "toml" | "yaml" | "yml"
        | "xml" | "md" | "txt" | "csv" | "lua" | "r" | "scala" | "dart" | "zig" | "hs" | "ex" | "exs" => text_bytes(d),
        _ => false,
    }
}

/// Text files must be UTF-8 (and not smuggle NULs); anything else is treated
/// as binary even when it carries a code extension.
fn text_bytes(d: &[u8]) -> bool {
    !d.is_empty() && !d.contains(&0) && std::str::from_utf8(d).is_ok()
}

/// A notebook is a JSON object with `cells` and `nbformat`; requiring both
/// keeps renamed binaries and arbitrary JSON out of the notebook path.
fn notebook_bytes(d: &[u8]) -> bool {
    if !text_bytes(d) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(d) else {
        return false;
    };
    let text = text.trim();
    text.starts_with('{') && text.ends_with('}') && text.contains("\"cells\"") && text.contains("\"nbformat\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png() -> FilePacket {
        let mut content = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        content.extend_from_slice(&[0u8; 300]);
        FilePacket { name: Some("img_1.png".into()), mime: Some("image/png".into()), content }
    }

    #[test]
    fn roundtrips_and_validates() {
        let file = png();
        let decoded = FilePacket::decode(&file.encode().unwrap()).unwrap();
        assert_eq!(decoded, file);
        assert_eq!(decoded.validate(), Some((MediaKind::Image, "png")));
    }

    #[test]
    fn sendable_extensions_all_have_a_mime() {
        for ext in SENDABLE_EXTENSIONS {
            assert!(mime_for_extension(ext).is_some(), "{ext}");
        }
        assert!(mime_for_extension("exe").is_none());
    }

    #[test]
    fn accepts_code_files_and_notebooks() {
        let mut file = FilePacket {
            name: Some("main.rs".into()),
            mime: Some("text/x-rust".into()),
            content: b"fn main() {}\n".to_vec(),
        };
        assert_eq!(file.validate(), Some((MediaKind::File, "rs")));
        file.mime = Some("application/json".into());
        file.content = br#"{"a": 1}"#.to_vec();
        assert_eq!(file.validate(), Some((MediaKind::File, "json")));
        file.mime = Some("application/x-ipynb+json".into());
        file.content = br#"{"cells": [], "nbformat": 4, "nbformat_minor": 5, "metadata": {}}"#.to_vec();
        assert_eq!(file.validate(), Some((MediaKind::File, "ipynb")));
    }

    #[test]
    fn rejects_binary_wearing_a_code_extension() {
        let mut file =
            FilePacket { name: Some("main.py".into()), mime: Some("text/x-python".into()), content: vec![0xFF, 0x00] };
        assert!(file.validate().is_none());
        file.mime = Some("application/x-ipynb+json".into());
        file.content = br#"{"cells": []}"#.to_vec();
        assert!(file.validate().is_none(), "a notebook needs nbformat");
    }

    #[test]
    fn rejects_mismatched_magic_and_unknown_mime() {
        let mut file = png();
        file.mime = Some("image/jpeg".into());
        assert!(file.validate().is_none());
        file.mime = Some("application/x-msdownload".into());
        assert!(file.validate().is_none());
        file.mime = None;
        assert!(file.validate().is_none());
    }

    #[test]
    fn accepts_legacy_two_byte_content_length() {
        let mut data = vec![TAG_MIME, 0, 8];
        data.extend_from_slice(b"text/raw");
        data.extend_from_slice(&[TAG_CONTENT, 0, 3, b'a', b'b', b'c']);
        let file = FilePacket::decode(&data).unwrap();
        assert_eq!(file.content, b"abc");
    }

    #[test]
    fn rejects_oversize_and_truncated() {
        let mut big = png();
        big.content = vec![0; MAX_FILE_BYTES + 1];
        assert!(big.encode().is_none());
        assert!(FilePacket::decode(&[TAG_NAME, 0, 9, b'x']).is_none(), "value shorter than its length");
        assert!(FilePacket::decode(&[TAG_SIZE, 0, 4, 0, 0x20, 0, 0]).is_none(), "declared size over 1 MiB");
        assert!(FilePacket::decode(&[]).is_none());
    }
}
