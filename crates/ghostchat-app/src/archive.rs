//! The one executable out of a release archive: a zip on Windows, a tar.gz
//! on Linux. The release assets are small and written by tools that put the
//! sizes in the headers, so zip64 and data descriptors are not handled.

use anyhow::{anyhow, bail, Result};
use std::io::Read;

/// The platform's executable from its release archive.
#[cfg(windows)]
pub fn binary(archive: &[u8]) -> Result<Vec<u8>> {
    zip_entry(archive, "ghostchat.exe")
}

#[cfg(not(windows))]
pub fn binary(archive: &[u8]) -> Result<Vec<u8>> {
    tar_entry(archive, "ghostchat")
}

#[cfg(any(windows, test))]
fn zip_entry(archive: &[u8], wanted: &str) -> Result<Vec<u8>> {
    let eocd = find_eocd(archive)?;
    let count = u16::from_le_bytes(archive[eocd + 10..eocd + 12].try_into()?) as usize;
    let mut offset = u32::from_le_bytes(archive[eocd + 16..eocd + 20].try_into()?) as usize;
    for _ in 0..count {
        if read_u32(archive, offset)? != 0x0201_4b50 {
            bail!("the zip directory is damaged");
        }
        let method = read_u16(archive, offset + 10)?;
        let compressed = read_u32(archive, offset + 20)? as usize;
        let size = read_u32(archive, offset + 24)? as usize;
        let name_len = read_u16(archive, offset + 28)? as usize;
        let extra_len = read_u16(archive, offset + 30)? as usize;
        let comment_len = read_u16(archive, offset + 32)? as usize;
        let local = read_u32(archive, offset + 42)? as usize;
        let name = archive
            .get(offset + 46..offset + 46 + name_len)
            .ok_or_else(|| anyhow!("the zip directory is cut short"))?;
        if file_name(name) == wanted.as_bytes() {
            return zip_data(archive, local, method, compressed, size);
        }
        offset += 46 + name_len + extra_len + comment_len;
    }
    bail!("{wanted} is not in the zip")
}

#[cfg(any(windows, test))]
fn zip_data(archive: &[u8], local: usize, method: u16, compressed: usize, size: usize) -> Result<Vec<u8>> {
    if read_u32(archive, local)? != 0x0403_4b50 {
        bail!("the zip entry is damaged");
    }
    let name_len = read_u16(archive, local + 26)? as usize;
    let extra_len = read_u16(archive, local + 28)? as usize;
    let start = local + 30 + name_len + extra_len;
    let data = archive.get(start..start + compressed).ok_or_else(|| anyhow!("the zip entry is cut short"))?;
    let mut out = Vec::with_capacity(size);
    match method {
        0 => {
            out.extend_from_slice(data);
        }
        8 => {
            flate2::read::DeflateDecoder::new(data).read_to_end(&mut out)?;
        }
        other => bail!("zip compression method {other} is not supported"),
    }
    if out.len() != size {
        bail!("the zip entry has the wrong size");
    }
    Ok(out)
}

#[cfg(any(windows, test))]
fn find_eocd(archive: &[u8]) -> Result<usize> {
    if archive.len() < 22 {
        bail!("not a zip file");
    }
    let earliest = archive.len().saturating_sub(22 + usize::from(u16::MAX));
    for at in (earliest..=archive.len() - 22).rev() {
        if archive[at..at + 4] != [0x50, 0x4b, 0x05, 0x06] {
            continue;
        }
        let comment = u16::from_le_bytes([archive[at + 20], archive[at + 21]]) as usize;
        if at + 22 + comment == archive.len() {
            return Ok(at);
        }
    }
    bail!("not a zip file")
}

#[cfg(any(windows, test))]
fn read_u16(bytes: &[u8], at: usize) -> Result<u16> {
    let pair = bytes.get(at..at + 2).ok_or_else(|| anyhow!("the zip is cut short"))?;
    Ok(u16::from_le_bytes(pair.try_into().expect("two bytes")))
}

#[cfg(any(windows, test))]
fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    let quad = bytes.get(at..at + 4).ok_or_else(|| anyhow!("the zip is cut short"))?;
    Ok(u32::from_le_bytes(quad.try_into().expect("four bytes")))
}

#[cfg(any(not(windows), test))]
fn tar_entry(archive: &[u8], wanted: &str) -> Result<Vec<u8>> {
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(archive).read_to_end(&mut tar)?;
    let mut offset = 0;
    let mut long_name: Option<String> = None;
    while offset + 512 <= tar.len() {
        let header = &tar[offset..offset + 512];
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let name = c_str(&header[0..100]);
        let prefix = c_str(&header[345..500]);
        let size = octal(&header[124..136])?;
        let kind = header[156];
        let data = offset + 512;
        let body = tar.get(data..data + size).ok_or_else(|| anyhow!("the tarball is cut short"))?;
        match kind {
            b'L' => long_name = Some(String::from_utf8_lossy(body).trim_end_matches('\0').to_string()),
            b'0' | 0 => {
                let full = long_name.take().unwrap_or_else(|| {
                    if prefix.is_empty() {
                        name.to_string()
                    } else {
                        format!("{prefix}/{name}")
                    }
                });
                if file_name(full.as_bytes()) == wanted.as_bytes() {
                    return Ok(body.to_vec());
                }
            }
            _ => {}
        }
        offset = data + size.div_ceil(512) * 512;
    }
    bail!("{wanted} is not in the tarball")
}

#[cfg(any(not(windows), test))]
fn c_str(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).unwrap_or("")
}

#[cfg(any(not(windows), test))]
fn octal(bytes: &[u8]) -> Result<usize> {
    let text = std::str::from_utf8(bytes)?.trim_matches(|c: char| c == '\0' || c == ' ');
    if text.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(text, 8).map_err(|_| anyhow!("bad tar size"))
}

fn file_name(name: &[u8]) -> &[u8] {
    let at = name.iter().rposition(|&b| b == b'/' || b == b'\\').map_or(0, |i| i + 1);
    &name[at..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tar_header(name: &str, size: usize, kind: u8) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{size:011o}\0");
        header[124..136].copy_from_slice(size.as_bytes());
        header[156] = kind;
        header[257..262].copy_from_slice(b"ustar");
        header
    }

    fn tar_of(entries: &[(&str, &[u8], u8)]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, body, kind) in entries {
            tar.extend_from_slice(&tar_header(name, body.len(), *kind));
            tar.extend_from_slice(body);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.extend_from_slice(&[0u8; 1024]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn tar_reads_the_binary_and_skips_other_entries() {
        let archive = tar_of(&[("ghostchat.json", b"{}", b'0'), ("./ghostchat", b"binary", b'0')]);
        assert_eq!(tar_entry(&archive, "ghostchat").unwrap(), b"binary");
        assert!(tar_entry(&archive, "missing").is_err());
    }

    fn zip_of(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, body, deflate) in entries {
            let data = if *deflate {
                let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(body).unwrap();
                encoder.finish().unwrap()
            } else {
                body.to_vec()
            };
            let method = if *deflate { 8u16 } else { 0u16 };
            let offset = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&data);

            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(body.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let central_at = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&central_at.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn zip_reads_stored_and_deflated_entries() {
        let archive = zip_of(&[("LICENSE", b"MIT", false), ("ghostchat.exe", b"binary", true)]);
        assert_eq!(zip_entry(&archive, "ghostchat.exe").unwrap(), b"binary");
        assert!(zip_entry(&archive, "missing").is_err());
    }
}
