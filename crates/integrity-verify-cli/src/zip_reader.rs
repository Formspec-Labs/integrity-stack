// Rust guideline compliant 2026-02-21
//! Minimal STORED-only ZIP reader for deterministic-bundle archives.
//!
//! The writer side lives in `integrity-bundle`. This reader supports the
//! subset that writer emits: STORED compression only, classic ZIP32 fields,
//! single-disk archives, ASCII paths, no encryption, no zip64. Anything
//! outside that subset is rejected with a typed error so the CLI does not
//! silently misread an archive produced by another toolchain.
//!
//! Reader scope is intentionally narrow: this is not a general-purpose ZIP
//! library. If wider ZIP-reading support is needed elsewhere in the stack,
//! lift this into `integrity-bundle` as a `from_zip_bytes` constructor.

use std::fmt::{Display, Formatter};

const ZIP_LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x0403_4b50;
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;
const ZIP_COMPRESSION_STORED: u16 = 0;
const EOCD_MIN_LEN: usize = 22;

/// One ZIP entry read from a deterministic bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZipEntry {
    pub path: String,
    pub bytes: Vec<u8>,
}

/// ZIP reader error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZipReadError {
    message: String,
}

impl ZipReadError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for ZipReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ZipReadError {}

/// Parses a STORED-only deterministic ZIP archive into its entries.
///
/// # Errors
///
/// Returns an error when the archive is truncated, uses unsupported
/// compression, references a multi-disk archive, declares zip64 extensions,
/// or carries a corrupted Local File Header.
pub fn read_stored_zip(bytes: &[u8]) -> Result<Vec<ZipEntry>, ZipReadError> {
    if bytes.len() < EOCD_MIN_LEN {
        return Err(ZipReadError::new("archive shorter than EOCD record"));
    }
    let eocd_offset = find_eocd(bytes)?;
    let eocd = &bytes[eocd_offset..];
    let disk_number = read_u16(eocd, 4);
    let disk_with_central = read_u16(eocd, 6);
    let entries_on_disk = read_u16(eocd, 8);
    let entries_total = read_u16(eocd, 10);
    let central_size = read_u32(eocd, 12) as usize;
    let central_offset = read_u32(eocd, 16) as usize;
    let comment_length = read_u16(eocd, 20) as usize;

    if disk_number != 0 || disk_with_central != 0 {
        return Err(ZipReadError::new("multi-disk archives are unsupported"));
    }
    if entries_on_disk != entries_total {
        return Err(ZipReadError::new(
            "entries-on-disk does not match total entries",
        ));
    }
    if comment_length != 0 {
        return Err(ZipReadError::new("archive comments are unsupported"));
    }
    if central_offset >= bytes.len() {
        return Err(ZipReadError::new("central directory offset out of bounds"));
    }
    let central_end = central_offset
        .checked_add(central_size)
        .ok_or_else(|| ZipReadError::new("central directory size overflow"))?;
    if central_end > eocd_offset {
        return Err(ZipReadError::new("central directory size out of bounds"));
    }

    let mut cursor = central_offset;
    let mut out = Vec::with_capacity(entries_total as usize);
    for _ in 0..entries_total {
        if cursor + 46 > bytes.len() {
            return Err(ZipReadError::new("truncated central directory entry"));
        }
        let signature = read_u32(&bytes[cursor..], 0);
        if signature != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
            return Err(ZipReadError::new(
                "missing central directory entry signature",
            ));
        }
        let compression_method = read_u16(&bytes[cursor..], 10);
        let compressed_size = read_u32(&bytes[cursor..], 20) as usize;
        let uncompressed_size = read_u32(&bytes[cursor..], 24) as usize;
        let name_length = read_u16(&bytes[cursor..], 28) as usize;
        let extra_length = read_u16(&bytes[cursor..], 30) as usize;
        let comment_length = read_u16(&bytes[cursor..], 32) as usize;
        let local_header_offset = read_u32(&bytes[cursor..], 42) as usize;

        if compression_method != ZIP_COMPRESSION_STORED {
            return Err(ZipReadError::new(
                "only STORED compression is supported by integrity-verify",
            ));
        }
        if compressed_size != uncompressed_size {
            return Err(ZipReadError::new(
                "STORED entry compressed_size != uncompressed_size",
            ));
        }
        let header_total = 46 + name_length + extra_length + comment_length;
        if cursor + header_total > bytes.len() {
            return Err(ZipReadError::new(
                "truncated central directory entry payload",
            ));
        }
        let name_bytes = &bytes[cursor + 46..cursor + 46 + name_length];
        let path = std::str::from_utf8(name_bytes)
            .map_err(|_| ZipReadError::new("entry name is not UTF-8"))?
            .to_string();

        let entry_bytes = read_local_file_payload(bytes, local_header_offset, compressed_size)?;
        out.push(ZipEntry {
            path,
            bytes: entry_bytes,
        });

        cursor += header_total;
    }
    if cursor != central_end {
        return Err(ZipReadError::new(
            "central directory size does not match entries",
        ));
    }
    Ok(out)
}

fn read_local_file_payload(
    bytes: &[u8],
    offset: usize,
    declared_size: usize,
) -> Result<Vec<u8>, ZipReadError> {
    if offset + 30 > bytes.len() {
        return Err(ZipReadError::new("truncated local file header"));
    }
    let signature = read_u32(&bytes[offset..], 0);
    if signature != ZIP_LOCAL_FILE_HEADER_SIGNATURE {
        return Err(ZipReadError::new("missing local file header signature"));
    }
    let compression_method = read_u16(&bytes[offset..], 8);
    if compression_method != ZIP_COMPRESSION_STORED {
        return Err(ZipReadError::new(
            "only STORED compression is supported by integrity-verify",
        ));
    }
    let name_length = read_u16(&bytes[offset..], 26) as usize;
    let extra_length = read_u16(&bytes[offset..], 28) as usize;
    let payload_start = offset
        .checked_add(30)
        .and_then(|n| n.checked_add(name_length))
        .and_then(|n| n.checked_add(extra_length))
        .ok_or_else(|| ZipReadError::new("local header offset overflow"))?;
    let payload_end = payload_start
        .checked_add(declared_size)
        .ok_or_else(|| ZipReadError::new("payload offset overflow"))?;
    if payload_end > bytes.len() {
        return Err(ZipReadError::new("truncated local file payload"));
    }
    Ok(bytes[payload_start..payload_end].to_vec())
}

fn find_eocd(bytes: &[u8]) -> Result<usize, ZipReadError> {
    if bytes.len() < EOCD_MIN_LEN {
        return Err(ZipReadError::new("archive shorter than EOCD record"));
    }
    let max_scan = bytes.len().saturating_sub(EOCD_MIN_LEN);
    let mut index = max_scan;
    loop {
        if read_u32(&bytes[index..], 0) == ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE {
            return Ok(index);
        }
        if index == 0 {
            return Err(ZipReadError::new(
                "end-of-central-directory signature not found",
            ));
        }
        index -= 1;
    }
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use integrity_bundle::{Bundle, BundleEntry};

    #[test]
    fn round_trips_deterministic_bundle() {
        let mut bundle = Bundle::new();
        bundle.add_entry(BundleEntry::new("010-event.cbor", vec![0x01, 0x02, 0x03]));
        bundle.add_entry(BundleEntry::new("020-head.cbor", vec![0xff, 0xee]));
        let zip_bytes = bundle.to_zip_bytes().unwrap();
        let entries = read_stored_zip(&zip_bytes).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "010-event.cbor");
        assert_eq!(entries[0].bytes, vec![0x01, 0x02, 0x03]);
        assert_eq!(entries[1].path, "020-head.cbor");
        assert_eq!(entries[1].bytes, vec![0xff, 0xee]);
    }

    #[test]
    fn rejects_truncated_archive() {
        let result = read_stored_zip(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_random_bytes_without_eocd() {
        let result = read_stored_zip(&[0x55; 256]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_central_directory_size_that_runs_past_eocd() {
        let mut bundle = Bundle::new();
        bundle.add_entry(BundleEntry::new("010-event.cbor", vec![0x01]));
        let mut zip_bytes = bundle.to_zip_bytes().unwrap();
        let eocd_offset = find_eocd(&zip_bytes).unwrap();
        zip_bytes[eocd_offset + 12..eocd_offset + 16].copy_from_slice(&u32::MAX.to_le_bytes());

        let err = read_stored_zip(&zip_bytes).unwrap_err();
        assert_eq!(err.to_string(), "central directory size out of bounds");
    }
}
