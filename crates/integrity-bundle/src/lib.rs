// Rust guideline compliant 2026-02-21
//! Provides deterministic ZIP bundle primitives.

#![forbid(unsafe_code)]

use std::backtrace::Backtrace;
use std::fmt::{Display, Formatter};

use crc32fast::Hasher;

const ZIP_VERSION_NEEDED: u16 = 20;
const ZIP_VERSION_MADE_BY: u16 = 20;
const ZIP_GENERAL_PURPOSE_BITS: u16 = 0;
const ZIP_COMPRESSION_STORED: u16 = 0;
const ZIP_FIXED_TIME: u16 = 0;
const ZIP_FIXED_DATE: u16 = (1 << 5) | 1;
const ZIP_LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x0403_4b50;
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;
const EOCD_MIN_LEN: usize = 22;

/// One file entry in a deterministic bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleEntry {
    path: String,
    bytes: Vec<u8>,
}

impl BundleEntry {
    /// Creates a deterministic bundle entry.
    #[must_use]
    pub fn new(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            bytes,
        }
    }

    /// Returns the archive path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the file bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Error returned when deterministic bundle processing fails.
#[derive(Debug)]
pub struct BundleError {
    message: String,
    backtrace: Backtrace,
}

impl BundleError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            backtrace: Backtrace::capture(),
        }
    }

    /// Returns the captured backtrace.
    #[must_use]
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl Display for BundleError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BundleError {}

/// Parses a STORED-only deterministic ZIP archive into bundle entries.
///
/// This reader accepts the same narrow ZIP32 subset emitted by [`Bundle`]:
/// single-disk archives, STORED compression, UTF-8 ASCII paths, no comments,
/// no zip64, and no encrypted members.
///
/// # Errors
/// Returns an error when the archive is truncated, uses unsupported ZIP
/// features, or contains a corrupted central directory or local file header.
pub fn read_stored_zip(bytes: &[u8]) -> Result<Vec<BundleEntry>, BundleError> {
    if bytes.len() < EOCD_MIN_LEN {
        return Err(BundleError::new("archive shorter than EOCD record"));
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
        return Err(BundleError::new("multi-disk archives are unsupported"));
    }
    if entries_on_disk != entries_total {
        return Err(BundleError::new(
            "entries-on-disk does not match total entries",
        ));
    }
    if comment_length != 0 {
        return Err(BundleError::new("archive comments are unsupported"));
    }
    if central_offset >= bytes.len() {
        return Err(BundleError::new("central directory offset out of bounds"));
    }
    let central_end = central_offset
        .checked_add(central_size)
        .ok_or_else(|| BundleError::new("central directory size overflow"))?;
    if central_end > eocd_offset {
        return Err(BundleError::new("central directory size out of bounds"));
    }

    let mut cursor = central_offset;
    let mut out = Vec::with_capacity(entries_total as usize);
    for _ in 0..entries_total {
        if cursor + 46 > bytes.len() {
            return Err(BundleError::new("truncated central directory entry"));
        }
        let signature = read_u32(&bytes[cursor..], 0);
        if signature != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
            return Err(BundleError::new(
                "missing central directory entry signature",
            ));
        }
        let general_purpose_bits = read_u16(&bytes[cursor..], 8);
        let compression_method = read_u16(&bytes[cursor..], 10);
        let expected_crc32 = read_u32(&bytes[cursor..], 16);
        let compressed_size = read_u32(&bytes[cursor..], 20) as usize;
        let uncompressed_size = read_u32(&bytes[cursor..], 24) as usize;
        let name_length = read_u16(&bytes[cursor..], 28) as usize;
        let extra_length = read_u16(&bytes[cursor..], 30) as usize;
        let comment_length = read_u16(&bytes[cursor..], 32) as usize;
        let local_header_offset = read_u32(&bytes[cursor..], 42) as usize;

        if general_purpose_bits != ZIP_GENERAL_PURPOSE_BITS {
            return Err(BundleError::new(
                "general purpose bit flags are unsupported",
            ));
        }
        if compression_method != ZIP_COMPRESSION_STORED {
            return Err(BundleError::new(
                "only STORED compression is supported by integrity-bundle",
            ));
        }
        if compressed_size != uncompressed_size {
            return Err(BundleError::new(
                "STORED entry compressed_size != uncompressed_size",
            ));
        }
        if extra_length != 0 {
            return Err(BundleError::new(
                "central directory extra fields are unsupported",
            ));
        }
        if comment_length != 0 {
            return Err(BundleError::new(
                "central directory comments are unsupported",
            ));
        }
        let header_total = 46 + name_length + extra_length + comment_length;
        if cursor + header_total > bytes.len() {
            return Err(BundleError::new(
                "truncated central directory entry payload",
            ));
        }
        let name_bytes = &bytes[cursor + 46..cursor + 46 + name_length];
        let path = std::str::from_utf8(name_bytes)
            .map_err(|_| BundleError::new("entry name is not UTF-8"))?
            .to_string();
        if !path.is_ascii() {
            return Err(BundleError::new("entry name is not ASCII"));
        }

        let entry_bytes = read_local_file_payload(
            bytes,
            local_header_offset,
            name_bytes,
            expected_crc32,
            compressed_size,
            uncompressed_size,
        )?;
        out.push(BundleEntry::new(path, entry_bytes));

        cursor += header_total;
    }
    if cursor != central_end {
        return Err(BundleError::new(
            "central directory size does not match entries",
        ));
    }
    Ok(out)
}

/// Logical file bundle with deterministic ZIP serialization.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bundle {
    entries: Vec<BundleEntry>,
}

impl Bundle {
    /// Creates an empty deterministic bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry to the logical bundle.
    pub fn add_entry(&mut self, entry: BundleEntry) {
        self.entries.push(entry);
    }

    /// Returns the logical bundle entries.
    #[must_use]
    pub fn entries(&self) -> &[BundleEntry] {
        &self.entries
    }

    /// Serializes the logical bundle to deterministic ZIP bytes.
    ///
    /// Entries are emitted in lexicographic path order with stored compression,
    /// fixed DOS timestamps, zero extra fields, and zero external attributes.
    ///
    /// # Errors
    /// Returns an error when duplicate or non-ASCII paths are present, or when
    /// the archive exceeds classic ZIP field bounds.
    pub fn to_zip_bytes(&self) -> Result<Vec<u8>, BundleError> {
        let mut entries = self.entries.clone();
        entries.sort_by(|left, right| left.path.cmp(&right.path));

        for pair in entries.windows(2) {
            if pair[0].path == pair[1].path {
                return Err(BundleError::new(format!(
                    "duplicate bundle path `{}`",
                    pair[0].path
                )));
            }
        }

        let mut local_sections = Vec::new();
        let mut central_sections = Vec::new();
        let mut offset = 0usize;

        for entry in &entries {
            if !entry.path.is_ascii() {
                return Err(BundleError::new(format!(
                    "bundle path `{}` is not ASCII",
                    entry.path
                )));
            }

            let path_bytes = entry.path.as_bytes();
            let crc32 = crc32(entry.bytes());
            let compressed_size = u32::try_from(entry.bytes.len()).map_err(|_| {
                BundleError::new(format!("entry `{}` exceeds ZIP32 size bounds", entry.path))
            })?;
            let path_len = u16::try_from(path_bytes.len()).map_err(|_| {
                BundleError::new(format!(
                    "entry path `{}` exceeds ZIP32 name bounds",
                    entry.path
                ))
            })?;
            let local_offset = u32::try_from(offset)
                .map_err(|_| BundleError::new("archive offset exceeds ZIP32 bounds"))?;

            let mut local = Vec::new();
            push_u32_le(&mut local, ZIP_LOCAL_FILE_HEADER_SIGNATURE);
            push_u16_le(&mut local, ZIP_VERSION_NEEDED);
            push_u16_le(&mut local, ZIP_GENERAL_PURPOSE_BITS);
            push_u16_le(&mut local, ZIP_COMPRESSION_STORED);
            push_u16_le(&mut local, ZIP_FIXED_TIME);
            push_u16_le(&mut local, ZIP_FIXED_DATE);
            push_u32_le(&mut local, crc32);
            push_u32_le(&mut local, compressed_size);
            push_u32_le(&mut local, compressed_size);
            push_u16_le(&mut local, path_len);
            push_u16_le(&mut local, 0);
            local.extend_from_slice(path_bytes);
            local.extend_from_slice(&entry.bytes);

            let mut central = Vec::new();
            push_u32_le(&mut central, ZIP_CENTRAL_DIRECTORY_SIGNATURE);
            push_u16_le(&mut central, ZIP_VERSION_MADE_BY);
            push_u16_le(&mut central, ZIP_VERSION_NEEDED);
            push_u16_le(&mut central, ZIP_GENERAL_PURPOSE_BITS);
            push_u16_le(&mut central, ZIP_COMPRESSION_STORED);
            push_u16_le(&mut central, ZIP_FIXED_TIME);
            push_u16_le(&mut central, ZIP_FIXED_DATE);
            push_u32_le(&mut central, crc32);
            push_u32_le(&mut central, compressed_size);
            push_u32_le(&mut central, compressed_size);
            push_u16_le(&mut central, path_len);
            push_u16_le(&mut central, 0);
            push_u16_le(&mut central, 0);
            push_u16_le(&mut central, 0);
            push_u16_le(&mut central, 0);
            push_u32_le(&mut central, 0);
            push_u32_le(&mut central, local_offset);
            central.extend_from_slice(path_bytes);

            offset = offset
                .checked_add(local.len())
                .ok_or_else(|| BundleError::new("archive offset overflow"))?;
            local_sections.extend_from_slice(&local);
            central_sections.extend_from_slice(&central);
        }

        let central_offset = u32::try_from(local_sections.len())
            .map_err(|_| BundleError::new("central directory offset exceeds ZIP32 bounds"))?;
        let central_size = u32::try_from(central_sections.len())
            .map_err(|_| BundleError::new("central directory size exceeds ZIP32 bounds"))?;
        let entry_count = u16::try_from(entries.len())
            .map_err(|_| BundleError::new("entry count exceeds ZIP32 bounds"))?;

        let mut output = Vec::new();
        output.extend_from_slice(&local_sections);
        output.extend_from_slice(&central_sections);
        push_u32_le(&mut output, ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE);
        push_u16_le(&mut output, 0);
        push_u16_le(&mut output, 0);
        push_u16_le(&mut output, entry_count);
        push_u16_le(&mut output, entry_count);
        push_u32_le(&mut output, central_size);
        push_u32_le(&mut output, central_offset);
        push_u16_le(&mut output, 0);
        Ok(output)
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn push_u16_le(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_le_bytes());
}

fn push_u32_le(target: &mut Vec<u8>, value: u32) {
    target.extend_from_slice(&value.to_le_bytes());
}

fn read_local_file_payload(
    bytes: &[u8],
    offset: usize,
    expected_name: &[u8],
    expected_crc32: u32,
    expected_compressed_size: usize,
    expected_uncompressed_size: usize,
) -> Result<Vec<u8>, BundleError> {
    if offset + 30 > bytes.len() {
        return Err(BundleError::new("truncated local file header"));
    }
    let signature = read_u32(&bytes[offset..], 0);
    if signature != ZIP_LOCAL_FILE_HEADER_SIGNATURE {
        return Err(BundleError::new("missing local file header signature"));
    }
    let general_purpose_bits = read_u16(&bytes[offset..], 6);
    let compression_method = read_u16(&bytes[offset..], 8);
    let local_crc32 = read_u32(&bytes[offset..], 14);
    let local_compressed_size = read_u32(&bytes[offset..], 18) as usize;
    let local_uncompressed_size = read_u32(&bytes[offset..], 22) as usize;
    let name_length = read_u16(&bytes[offset..], 26) as usize;
    let extra_length = read_u16(&bytes[offset..], 28) as usize;

    if general_purpose_bits != ZIP_GENERAL_PURPOSE_BITS {
        return Err(BundleError::new(
            "general purpose bit flags are unsupported",
        ));
    }
    if compression_method != ZIP_COMPRESSION_STORED {
        return Err(BundleError::new(
            "only STORED compression is supported by integrity-bundle",
        ));
    }
    if local_crc32 != expected_crc32 {
        return Err(BundleError::new(
            "local file header CRC32 does not match central directory",
        ));
    }
    if local_compressed_size != expected_compressed_size {
        return Err(BundleError::new(
            "local file header compressed size does not match central directory",
        ));
    }
    if local_uncompressed_size != expected_uncompressed_size {
        return Err(BundleError::new(
            "local file header uncompressed size does not match central directory",
        ));
    }
    if extra_length != 0 {
        return Err(BundleError::new(
            "local file header extra fields are unsupported",
        ));
    }
    if name_length != expected_name.len() {
        return Err(BundleError::new(
            "local file header name does not match central directory",
        ));
    }
    let name_start = offset
        .checked_add(30)
        .ok_or_else(|| BundleError::new("local header offset overflow"))?;
    let name_end = name_start
        .checked_add(name_length)
        .ok_or_else(|| BundleError::new("local header offset overflow"))?;
    if name_end > bytes.len() {
        return Err(BundleError::new("truncated local file header name"));
    }
    if &bytes[name_start..name_end] != expected_name {
        return Err(BundleError::new(
            "local file header name does not match central directory",
        ));
    }
    let payload_start = offset
        .checked_add(30)
        .and_then(|n| n.checked_add(name_length))
        .and_then(|n| n.checked_add(extra_length))
        .ok_or_else(|| BundleError::new("local header offset overflow"))?;
    let payload_end = payload_start
        .checked_add(expected_compressed_size)
        .ok_or_else(|| BundleError::new("payload offset overflow"))?;
    if payload_end > bytes.len() {
        return Err(BundleError::new("truncated local file payload"));
    }
    let payload = &bytes[payload_start..payload_end];
    if crc32(payload) != expected_crc32 {
        return Err(BundleError::new("entry CRC32 does not match payload"));
    }
    Ok(payload.to_vec())
}

fn find_eocd(bytes: &[u8]) -> Result<usize, BundleError> {
    if bytes.len() < EOCD_MIN_LEN {
        return Err(BundleError::new("archive shorter than EOCD record"));
    }
    let max_scan = bytes.len().saturating_sub(EOCD_MIN_LEN);
    let mut index = max_scan;
    loop {
        if read_u32(&bytes[index..], 0) == ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE {
            return Ok(index);
        }
        if index == 0 {
            return Err(BundleError::new(
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
    use super::{Bundle, BundleEntry, find_eocd, read_stored_zip, read_u32};

    #[test]
    fn deterministic_zip_bytes_are_reproducible() {
        let mut package = Bundle::new();
        package.add_entry(BundleEntry::new("020-head.cbor", vec![0x02, 0x03]));
        package.add_entry(BundleEntry::new("010-event.cbor", vec![0x00, 0x01]));

        let first = package.to_zip_bytes().unwrap();
        let second = package.to_zip_bytes().unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn deterministic_zip_bytes_sort_paths() {
        let mut unordered = Bundle::new();
        unordered.add_entry(BundleEntry::new("b.txt", b"b".to_vec()));
        unordered.add_entry(BundleEntry::new("a.txt", b"a".to_vec()));

        let mut ordered = Bundle::new();
        ordered.add_entry(BundleEntry::new("a.txt", b"a".to_vec()));
        ordered.add_entry(BundleEntry::new("b.txt", b"b".to_vec()));

        assert_eq!(
            unordered.to_zip_bytes().unwrap(),
            ordered.to_zip_bytes().unwrap()
        );
    }

    #[test]
    fn duplicate_paths_are_rejected() {
        let mut package = Bundle::new();
        package.add_entry(BundleEntry::new("same.txt", b"one".to_vec()));
        package.add_entry(BundleEntry::new("same.txt", b"two".to_vec()));

        let error = package.to_zip_bytes().unwrap_err();
        assert!(error.to_string().contains("duplicate bundle path"));
    }

    #[test]
    fn read_stored_zip_round_trips_deterministic_bundle() {
        let mut bundle = Bundle::new();
        bundle.add_entry(BundleEntry::new("010-event.cbor", vec![0x01, 0x02, 0x03]));
        bundle.add_entry(BundleEntry::new("020-head.cbor", vec![0xff, 0xee]));
        let zip_bytes = bundle.to_zip_bytes().unwrap();
        let entries = read_stored_zip(&zip_bytes).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path(), "010-event.cbor");
        assert_eq!(entries[0].bytes(), &[0x01, 0x02, 0x03]);
        assert_eq!(entries[1].path(), "020-head.cbor");
        assert_eq!(entries[1].bytes(), &[0xff, 0xee]);
    }

    #[test]
    fn read_stored_zip_rejects_truncated_archive() {
        let result = read_stored_zip(&[0u8; 10]);

        assert!(result.is_err());
    }

    #[test]
    fn read_stored_zip_rejects_random_bytes_without_eocd() {
        let result = read_stored_zip(&[0x55; 256]);

        assert!(result.is_err());
    }

    #[test]
    fn read_stored_zip_rejects_central_directory_size_that_runs_past_eocd() {
        let mut bundle = Bundle::new();
        bundle.add_entry(BundleEntry::new("010-event.cbor", vec![0x01]));
        let mut zip_bytes = bundle.to_zip_bytes().unwrap();
        let eocd_offset = find_eocd(&zip_bytes).unwrap();
        zip_bytes[eocd_offset + 12..eocd_offset + 16].copy_from_slice(&u32::MAX.to_le_bytes());

        let err = read_stored_zip(&zip_bytes).unwrap_err();
        assert_eq!(err.to_string(), "central directory size out of bounds");
    }

    #[test]
    fn read_stored_zip_rejects_general_purpose_flags() {
        let mut bundle = Bundle::new();
        bundle.add_entry(BundleEntry::new("010-event.cbor", vec![0x01]));
        let mut zip_bytes = bundle.to_zip_bytes().unwrap();
        zip_bytes[6] = 1;

        let err = read_stored_zip(&zip_bytes).unwrap_err();
        assert_eq!(err.to_string(), "general purpose bit flags are unsupported");
    }

    #[test]
    fn read_stored_zip_rejects_local_name_mismatch() {
        let mut bundle = Bundle::new();
        bundle.add_entry(BundleEntry::new("010-event.cbor", vec![0x01]));
        let mut zip_bytes = bundle.to_zip_bytes().unwrap();
        zip_bytes[30] = b'x';

        let err = read_stored_zip(&zip_bytes).unwrap_err();
        assert_eq!(
            err.to_string(),
            "local file header name does not match central directory"
        );
    }

    #[test]
    fn read_stored_zip_rejects_local_crc_mismatch() {
        let mut bundle = Bundle::new();
        bundle.add_entry(BundleEntry::new("010-event.cbor", vec![0x01]));
        let mut zip_bytes = bundle.to_zip_bytes().unwrap();
        zip_bytes[14..18].copy_from_slice(&0u32.to_le_bytes());

        let err = read_stored_zip(&zip_bytes).unwrap_err();
        assert_eq!(
            err.to_string(),
            "local file header CRC32 does not match central directory"
        );
    }

    #[test]
    fn read_stored_zip_rejects_payload_crc_mismatch() {
        let mut bundle = Bundle::new();
        bundle.add_entry(BundleEntry::new("010-event.cbor", vec![0x01]));
        let mut zip_bytes = bundle.to_zip_bytes().unwrap();
        let payload_offset = 30 + "010-event.cbor".len();
        zip_bytes[payload_offset] = 0x02;

        let err = read_stored_zip(&zip_bytes).unwrap_err();
        assert_eq!(err.to_string(), "entry CRC32 does not match payload");
    }

    #[test]
    fn read_stored_zip_rejects_central_extra_fields() {
        let mut bundle = Bundle::new();
        bundle.add_entry(BundleEntry::new("010-event.cbor", vec![0x01]));
        let mut zip_bytes = bundle.to_zip_bytes().unwrap();
        let eocd_offset = find_eocd(&zip_bytes).unwrap();
        let central_offset = read_u32(&zip_bytes[eocd_offset..], 16) as usize;
        zip_bytes[central_offset + 30..central_offset + 32].copy_from_slice(&1u16.to_le_bytes());

        let err = read_stored_zip(&zip_bytes).unwrap_err();
        assert_eq!(
            err.to_string(),
            "central directory extra fields are unsupported"
        );
    }
}
