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

/// Error returned when deterministic bundle serialization fails.
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

#[cfg(test)]
mod tests {
    use super::{Bundle, BundleEntry};

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
}
