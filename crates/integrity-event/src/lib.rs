// Rust guideline compliant 2026-02-21
//! Provides identity-free integrity event primitives.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Domain-neutral event sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventSequence(u64);

impl EventSequence {
    /// Creates an event sequence number.
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying sequence number.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Domain-neutral event kind identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventKind(String);

impl EventKind {
    /// Creates an event kind identifier.
    ///
    /// # Errors
    /// Returns an error when the kind is empty or contains whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, EventPrimitiveError> {
        let value = value.into();
        if value.is_empty() {
            return Err(EventPrimitiveError::new("event kind must not be empty"));
        }
        if value.chars().any(char::is_whitespace) {
            return Err(EventPrimitiveError::new(
                "event kind must not contain whitespace",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the event kind text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Domain-neutral event payload bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPayload(Vec<u8>);

impl EventPayload {
    /// Creates event payload bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns the payload bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Domain-neutral event hash bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHash([u8; 32]);

impl EventHash {
    /// Creates an event hash from 32 bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the hash bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Identity-free event envelope primitive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityEvent {
    sequence: EventSequence,
    kind: EventKind,
    payload: EventPayload,
    previous_hash: Option<EventHash>,
}

impl IntegrityEvent {
    /// Creates an identity-free integrity event.
    #[must_use]
    pub fn new(
        sequence: EventSequence,
        kind: EventKind,
        payload: EventPayload,
        previous_hash: Option<EventHash>,
    ) -> Self {
        Self {
            sequence,
            kind,
            payload,
            previous_hash,
        }
    }

    /// Returns the event sequence number.
    #[must_use]
    pub fn sequence(&self) -> EventSequence {
        self.sequence
    }

    /// Returns the event kind identifier.
    #[must_use]
    pub fn kind(&self) -> &EventKind {
        &self.kind
    }

    /// Returns the event payload bytes.
    #[must_use]
    pub fn payload(&self) -> &EventPayload {
        &self.payload
    }

    /// Returns the previous event hash.
    #[must_use]
    pub fn previous_hash(&self) -> Option<EventHash> {
        self.previous_hash
    }
}

/// Error returned when an event primitive is invalid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventPrimitiveError {
    message: String,
}

impl EventPrimitiveError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for EventPrimitiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EventPrimitiveError {}

#[cfg(test)]
mod tests {
    use super::{EventHash, EventKind, EventPayload, EventSequence, IntegrityEvent};

    #[test]
    fn event_primitives_round_trip_values() {
        let hash = EventHash::new([7; 32]);
        let event = IntegrityEvent::new(
            EventSequence::new(3),
            EventKind::new("wos.kernel.record").unwrap(),
            EventPayload::new([1, 2, 3]),
            Some(hash),
        );

        assert_eq!(event.sequence().get(), 3);
        assert_eq!(event.kind().as_str(), "wos.kernel.record");
        assert_eq!(event.payload().as_bytes(), &[1, 2, 3]);
        assert_eq!(event.previous_hash(), Some(hash));
    }

    #[test]
    fn event_kind_rejects_empty_or_whitespace_values() {
        assert!(EventKind::new("").is_err());
        assert!(EventKind::new("bad kind").is_err());
        assert!(EventKind::new("good.kind").is_ok());
    }
}
