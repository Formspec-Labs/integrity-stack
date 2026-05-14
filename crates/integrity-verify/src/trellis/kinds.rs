// Rust guideline compliant 2026-02-21
//! Wire-stable verification failure and decode-error discriminants.

#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerificationFailureKind {
    ArchiveIntegrityFailure,
    AttachmentBindingEventUnresolved,
    AttachmentBindingLineageCycle,
    AttachmentBindingMismatch,
    AttachmentBindingMissing,
    AttachmentManifestDigestMismatch,
    AttachmentManifestDuplicateBinding,
    AttachmentManifestInvalid,
    AttachmentPayloadHashMismatch,
    AttachmentPriorBindingForwardReference,
    AttachmentPriorBindingUnresolved,
    AttestationInsufficient,
    AuthorPreimageInvalid,
    BoundRegistryInvalid,
    CertificateCatalogDigestMismatch,
    CertificateCatalogDuplicateEvent,
    CertificateCatalogEventTypeMismatch,
    CertificateCatalogEventUnresolved,
    CertificateCatalogInvalid,
    CertificateCatalogMismatch,
    CertificateChainSummaryMismatch,
    CertificateIdCollision,
    CheckpointPayloadInvalid,
    CheckpointRootMismatch,
    CheckpointSignatureInvalid,
    CheckpointsInvalid,
    ConsistencyProofInvalid,
    ConsistencyProofMismatch,
    ConsistencyProofsInvalid,
    ContentHashMismatch,
    ErasureAttestationSignatureInvalid,
    ErasureDestroyedAtConflict,
    ErasureDestroyedAtAfterHost,
    ErasureEvidenceCatalogDigestMismatch,
    ErasureEvidenceCatalogDuplicateEvent,
    ErasureEvidenceCatalogEventTypeMismatch,
    ErasureEvidenceCatalogEventUnresolved,
    ErasureEvidenceCatalogInvalid,
    ErasureEvidenceCatalogMismatch,
    ErasureKeyClassPayloadConflict,
    ErasureKeyClassRegistryMismatch,
    EventReorder,
    EventTruncation,
    EventsInvalid,
    ExportEventsDuplicateCanonicalHash,
    ExportZipInvalid,
    HashMismatch,
    HeadCheckpointDigestMismatch,
    IdempotencyKeyLengthInvalid,
    IdempotencyKeyPayloadMismatch,
    InclusionProofInvalid,
    InclusionProofMismatch,
    InclusionProofsInvalid,
    InteropSidecarContentMismatch,
    InteropSidecarDerivationVersionUnknown,
    InteropSidecarKindUnknown,
    InteropSidecarMissing,
    InteropSidecarPathInvalid,
    InteropSidecarPhase1Locked,
    InteropSidecarUnlistedFile,
    KeyClassMismatch,
    KeyEntryAttributesShapeMismatch,
    LegacyTimestampFormat,
    MalformedCose,
    MalformedResponseDigest,
    ManifestPayloadInvalid,
    ManifestPayloadMissing,
    ManifestSignatureInvalid,
    ManifestStructureInvalid,
    MissingAttachmentBody,
    MissingAttachmentManifest,
    MissingCertificateCatalog,
    MissingErasureEvidenceCatalog,
    MissingManifest,
    MissingSigningKeyRegistry,
    PostErasureUse,
    PostErasureWrap,
    PostureDeclarationDigestMismatch,
    PresentationArtifactAttachmentMissing,
    PresentationArtifactContentMismatch,
    PrevCheckpointHashMismatch,
    PrevHashBreak,
    PrevHashMismatch,
    RegistryDigestMismatch,
    ResponseRefMismatch,
    RevokedAuthority,
    ScopeMismatch,
    StateContinuityMismatch,
    SignatureInvalid,
    SigningEventTimestampMismatch,
    SigningEventUnresolved,
    SigningKeyRegistryInvalid,
    SupersessionGraphCycle,
    SupersessionGraphHeadMismatch,
    SupersessionGraphInvalid,
    SupersessionGraphLinkageMismatch,
    SupersessionGraphUnbound,
    SupersessionPredecessorCheckpointMismatch,
    TimestampNanosOutOfRange,
    TimestampOrderViolation,
    TreeSizeInvalid,
    UnresolvableManifestKid,
    UnsupportedSuite,
    UserContentAttestationChainPositionMismatch,
    UserContentAttestationIdCollision,
    UserContentAttestationIdentityRequired,
    UserContentAttestationIdentitySubjectMismatch,
    UserContentAttestationIdentityTemporalInversion,
    UserContentAttestationIdentityUnresolved,
    UserContentAttestationIntentMalformed,
    UserContentAttestationKeyNotActive,
    UserContentAttestationOperatorInUserSlot,
    UserContentAttestationSignatureInvalid,
    UserContentAttestationTimestampMismatch,
}

impl VerificationFailureKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArchiveIntegrityFailure => "archive_integrity_failure",
            Self::AttachmentBindingEventUnresolved => "attachment_binding_event_unresolved",
            Self::AttachmentBindingLineageCycle => "attachment_binding_lineage_cycle",
            Self::AttachmentBindingMismatch => "attachment_binding_mismatch",
            Self::AttachmentBindingMissing => "attachment_binding_missing",
            Self::AttachmentManifestDigestMismatch => "attachment_manifest_digest_mismatch",
            Self::AttachmentManifestDuplicateBinding => "attachment_manifest_duplicate_binding",
            Self::AttachmentManifestInvalid => "attachment_manifest_invalid",
            Self::AttachmentPayloadHashMismatch => "attachment_payload_hash_mismatch",
            Self::AttachmentPriorBindingForwardReference => {
                "attachment_prior_binding_forward_reference"
            }
            Self::AttachmentPriorBindingUnresolved => "attachment_prior_binding_unresolved",
            Self::AttestationInsufficient => "attestation_insufficient",
            Self::AuthorPreimageInvalid => "author_preimage_invalid",
            Self::BoundRegistryInvalid => "bound_registry_invalid",
            Self::CertificateCatalogDigestMismatch => "certificate_catalog_digest_mismatch",
            Self::CertificateCatalogDuplicateEvent => "certificate_catalog_duplicate_event",
            Self::CertificateCatalogEventTypeMismatch => "certificate_catalog_event_type_mismatch",
            Self::CertificateCatalogEventUnresolved => "certificate_catalog_event_unresolved",
            Self::CertificateCatalogInvalid => "certificate_catalog_invalid",
            Self::CertificateCatalogMismatch => "certificate_catalog_mismatch",
            Self::CertificateChainSummaryMismatch => "certificate_chain_summary_mismatch",
            Self::CertificateIdCollision => "certificate_id_collision",
            Self::CheckpointPayloadInvalid => "checkpoint_payload_invalid",
            Self::CheckpointRootMismatch => "checkpoint_root_mismatch",
            Self::CheckpointSignatureInvalid => "checkpoint_signature_invalid",
            Self::CheckpointsInvalid => "checkpoints_invalid",
            Self::ConsistencyProofInvalid => "consistency_proof_invalid",
            Self::ConsistencyProofMismatch => "consistency_proof_mismatch",
            Self::ConsistencyProofsInvalid => "consistency_proofs_invalid",
            Self::ContentHashMismatch => "content_hash_mismatch",
            Self::ErasureAttestationSignatureInvalid => "erasure_attestation_signature_invalid",
            Self::ErasureDestroyedAtConflict => "erasure_destroyed_at_conflict",
            Self::ErasureDestroyedAtAfterHost => "erasure_destroyed_at_after_host",
            Self::ErasureEvidenceCatalogDigestMismatch => {
                "erasure_evidence_catalog_digest_mismatch"
            }
            Self::ErasureEvidenceCatalogDuplicateEvent => {
                "erasure_evidence_catalog_duplicate_event"
            }
            Self::ErasureEvidenceCatalogEventTypeMismatch => {
                "erasure_evidence_catalog_event_type_mismatch"
            }
            Self::ErasureEvidenceCatalogEventUnresolved => {
                "erasure_evidence_catalog_event_unresolved"
            }
            Self::ErasureEvidenceCatalogInvalid => "erasure_evidence_catalog_invalid",
            Self::ErasureEvidenceCatalogMismatch => "erasure_evidence_catalog_mismatch",
            Self::ErasureKeyClassPayloadConflict => "erasure_key_class_payload_conflict",
            Self::ErasureKeyClassRegistryMismatch => "erasure_key_class_registry_mismatch",
            Self::EventReorder => "event_reorder",
            Self::EventTruncation => "event_truncation",
            Self::EventsInvalid => "events_invalid",
            Self::ExportEventsDuplicateCanonicalHash => "export_events_duplicate_canonical_hash",
            Self::ExportZipInvalid => "export_zip_invalid",
            Self::HashMismatch => "hash_mismatch",
            Self::HeadCheckpointDigestMismatch => "head_checkpoint_digest_mismatch",
            Self::IdempotencyKeyLengthInvalid => "idempotency_key_length_invalid",
            Self::IdempotencyKeyPayloadMismatch => "idempotency_key_payload_mismatch",
            Self::InclusionProofInvalid => "inclusion_proof_invalid",
            Self::InclusionProofMismatch => "inclusion_proof_mismatch",
            Self::InclusionProofsInvalid => "inclusion_proofs_invalid",
            Self::InteropSidecarContentMismatch => "interop_sidecar_content_mismatch",
            Self::InteropSidecarDerivationVersionUnknown => {
                "interop_sidecar_derivation_version_unknown"
            }
            Self::InteropSidecarKindUnknown => "interop_sidecar_kind_unknown",
            Self::InteropSidecarMissing => "interop_sidecar_missing",
            Self::InteropSidecarPathInvalid => "interop_sidecar_path_invalid",
            Self::InteropSidecarPhase1Locked => "interop_sidecar_phase_1_locked",
            Self::InteropSidecarUnlistedFile => "interop_sidecar_unlisted_file",
            Self::KeyClassMismatch => "key_class_mismatch",
            Self::KeyEntryAttributesShapeMismatch => "key_entry_attributes_shape_mismatch",
            Self::LegacyTimestampFormat => "legacy_timestamp_format",
            Self::MalformedCose => "malformed_cose",
            Self::MalformedResponseDigest => "malformed_response_digest",
            Self::ManifestPayloadInvalid => "manifest_payload_invalid",
            Self::ManifestPayloadMissing => "manifest_payload_missing",
            Self::ManifestSignatureInvalid => "manifest_signature_invalid",
            Self::ManifestStructureInvalid => "manifest_structure_invalid",
            Self::MissingAttachmentBody => "missing_attachment_body",
            Self::MissingAttachmentManifest => "missing_attachment_manifest",
            Self::MissingCertificateCatalog => "missing_certificate_catalog",
            Self::MissingErasureEvidenceCatalog => "missing_erasure_evidence_catalog",
            Self::MissingManifest => "missing_manifest",
            Self::MissingSigningKeyRegistry => "missing_signing_key_registry",
            Self::PostErasureUse => "post_erasure_use",
            Self::PostErasureWrap => "post_erasure_wrap",
            Self::PostureDeclarationDigestMismatch => "posture_declaration_digest_mismatch",
            Self::PresentationArtifactAttachmentMissing => {
                "presentation_artifact_attachment_missing"
            }
            Self::PresentationArtifactContentMismatch => "presentation_artifact_content_mismatch",
            Self::PrevCheckpointHashMismatch => "prev_checkpoint_hash_mismatch",
            Self::PrevHashBreak => "prev_hash_break",
            Self::PrevHashMismatch => "prev_hash_mismatch",
            Self::RegistryDigestMismatch => "registry_digest_mismatch",
            Self::ResponseRefMismatch => "response_ref_mismatch",
            Self::RevokedAuthority => "revoked_authority",
            Self::ScopeMismatch => "scope_mismatch",
            Self::StateContinuityMismatch => "state_continuity_mismatch",
            Self::SignatureInvalid => "signature_invalid",
            Self::SigningEventTimestampMismatch => "signing_event_timestamp_mismatch",
            Self::SigningEventUnresolved => "signing_event_unresolved",
            Self::SigningKeyRegistryInvalid => "signing_key_registry_invalid",
            Self::SupersessionGraphCycle => "supersession_graph_cycle",
            Self::SupersessionGraphHeadMismatch => "supersession_graph_head_mismatch",
            Self::SupersessionGraphInvalid => "supersession_graph_invalid",
            Self::SupersessionGraphLinkageMismatch => "supersession_graph_linkage_mismatch",
            Self::SupersessionGraphUnbound => "supersession_graph_unbound",
            Self::SupersessionPredecessorCheckpointMismatch => {
                "supersession_predecessor_checkpoint_mismatch"
            }
            Self::TimestampNanosOutOfRange => "timestamp_nanos_out_of_range",
            Self::TimestampOrderViolation => "timestamp_order_violation",
            Self::TreeSizeInvalid => "tree_size_invalid",
            Self::UnresolvableManifestKid => "unresolvable_manifest_kid",
            Self::UnsupportedSuite => "unsupported_suite",
            Self::UserContentAttestationChainPositionMismatch => {
                "user_content_attestation_chain_position_mismatch"
            }
            Self::UserContentAttestationIdCollision => "user_content_attestation_id_collision",
            Self::UserContentAttestationIdentityRequired => {
                "user_content_attestation_identity_required"
            }
            Self::UserContentAttestationIdentitySubjectMismatch => {
                "user_content_attestation_identity_subject_mismatch"
            }
            Self::UserContentAttestationIdentityTemporalInversion => {
                "user_content_attestation_identity_temporal_inversion"
            }
            Self::UserContentAttestationIdentityUnresolved => {
                "user_content_attestation_identity_unresolved"
            }
            Self::UserContentAttestationIntentMalformed => {
                "user_content_attestation_intent_malformed"
            }
            Self::UserContentAttestationKeyNotActive => "user_content_attestation_key_not_active",
            Self::UserContentAttestationOperatorInUserSlot => {
                "user_content_attestation_operator_in_user_slot"
            }
            Self::UserContentAttestationSignatureInvalid => {
                "user_content_attestation_signature_invalid"
            }
            Self::UserContentAttestationTimestampMismatch => {
                "user_content_attestation_timestamp_mismatch"
            }
        }
    }
}

impl std::fmt::Display for VerificationFailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerifyErrorKind {
    IdempotencyKeyLengthInvalid,
    ErasureDestroyedAtAfterHost,
    MalformedCose,
    CertificateChainSummaryMismatch,
    LegacyTimestampFormat,
    TimestampNanosOutOfRange,
    KeyEntryAttributesShapeMismatch,
}

impl VerifyErrorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdempotencyKeyLengthInvalid => "idempotency_key_length_invalid",
            Self::ErasureDestroyedAtAfterHost => "erasure_destroyed_at_after_host",
            Self::MalformedCose => "malformed_cose",
            Self::CertificateChainSummaryMismatch => "certificate_chain_summary_mismatch",
            Self::LegacyTimestampFormat => "legacy_timestamp_format",
            Self::TimestampNanosOutOfRange => "timestamp_nanos_out_of_range",
            Self::KeyEntryAttributesShapeMismatch => "key_entry_attributes_shape_mismatch",
        }
    }

    #[must_use]
    pub fn verification_failure_kind(self) -> VerificationFailureKind {
        match self {
            Self::IdempotencyKeyLengthInvalid => {
                VerificationFailureKind::IdempotencyKeyLengthInvalid
            }
            Self::ErasureDestroyedAtAfterHost => {
                VerificationFailureKind::ErasureDestroyedAtAfterHost
            }
            Self::MalformedCose => VerificationFailureKind::MalformedCose,
            Self::CertificateChainSummaryMismatch => {
                VerificationFailureKind::CertificateChainSummaryMismatch
            }
            Self::LegacyTimestampFormat => VerificationFailureKind::LegacyTimestampFormat,
            Self::TimestampNanosOutOfRange => VerificationFailureKind::TimestampNanosOutOfRange,
            Self::KeyEntryAttributesShapeMismatch => {
                VerificationFailureKind::KeyEntryAttributesShapeMismatch
            }
        }
    }
}

impl std::fmt::Display for VerifyErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod wire_taxonomy_tests {
    use super::*;
    use std::collections::BTreeSet;

    macro_rules! all_verification_failure_kinds {
        ($m:ident) => {
            $m!(
                ArchiveIntegrityFailure,
                AttachmentBindingEventUnresolved,
                AttachmentBindingLineageCycle,
                AttachmentBindingMismatch,
                AttachmentBindingMissing,
                AttachmentManifestDigestMismatch,
                AttachmentManifestDuplicateBinding,
                AttachmentManifestInvalid,
                AttachmentPayloadHashMismatch,
                AttachmentPriorBindingForwardReference,
                AttachmentPriorBindingUnresolved,
                AttestationInsufficient,
                AuthorPreimageInvalid,
                BoundRegistryInvalid,
                CertificateCatalogDigestMismatch,
                CertificateCatalogDuplicateEvent,
                CertificateCatalogEventTypeMismatch,
                CertificateCatalogEventUnresolved,
                CertificateCatalogInvalid,
                CertificateCatalogMismatch,
                CertificateChainSummaryMismatch,
                CertificateIdCollision,
                CheckpointPayloadInvalid,
                CheckpointRootMismatch,
                CheckpointSignatureInvalid,
                CheckpointsInvalid,
                ConsistencyProofInvalid,
                ConsistencyProofMismatch,
                ConsistencyProofsInvalid,
                ContentHashMismatch,
                ErasureAttestationSignatureInvalid,
                ErasureDestroyedAtConflict,
                ErasureDestroyedAtAfterHost,
                ErasureEvidenceCatalogDigestMismatch,
                ErasureEvidenceCatalogDuplicateEvent,
                ErasureEvidenceCatalogEventTypeMismatch,
                ErasureEvidenceCatalogEventUnresolved,
                ErasureEvidenceCatalogInvalid,
                ErasureEvidenceCatalogMismatch,
                ErasureKeyClassPayloadConflict,
                ErasureKeyClassRegistryMismatch,
                EventReorder,
                EventTruncation,
                EventsInvalid,
                ExportEventsDuplicateCanonicalHash,
                ExportZipInvalid,
                HashMismatch,
                HeadCheckpointDigestMismatch,
                IdempotencyKeyLengthInvalid,
                IdempotencyKeyPayloadMismatch,
                InclusionProofInvalid,
                InclusionProofMismatch,
                InclusionProofsInvalid,
                InteropSidecarContentMismatch,
                InteropSidecarDerivationVersionUnknown,
                InteropSidecarKindUnknown,
                InteropSidecarMissing,
                InteropSidecarPathInvalid,
                InteropSidecarPhase1Locked,
                InteropSidecarUnlistedFile,
                KeyClassMismatch,
                KeyEntryAttributesShapeMismatch,
                LegacyTimestampFormat,
                MalformedCose,
                MalformedResponseDigest,
                ManifestPayloadInvalid,
                ManifestPayloadMissing,
                ManifestSignatureInvalid,
                ManifestStructureInvalid,
                MissingAttachmentBody,
                MissingAttachmentManifest,
                MissingCertificateCatalog,
                MissingErasureEvidenceCatalog,
                MissingManifest,
                MissingSigningKeyRegistry,
                PostErasureUse,
                PostErasureWrap,
                PostureDeclarationDigestMismatch,
                PresentationArtifactAttachmentMissing,
                PresentationArtifactContentMismatch,
                PrevCheckpointHashMismatch,
                PrevHashBreak,
                PrevHashMismatch,
                RegistryDigestMismatch,
                ResponseRefMismatch,
                RevokedAuthority,
                ScopeMismatch,
                StateContinuityMismatch,
                SignatureInvalid,
                SigningEventTimestampMismatch,
                SigningEventUnresolved,
                SigningKeyRegistryInvalid,
                SupersessionGraphCycle,
                SupersessionGraphHeadMismatch,
                SupersessionGraphInvalid,
                SupersessionGraphLinkageMismatch,
                SupersessionGraphUnbound,
                SupersessionPredecessorCheckpointMismatch,
                TimestampNanosOutOfRange,
                TimestampOrderViolation,
                TreeSizeInvalid,
                UnresolvableManifestKid,
                UnsupportedSuite,
                UserContentAttestationChainPositionMismatch,
                UserContentAttestationIdCollision,
                UserContentAttestationIdentityRequired,
                UserContentAttestationIdentitySubjectMismatch,
                UserContentAttestationIdentityTemporalInversion,
                UserContentAttestationIdentityUnresolved,
                UserContentAttestationIntentMalformed,
                UserContentAttestationKeyNotActive,
                UserContentAttestationOperatorInUserSlot,
                UserContentAttestationSignatureInvalid,
                UserContentAttestationTimestampMismatch,
            );
        };
    }

    macro_rules! unique_wire_strings {
        ($($v:ident),* $(,)?) => {
            #[test]
            fn verification_failure_kind_wire_strings_are_nonempty_and_unique() {
                let kinds = [$(VerificationFailureKind::$v),*];
                let mut seen = BTreeSet::<&'static str>::new();
                for k in kinds {
                    let wire = k.as_str();
                    assert!(!wire.is_empty(), "empty wire for {k:?}");
                    assert!(
                        seen.insert(wire),
                        "duplicate wire string {wire:?} for {k:?}"
                    );
                }
                assert_eq!(seen.len(), kinds.len());
            }
        };
    }

    all_verification_failure_kinds!(unique_wire_strings);

    #[test]
    fn verify_error_kind_bridges_to_matching_verification_failure_kind() {
        use VerifyErrorKind as Ek;
        let cases = [
            (
                Ek::IdempotencyKeyLengthInvalid,
                VerificationFailureKind::IdempotencyKeyLengthInvalid,
            ),
            (
                Ek::ErasureDestroyedAtAfterHost,
                VerificationFailureKind::ErasureDestroyedAtAfterHost,
            ),
            (Ek::MalformedCose, VerificationFailureKind::MalformedCose),
            (
                Ek::CertificateChainSummaryMismatch,
                VerificationFailureKind::CertificateChainSummaryMismatch,
            ),
            (
                Ek::LegacyTimestampFormat,
                VerificationFailureKind::LegacyTimestampFormat,
            ),
            (
                Ek::TimestampNanosOutOfRange,
                VerificationFailureKind::TimestampNanosOutOfRange,
            ),
            (
                Ek::KeyEntryAttributesShapeMismatch,
                VerificationFailureKind::KeyEntryAttributesShapeMismatch,
            ),
        ];
        for (ek, fk) in cases {
            assert_eq!(ek.as_str(), fk.as_str());
            assert_eq!(ek.verification_failure_kind(), fk);
        }
    }

    #[test]
    fn verification_failure_kind_display_matches_as_str() {
        let k = VerificationFailureKind::ExportZipInvalid;
        assert_eq!(k.to_string(), k.as_str());
    }
}
