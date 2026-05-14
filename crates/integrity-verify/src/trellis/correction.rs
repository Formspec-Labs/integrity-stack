use std::collections::BTreeMap;

use ciborium::Value;
use trellis_types::{map_lookup_array, map_lookup_map, map_lookup_optional_value, map_lookup_text};

use crate::trellis::parse::{decode_event_details, decode_value, readable_payload_bytes};
use crate::trellis::types::{
    CorrectionFieldValue, CorrectionPreservationOutcome, EventDetails, ParsedSign1,
};

const CORRECTION_AUTHORIZED_RECORD_KIND: &str = "correctionAuthorized";
const RESPONSE_CORRECTION_RECORD_KIND: &str = "responseCorrection";

pub(crate) fn finalize_correction_preservations(
    events: &[ParsedSign1],
    payload_blobs: Option<&BTreeMap<[u8; 32], Vec<u8>>>,
) -> Vec<CorrectionPreservationOutcome> {
    let mut outcomes = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let Ok(details) = decode_event_details(event) else {
            continue;
        };
        let payload_bytes = match payload_blobs {
            Some(blobs) => readable_payload_bytes(&details, blobs),
            None => readable_payload_bytes(&details, &BTreeMap::new()),
        };
        let Some(payload_bytes) = payload_bytes else {
            continue;
        };
        let Some(outcome) = correction_outcome_from_payload(index as u64, &details, &payload_bytes)
        else {
            continue;
        };
        outcomes.push(outcome);
    }
    outcomes
}

fn correction_outcome_from_payload(
    event_index: u64,
    details: &EventDetails,
    payload_bytes: &[u8],
) -> Option<CorrectionPreservationOutcome> {
    let value = decode_value(payload_bytes).ok()?;
    let map = value.as_map()?;
    let record_kind = map_lookup_text(map, "recordKind").ok()?;
    if record_kind != CORRECTION_AUTHORIZED_RECORD_KIND
        && record_kind != RESPONSE_CORRECTION_RECORD_KIND
    {
        return None;
    }
    let data = map_lookup_map(map, "data").ok()?;
    let target_event_hash = first_text(
        data,
        &[
            "correctionTargetEventHash",
            "targetEventHash",
            "priorEventHash",
        ],
    );
    let corrected_field_set = text_array(data, "correctedFieldSet").unwrap_or_default();
    let field_values = correction_field_values(data);

    Some(CorrectionPreservationOutcome {
        event_index,
        correction_event_hash: details.canonical_event_hash,
        target_event_hash,
        corrected_field_set,
        field_values,
    })
}

fn first_text(map: &[(Value, Value)], keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| map_lookup_text(map, key).ok())
}

fn text_array(map: &[(Value, Value)], key: &str) -> Option<Vec<String>> {
    let values = map_lookup_array(map, key).ok()?;
    Some(
        values
            .iter()
            .filter_map(Value::as_text)
            .map(ToOwned::to_owned)
            .collect(),
    )
}

fn correction_field_values(map: &[(Value, Value)]) -> Vec<CorrectionFieldValue> {
    let Some(Value::Array(rows)) = map_lookup_optional_value(map, "fieldValues") else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| {
            let row = row.as_map()?;
            let field_path = map_lookup_text(row, "path").ok()?;
            let original_value = map_lookup_optional_value(row, "originalValue")?;
            let corrected_value = map_lookup_optional_value(row, "correctedValue")?;
            Some(CorrectionFieldValue {
                field_path,
                original_value_cbor: encode_report_value(original_value),
                corrected_value_cbor: encode_report_value(corrected_value),
            })
        })
        .collect()
}

fn encode_report_value(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).expect("CBOR value encoding");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trellis::util::hex_string;

    #[test]
    fn correction_outcome_ignores_non_correction_record() {
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &Value::Map(vec![
                (
                    Value::Text("recordKind".into()),
                    Value::Text("determinationAmended".into()),
                ),
                (Value::Text("data".into()), Value::Map(Vec::new())),
            ]),
            &mut bytes,
        )
        .unwrap();
        let details = EventDetails {
            scope: Vec::new(),
            sequence: 0,
            authored_at: crate::trellis::types::TrellisTimestamp {
                seconds: 0,
                nanos: 0,
            },
            event_type: String::new(),
            classification: String::new(),
            prev_hash: None,
            author_event_hash: [0; 32],
            content_hash: [0; 32],
            canonical_event_hash: [0; 32],
            idempotency_key: b"id".to_vec(),
            payload_ref: crate::trellis::types::PayloadRef::Inline(bytes.clone()),
            profile_extensions: crate::trellis::types::ProfileExtensionMap::new(),
            wrap_recipients: Vec::new(),
        };

        assert!(correction_outcome_from_payload(0, &details, &bytes).is_none());
    }

    #[test]
    fn correction_field_values_encode_original_and_corrected_bytes() {
        let row = Value::Map(vec![
            (Value::Text("path".into()), Value::Text("/name".into())),
            (
                Value::Text("originalValue".into()),
                Value::Text("Jon".into()),
            ),
            (
                Value::Text("correctedValue".into()),
                Value::Text("John".into()),
            ),
        ]);
        let data = vec![(Value::Text("fieldValues".into()), Value::Array(vec![row]))];

        let values = correction_field_values(&data);

        assert_eq!(values.len(), 1);
        assert_eq!(values[0].field_path, "/name");
        assert_eq!(hex_string(&values[0].original_value_cbor), "634a6f6e");
        assert_eq!(hex_string(&values[0].corrected_value_cbor), "644a6f686e");
    }
}
