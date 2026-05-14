use std::collections::BTreeSet;

use serde_json::Value as JsonValue;
use trellis_types::sha256_bytes;

use crate::trellis::export::{parse_export_zip, verify_export_zip};
use crate::trellis::kinds::VerificationFailureKind;
use crate::trellis::parse::{
    decode_event_details, decode_value, parse_sign1_bytes,
    parse_supersession_graph_export_extension,
};
use crate::trellis::types::{
    ExportArchive, ParsedSign1, SupersedesChainIdDetails, SupersessionGraph,
    SupersessionGraphExportExtension, SupersessionGraphPredecessor, VerificationFailure,
    VerificationReport,
};
use crate::trellis::util::{hex_decode, hex_string};

const SUPERSESSION_GRAPH_MEMBER: &str = "064-supersession-graph.json";
const PREDECESSOR_BUNDLE_PREFIX: &str = "070-predecessors/";

pub(crate) fn verify_supersession_graph(
    archive: &ExportArchive,
    events: &[ParsedSign1],
    scope: &[u8],
    extension: &SupersessionGraphExportExtension,
    report: &mut VerificationReport,
) {
    let Some(graph_bytes) = archive.members.get(SUPERSESSION_GRAPH_MEMBER) else {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::SupersessionGraphInvalid,
            SUPERSESSION_GRAPH_MEMBER,
        ));
        return;
    };

    if sha256_bytes(graph_bytes) != extension.graph_digest {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::SupersessionGraphInvalid,
            SUPERSESSION_GRAPH_MEMBER,
        ));
        return;
    }

    let graph = match parse_supersession_graph(graph_bytes) {
        Ok(graph) => graph,
        Err(error) => {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::SupersessionGraphInvalid,
                format!("{SUPERSESSION_GRAPH_MEMBER}/{error}"),
            ));
            return;
        }
    };

    if graph.predecessors.len() as u64 != extension.predecessor_count {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::SupersessionGraphInvalid,
            SUPERSESSION_GRAPH_MEMBER,
        ));
    }

    if graph.head_chain_id != scope {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::SupersessionGraphHeadMismatch,
            SUPERSESSION_GRAPH_MEMBER,
        ));
    }

    verify_graph_linkage(events, &graph, report);
    verify_graph_cycle(&graph, report);
    let mut traversal_path = BTreeSet::new();
    traversal_path.insert(graph.head_chain_id.clone());
    verify_predecessor_bundles(archive, &graph, &mut traversal_path, report);
}

pub(crate) fn verify_unbound_supersession_graph(
    archive: &ExportArchive,
    extension_present: bool,
    report: &mut VerificationReport,
) {
    if !extension_present && archive.members.contains_key(SUPERSESSION_GRAPH_MEMBER) {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::SupersessionGraphUnbound,
            SUPERSESSION_GRAPH_MEMBER,
        ));
    }
}

fn verify_graph_linkage(
    events: &[ParsedSign1],
    graph: &SupersessionGraph,
    report: &mut VerificationReport,
) {
    for event in events {
        let Ok(details) = decode_event_details(event) else {
            continue;
        };
        let Some(linkage) = details.supersedes_chain() else {
            continue;
        };
        if !graph_contains_linkage(graph, &linkage) {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::SupersessionGraphLinkageMismatch,
                hex_string(&details.canonical_event_hash),
            ));
        }
    }
}

fn graph_contains_linkage(graph: &SupersessionGraph, linkage: &SupersedesChainIdDetails) -> bool {
    graph.predecessors.iter().any(|row| {
        row.chain_id == linkage.chain_id && row.checkpoint_hash == linkage.checkpoint_hash
    })
}

fn verify_graph_cycle(graph: &SupersessionGraph, report: &mut VerificationReport) {
    let mut seen = BTreeSet::new();
    for row in &graph.predecessors {
        if row.chain_id == graph.head_chain_id || !seen.insert(row.chain_id.clone()) {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::SupersessionGraphCycle,
                SUPERSESSION_GRAPH_MEMBER,
            ));
            return;
        }
    }
}

fn verify_predecessor_bundles(
    archive: &ExportArchive,
    graph: &SupersessionGraph,
    traversal_path: &mut BTreeSet<Vec<u8>>,
    report: &mut VerificationReport,
) {
    for row in &graph.predecessors {
        if !traversal_path.insert(row.chain_id.clone()) {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::SupersessionGraphCycle,
                SUPERSESSION_GRAPH_MEMBER,
            ));
            continue;
        }
        let Some(bundle_path) = &row.bundle_path else {
            traversal_path.remove(&row.chain_id);
            continue;
        };
        let Some(bundle_bytes) = archive.members.get(bundle_path) else {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::SupersessionPredecessorCheckpointMismatch,
                bundle_path,
            ));
            traversal_path.remove(&row.chain_id);
            continue;
        };
        let nested_report = verify_export_zip(bundle_bytes);
        if !nested_report.structure_verified || !nested_report.integrity_verified {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::SupersessionPredecessorCheckpointMismatch,
                bundle_path,
            ));
            traversal_path.remove(&row.chain_id);
            continue;
        }
        match export_manifest_info_from_bytes(bundle_bytes) {
            Ok(info) if info.head_checkpoint_digest == row.checkpoint_hash => {
                if info.scope != row.chain_id {
                    report.event_failures.push(VerificationFailure::new(
                        VerificationFailureKind::SupersessionPredecessorCheckpointMismatch,
                        bundle_path,
                    ));
                } else if let Some((nested_archive, nested_graph)) =
                    nested_supersession_graph(bundle_bytes, &info, report)
                {
                    verify_predecessor_bundles(
                        &nested_archive,
                        &nested_graph,
                        traversal_path,
                        report,
                    );
                }
            }
            Ok(_) | Err(_) => report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::SupersessionPredecessorCheckpointMismatch,
                bundle_path,
            )),
        }
        traversal_path.remove(&row.chain_id);
    }
}

fn nested_supersession_graph(
    export_zip: &[u8],
    info: &ExportManifestInfo,
    report: &mut VerificationReport,
) -> Option<(ExportArchive, SupersessionGraph)> {
    let extension = info.supersession_extension.as_ref()?;
    let archive = match parse_export_zip(export_zip) {
        Ok(archive) => archive,
        Err(_) => return None,
    };
    let Some(graph_bytes) = archive.members.get(SUPERSESSION_GRAPH_MEMBER) else {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::SupersessionGraphInvalid,
            SUPERSESSION_GRAPH_MEMBER,
        ));
        return None;
    };
    if sha256_bytes(graph_bytes) != extension.graph_digest {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::SupersessionGraphInvalid,
            SUPERSESSION_GRAPH_MEMBER,
        ));
        return None;
    }
    let graph = match parse_supersession_graph(graph_bytes) {
        Ok(graph) => graph,
        Err(error) => {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::SupersessionGraphInvalid,
                format!("{SUPERSESSION_GRAPH_MEMBER}/{error}"),
            ));
            return None;
        }
    };
    if graph.predecessors.len() as u64 != extension.predecessor_count {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::SupersessionGraphInvalid,
            SUPERSESSION_GRAPH_MEMBER,
        ));
    }
    if graph.head_chain_id != info.scope {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::SupersessionGraphHeadMismatch,
            SUPERSESSION_GRAPH_MEMBER,
        ));
    }
    Some((archive, graph))
}

pub(crate) fn parse_supersession_graph(bytes: &[u8]) -> Result<SupersessionGraph, String> {
    if bytes.starts_with(b"\xef\xbb\xbf") {
        return Err("BOM is forbidden".to_string());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "graph is not UTF-8".to_string())?;
    if !text.ends_with('\n') || text[..text.len() - 1].contains('\n') {
        return Err("graph must have one trailing newline".to_string());
    }
    let value: JsonValue =
        serde_json::from_str(text).map_err(|error| format!("invalid JSON: {error}"))?;
    let graph = parse_graph_value(&value)?;
    let canonical = render_supersession_graph(&graph);
    if canonical.as_bytes() != bytes {
        return Err("graph is not Trellis canonical JSON".to_string());
    }
    Ok(graph)
}

fn parse_graph_value(value: &JsonValue) -> Result<SupersessionGraph, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "graph root is not an object".to_string())?;
    let keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    if keys.as_slice() != ["head_chain_id", "predecessors"] {
        return Err("graph root keys are not exactly head_chain_id/predecessors".to_string());
    }
    let head_chain_id = parse_lower_hex_string(
        object
            .get("head_chain_id")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "head_chain_id is not a string".to_string())?,
        "head_chain_id",
    )?;
    let predecessor_values = object
        .get("predecessors")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "predecessors is not an array".to_string())?;
    let mut predecessors = Vec::with_capacity(predecessor_values.len());
    for value in predecessor_values {
        predecessors.push(parse_predecessor_value(value)?);
    }
    Ok(SupersessionGraph {
        head_chain_id,
        predecessors,
    })
}

fn parse_predecessor_value(value: &JsonValue) -> Result<SupersessionGraphPredecessor, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "predecessor row is not an object".to_string())?;
    let keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    if keys.as_slice() != ["bundle_path", "chain_id", "checkpoint_hash"] {
        return Err(
            "predecessor row keys are not exactly bundle_path/chain_id/checkpoint_hash".to_string(),
        );
    }
    let bundle_path = match object.get("bundle_path") {
        Some(JsonValue::Null) => None,
        Some(JsonValue::String(path)) => {
            if !path.is_ascii() || !path.starts_with(PREDECESSOR_BUNDLE_PREFIX) {
                return Err("bundle_path must be an ASCII 070-predecessors/ path".to_string());
            }
            Some(path.clone())
        }
        _ => return Err("bundle_path must be null or a string".to_string()),
    };
    let chain_id = parse_lower_hex_string(
        object
            .get("chain_id")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "chain_id is not a string".to_string())?,
        "chain_id",
    )?;
    let checkpoint_hash = parse_lower_hex_string(
        object
            .get("checkpoint_hash")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "checkpoint_hash is not a string".to_string())?,
        "checkpoint_hash",
    )?;
    let checkpoint_hash: [u8; 32] = checkpoint_hash
        .as_slice()
        .try_into()
        .map_err(|_| "checkpoint_hash must decode to 32 bytes".to_string())?;
    Ok(SupersessionGraphPredecessor {
        chain_id,
        checkpoint_hash,
        bundle_path,
    })
}

fn parse_lower_hex_string(value: &str, field: &str) -> Result<Vec<u8>, String> {
    let decoded = hex_decode(value).map_err(|error| format!("{field} is invalid hex: {error}"))?;
    if hex_string(&decoded) != value {
        return Err(format!("{field} must be lowercase hexadecimal"));
    }
    Ok(decoded)
}

fn render_supersession_graph(graph: &SupersessionGraph) -> String {
    let mut text = String::new();
    text.push_str("{\"head_chain_id\":\"");
    text.push_str(&hex_string(&graph.head_chain_id));
    text.push_str("\",\"predecessors\":[");
    for (index, row) in graph.predecessors.iter().enumerate() {
        if index > 0 {
            text.push(',');
        }
        text.push_str("{\"bundle_path\":");
        match &row.bundle_path {
            Some(path) => {
                text.push('"');
                text.push_str(path);
                text.push('"');
            }
            None => text.push_str("null"),
        }
        text.push_str(",\"chain_id\":\"");
        text.push_str(&hex_string(&row.chain_id));
        text.push_str("\",\"checkpoint_hash\":\"");
        text.push_str(&hex_string(&row.checkpoint_hash));
        text.push_str("\"}");
    }
    text.push_str("]}\n");
    text
}

struct ExportManifestInfo {
    scope: Vec<u8>,
    head_checkpoint_digest: [u8; 32],
    supersession_extension: Option<SupersessionGraphExportExtension>,
}

fn export_manifest_info_from_bytes(export_zip: &[u8]) -> Result<ExportManifestInfo, String> {
    let archive = parse_export_zip(export_zip).map_err(|error| error.to_string())?;
    let manifest_bytes = archive
        .members
        .get("000-manifest.cbor")
        .ok_or_else(|| "missing 000-manifest.cbor".to_string())?;
    let manifest = parse_sign1_bytes(manifest_bytes)
        .map_err(|error| format!("invalid manifest COSE: {error}"))?;
    let payload = manifest
        .payload
        .ok_or_else(|| "manifest payload is detached".to_string())?;
    let value = decode_value(&payload).map_err(|error| format!("invalid payload: {error}"))?;
    let map = value
        .as_map()
        .ok_or_else(|| "manifest payload root is not a map".to_string())?;
    let scope = trellis_types::map_lookup_bytes(map, "scope").map_err(|error| error.to_string())?;
    let digest = trellis_types::map_lookup_fixed_bytes(map, "head_checkpoint_digest", 32)
        .map_err(|error| error.to_string())?;
    let head_checkpoint_digest = digest
        .as_slice()
        .try_into()
        .map_err(|_| "head checkpoint digest is not 32 bytes".to_string())?;
    let supersession_extension =
        parse_supersession_graph_export_extension(map).map_err(|error| error.to_string())?;
    Ok(ExportManifestInfo {
        scope,
        head_checkpoint_digest,
        supersession_extension,
    })
}
