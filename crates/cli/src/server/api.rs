//! REST API endpoints for the ECAC Gateway.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

use super::state::AppState;
use super::static_files::serve_static;

#[cfg(feature = "serve")]
use super::state::PeerInfo;

/// Create the API router with all endpoints.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health & Info
        .route("/api/health", get(health))
        .route("/api/node", get(get_node_info))
        // State
        .route("/api/state", get(get_state))
        .route("/api/state/{obj}", get(get_object))
        .route("/api/state/{obj}/{field}", get(get_field))
        // Operations
        .route("/api/ops", get(list_ops))
        .route("/api/ops/{op_id}", get(get_op))
        // Trust
        .route("/api/trust", get(get_trust))
        // Peers (if networking enabled)
        .route("/api/node/peers", get(list_peers))
        .route("/api/node/peers", post(add_peer))
        // Write operations (if enabled)
        .route("/api/data", post(write_data))
        // Static files (fallback for UI)
        .fallback(serve_static)
        .with_state(state)
}

// ============================================================================
// Response Types
// ============================================================================

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    version: &'static str,
}

#[derive(Serialize)]
struct NodeInfoResponse {
    site_name: Option<String>,
    op_count: usize,
    head_count: usize,
    state_digest: String,
    db_path: String,
    allow_writes: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    libp2p_listen: Option<String>,
}

#[derive(Serialize)]
struct StateResponse {
    objects: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    digest: String,
}

#[derive(Serialize)]
struct OpView {
    op_id: String,
    author: String,
    hlc_ms: u64,
    hlc_logical: u32,
    parents: Vec<String>,
    payload_type: String,
    payload: serde_json::Value,
}

#[derive(Serialize)]
struct OpsListResponse {
    ops: Vec<OpView>,
    total: usize,
}

#[derive(Serialize)]
struct TrustResponse {
    issuers: Vec<IssuerView>,
}

#[derive(Serialize)]
struct IssuerView {
    issuer_id: String,
    keys: Vec<KeyView>,
}

#[derive(Serialize)]
struct KeyView {
    key_id: String,
    algo: String,
    pubkey: String,
    valid_from_ms: u64,
    valid_until_ms: u64,
    revoked: bool,
}

#[derive(Serialize)]
struct PeerView {
    peer_id: String,
    connected: bool,
}

#[derive(Serialize)]
struct PeersResponse {
    peers: Vec<PeerView>,
    networking_enabled: bool,
}

#[derive(Deserialize)]
struct AddPeerRequest {
    multiaddr: String,
}

#[derive(Deserialize)]
struct WriteDataRequest {
    object: String,
    field: String,
    value: String,
}

#[derive(Serialize)]
struct WriteResponse {
    ok: bool,
    op_id: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ============================================================================
// Handlers
// ============================================================================

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn get_node_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NodeInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ids = state.store.topo_ids().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let heads = state.store.heads(8).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let cached = state.get_or_refresh().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    #[cfg(feature = "serve")]
    let peer_id = state.get_peer_id().await;

    #[cfg(not(feature = "serve"))]
    let peer_id: Option<String> = None;

    let libp2p_listen = if state.networking_enabled() {
        state.config.libp2p_listen.clone()
    } else {
        None
    };

    Ok(Json(NodeInfoResponse {
        site_name: state.config.site_name.clone(),
        op_count: ids.len(),
        head_count: heads.len(),
        state_digest: hex::encode(cached.digest),
        db_path: state.config.db.display().to_string(),
        allow_writes: state.config.allow_writes,
        peer_id,
        libp2p_listen,
    }))
}

async fn get_state(
    State(state): State<Arc<AppState>>,
) -> Result<Json<StateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let cached = state.get_or_refresh().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    // Convert State to JSON-friendly format
    let mut objects: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();

    for (obj_name, fields) in &cached.state.objects {
        let mut field_map = BTreeMap::new();
        for (field_name, field_value) in fields {
            // Convert field value to JSON
            let json_val = match field_value {
                ecac_core::state::FieldValue::MV(mv) => {
                    let values: Vec<String> = mv
                        .values()
                        .iter()
                        .map(|v| String::from_utf8_lossy(v).to_string())
                        .collect();
                    if values.len() == 1 {
                        serde_json::Value::String(values[0].clone())
                    } else {
                        serde_json::json!({"concurrent_values": values})
                    }
                }
                ecac_core::state::FieldValue::Set(set) => {
                    let items: Vec<String> = set
                        .iter_present()
                        .map(|(_, v)| String::from_utf8_lossy(&v).to_string())
                        .collect();
                    serde_json::json!(items)
                }
            };
            field_map.insert(field_name.clone(), json_val);
        }
        objects.insert(obj_name.clone(), field_map);
    }

    Ok(Json(StateResponse {
        objects,
        digest: hex::encode(cached.digest),
    }))
}

async fn get_object(
    State(state): State<Arc<AppState>>,
    Path(obj): Path<String>,
) -> Result<Json<BTreeMap<String, serde_json::Value>>, (StatusCode, Json<ErrorResponse>)> {
    let cached = state.get_or_refresh().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let fields = cached.state.objects.get(&obj).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Object '{}' not found", obj),
            }),
        )
    })?;

    let mut field_map = BTreeMap::new();
    for (field_name, field_value) in fields {
        let json_val = match field_value {
            ecac_core::state::FieldValue::MV(mv) => {
                let values: Vec<String> = mv
                    .values()
                    .iter()
                    .map(|v| String::from_utf8_lossy(v).to_string())
                    .collect();
                if values.len() == 1 {
                    serde_json::Value::String(values[0].clone())
                } else {
                    serde_json::json!({"concurrent_values": values})
                }
            }
            ecac_core::state::FieldValue::Set(set) => {
                let items: Vec<String> = set
                    .iter_present()
                    .map(|(_, v)| String::from_utf8_lossy(&v).to_string())
                    .collect();
                serde_json::json!(items)
            }
        };
        field_map.insert(field_name.clone(), json_val);
    }

    Ok(Json(field_map))
}

async fn get_field(
    State(state): State<Arc<AppState>>,
    Path((obj, field)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let cached = state.get_or_refresh().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let fields = cached.state.objects.get(&obj).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Object '{}' not found", obj),
            }),
        )
    })?;

    let field_value = fields.get(&field).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Field '{}.{}' not found", obj, field),
            }),
        )
    })?;

    let json_val = match field_value {
        ecac_core::state::FieldValue::MV(mv) => {
            let values: Vec<String> = mv
                .values()
                .iter()
                .map(|v| String::from_utf8_lossy(v).to_string())
                .collect();
            if values.len() == 1 {
                serde_json::Value::String(values[0].clone())
            } else {
                serde_json::json!({"concurrent_values": values})
            }
        }
        ecac_core::state::FieldValue::Set(set) => {
            let items: Vec<String> = set
                .iter_present()
                .map(|(_, v)| String::from_utf8_lossy(&v).to_string())
                .collect();
            serde_json::json!(items)
        }
    };

    Ok(Json(json_val))
}

async fn list_ops(
    State(state): State<Arc<AppState>>,
) -> Result<Json<OpsListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ids = state.store.topo_ids().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let total = ids.len();

    // Get last 50 ops (most recent first)
    let recent_ids: Vec<_> = ids.into_iter().rev().take(50).collect();
    let op_bytes = state.store.load_ops_cbor(&recent_ids).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let mut ops = Vec::with_capacity(op_bytes.len());
    for bytes in &op_bytes {
        let op: ecac_core::op::Op = serde_cbor::from_slice(bytes).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

        let (payload_type, payload) = match &op.header.payload {
            ecac_core::op::Payload::Data { key, value } => (
                "Data",
                serde_json::json!({
                    "key": key,
                    "value": String::from_utf8_lossy(value)
                }),
            ),
            ecac_core::op::Payload::Grant {
                subject_pk,
                cred_hash,
            } => (
                "Grant",
                serde_json::json!({
                    "subject_pk": hex::encode(subject_pk),
                    "cred_hash": hex::encode(cred_hash)
                }),
            ),
            ecac_core::op::Payload::Revoke {
                subject_pk,
                role,
                scope_tags,
                at,
            } => (
                "Revoke",
                serde_json::json!({
                    "subject_pk": hex::encode(subject_pk),
                    "role": role,
                    "scope_tags": scope_tags,
                    "at": at
                }),
            ),
            ecac_core::op::Payload::Credential {
                cred_id,
                cred_bytes,
                format,
            } => (
                "Credential",
                serde_json::json!({
                    "cred_id": cred_id,
                    "format": format,
                    "bytes_len": cred_bytes.len()
                }),
            ),
            ecac_core::op::Payload::IssuerKey {
                issuer_id,
                key_id,
                algo,
                pubkey,
                valid_from_ms,
                valid_until_ms,
                ..
            } => (
                "IssuerKey",
                serde_json::json!({
                    "issuer_id": issuer_id,
                    "key_id": key_id,
                    "algo": algo,
                    "pubkey": hex::encode(pubkey),
                    "valid_from_ms": valid_from_ms,
                    "valid_until_ms": valid_until_ms
                }),
            ),
            _ => ("Other", serde_json::json!({})),
        };

        ops.push(OpView {
            op_id: hex::encode(op.op_id),
            author: hex::encode(&op.header.author_pk),
            hlc_ms: op.header.hlc.physical_ms,
            hlc_logical: op.header.hlc.logical,
            parents: op.header.parents.iter().map(hex::encode).collect(),
            payload_type: payload_type.to_string(),
            payload,
        });
    }

    Ok(Json(OpsListResponse { ops, total }))
}

async fn get_op(
    State(state): State<Arc<AppState>>,
    Path(op_id_hex): Path<String>,
) -> Result<Json<OpView>, (StatusCode, Json<ErrorResponse>)> {
    let op_id_bytes = hex::decode(&op_id_hex).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid op_id hex: {}", e),
            }),
        )
    })?;

    if op_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "op_id must be 32 bytes".to_string(),
            }),
        ));
    }

    let mut op_id = [0u8; 32];
    op_id.copy_from_slice(&op_id_bytes);

    let bytes = state
        .store
        .get_op_bytes(&op_id)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Op not found".to_string(),
                }),
            )
        })?;

    let op: ecac_core::op::Op = serde_cbor::from_slice(&bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let (payload_type, payload) = match &op.header.payload {
        ecac_core::op::Payload::Data { key, value } => (
            "Data",
            serde_json::json!({
                "key": key,
                "value": String::from_utf8_lossy(value)
            }),
        ),
        ecac_core::op::Payload::Grant {
            subject_pk,
            cred_hash,
        } => (
            "Grant",
            serde_json::json!({
                "subject_pk": hex::encode(subject_pk),
                "cred_hash": hex::encode(cred_hash)
            }),
        ),
        _ => ("Other", serde_json::json!({})),
    };

    Ok(Json(OpView {
        op_id: hex::encode(op.op_id),
        author: hex::encode(&op.header.author_pk),
        hlc_ms: op.header.hlc.physical_ms,
        hlc_logical: op.header.hlc.logical,
        parents: op.header.parents.iter().map(hex::encode).collect(),
        payload_type: payload_type.to_string(),
        payload,
    }))
}

async fn get_trust(
    State(state): State<Arc<AppState>>,
) -> Result<Json<TrustResponse>, (StatusCode, Json<ErrorResponse>)> {
    let cached = state.get_or_refresh().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let mut issuers = Vec::new();

    for (issuer_id, keys_map) in &cached.trust_view.issuer_keys {
        let mut keys = Vec::new();
        for (key_id, record) in keys_map {
            keys.push(KeyView {
                key_id: key_id.clone(),
                algo: record.algo.clone(),
                pubkey: hex::encode(&record.pubkey),
                valid_from_ms: record.valid_from_ms,
                valid_until_ms: record.valid_until_ms,
                revoked: record.revoked_at_ms.is_some(),
            });
        }
        issuers.push(IssuerView {
            issuer_id: issuer_id.clone(),
            keys,
        });
    }

    Ok(Json(TrustResponse { issuers }))
}

async fn list_peers(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PeersResponse>, (StatusCode, Json<ErrorResponse>)> {
    #[cfg(feature = "serve")]
    {
        if state.networking_enabled() {
            let peer_infos = state.get_peers().await;
            let peers: Vec<PeerView> = peer_infos
                .into_iter()
                .map(|p| PeerView {
                    peer_id: p.peer_id,
                    connected: p.connected,
                })
                .collect();

            return Ok(Json(PeersResponse {
                peers,
                networking_enabled: true,
            }));
        }
    }

    Ok(Json(PeersResponse {
        peers: vec![],
        networking_enabled: state.networking_enabled(),
    }))
}

async fn add_peer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddPeerRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    #[cfg(feature = "serve")]
    {
        if state.networking_enabled() {
            match state.add_peer(req.multiaddr).await {
                Ok(peer_id) => {
                    return Ok(Json(serde_json::json!({
                        "ok": true,
                        "peer_id": peer_id
                    })));
                }
                Err(e) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse { error: e }),
                    ));
                }
            }
        }
    }

    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: "Networking not enabled".to_string(),
        }),
    ))
}

async fn write_data(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WriteDataRequest>,
) -> Result<Json<WriteResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !state.config.allow_writes {
        return Ok(Json(WriteResponse {
            ok: false,
            op_id: None,
            error: Some("Write operations not enabled (use --allow-writes)".to_string()),
        }));
    }

    // Generate a temporary keypair for demo writes
    // In production, this would use a configured identity
    let (sk, vk) = ecac_core::crypto::generate_keypair();
    let vk_bytes = ecac_core::crypto::vk_to_bytes(&vk);

    // Get current heads as parents
    let parents = state.store.heads(8).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    // Create HLC from current time
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let hlc = ecac_core::hlc::Hlc::new(now_ms, 0);

    // Create the op using MV register key format
    let key = format!("mv:{}:{}", req.object, req.field);
    let payload = ecac_core::op::Payload::Data {
        key,
        value: req.value.into_bytes(),
    };
    let op = ecac_core::op::Op::new(parents, hlc, vk_bytes, payload, &sk);
    let op_id = op.op_id;

    // Serialize and store
    let bytes = ecac_core::serialize::canonical_cbor(&op);
    state.store.put_op_cbor(&bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    // Invalidate cache
    state.invalidate_cache().await;

    // Trigger announcement to peers (if networking enabled)
    #[cfg(feature = "serve")]
    {
        let _ = state.announce().await;
    }

    Ok(Json(WriteResponse {
        ok: true,
        op_id: Some(hex::encode(op_id)),
        error: None,
    }))
}
