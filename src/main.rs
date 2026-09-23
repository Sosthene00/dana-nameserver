mod api_structs;

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::Json as AxumJson,
    routing::{get, post},
};
use spdk_wallet::bip321::Bip321Uri;
use spdk_wallet::client::{parse_sp, parse_tsp, SpUriExtension};
use log::{debug, error, info, warn};
use rand::RngCore;
use reqwest::Client;
use silentpayments::{Network as SpNetwork, SilentPaymentCode};
use dnssec_prover::{query::{ProofBuildingError, build_txt_proof_async}, rr::{Name, RR}, ser::parse_rr_stream, validation::verify_rr_stream};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tokio::sync::{Mutex, RwLock};

use crate::api_structs::{
    ApiResponse, ChallengeRequest, ChallengeResponse, CloudflareRequest, GetInfoResponse,
    LookupRequest, LookupResponse, PrefixSearchRequest, PrefixSearchResponse, Record,
    RegisterRequest, RegisterResponse,
};


const CLOUDFLARE_API_BASE_URL: &str = "https://api.cloudflare.com/client/v4";

/// Base URL for the Cloudflare API. Defaults to the real API; override with the
/// `CLOUDFLARE_API_BASE_URL` env var to point at a local mock server for testing.
fn cloudflare_base_url() -> String {
    std::env::var("CLOUDFLARE_API_BASE_URL")
        .unwrap_or_else(|_| CLOUDFLARE_API_BASE_URL.to_string())
}

// challenge-auth (branch 1): nonce TTL and rate-limit bounds
const NONCE_TTL_SECS: u64 = 300; // 5 minutes
const MAX_PENDING_NONCES: u64 = 10_000;
const MAX_NONCES_PER_PEER: u32 = 10;
// Upper bound on distinct peer keys retained in peer_nonce_counts. A brand-new
// peer past this cap is refused with 429 until expired/consumed slots are pruned.
const MAX_TRACKED_PEERS: usize = 1_000;
// Upper bound on distinct names retained in the per-name registration lock map.
// Once exceeded, locks not currently held are pruned before inserting a new
// entrant, so one-shot names cannot grow the map unboundedly.
const MAX_TRACKED_NAMES: usize = 10_000;

/// A nonce issued by the challenge endpoint. Bound to the user_name / SP
/// address / domain it was minted for so a later claim must match all three.
#[derive(Clone)]
struct NonceEntry {
    user_name: String,
    sp_address: String,
    domain: String,
    expires_at: Instant,
}

impl NonceEntry {
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

#[derive(Clone)]
struct AppState {
    zone_id: String,
    api_token: String,
    domain: String,
    sp_to_dana: Arc<RwLock<HashMap<SilentPaymentCode, Vec<String>>>>,
    dana_to_sp: Arc<RwLock<HashMap<String, SilentPaymentCode>>>,
    // we only accept registration requests from this network
    network: SpNetwork,
    // Challenge-response nonce store for signature auth
    nonce_store: Arc<RwLock<HashMap<String, NonceEntry>>>,
    // Per-peer outstanding nonce counts (keyed by the validated SP address string) for rate limiting
    peer_nonce_counts: Arc<RwLock<HashMap<String, u32>>>,
    // Per-name async mutexes serialising the check-then-create critical section of
    // /register, keyed by the canonicalised lowercase DNS label (see name_lock).
    name_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    max_pending_nonces: u64,
    max_nonces_per_peer: u32,
}

async fn handle_get_info(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, AxumJson<GetInfoResponse>) {
    (
        StatusCode::OK,
        AxumJson(GetInfoResponse {
            domain: state.domain.clone(),
            network: state.network,
        }),
    )
}

static DNS_RESOLVER_ADDR: SocketAddr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(1, 1, 1, 1), 53));

fn has_bitcoin_prefix(data: &[u8]) -> bool {
    data.starts_with(b"bitcoin:")
}

/// Validate that a string is a well-formed AND already-canonical DNS label
/// (RFC 1035): 1-63 characters drawn from `[a-z0-9-]`, with no leading,
/// trailing or consecutive hyphens.
///
/// Uppercase is rejected explicitly rather than silently folded: DNS is
/// case-insensitive, so admitting "Alice" alongside "alice" would create two
/// distinct server-side keys (nonce maps, registration maps, per-name locks)
/// that collapse onto ONE TXT name - a hijack/duplicate window. Callers
/// canonicalise at the boundary: /challenge requires already-canonical input
/// (400 on mismatch) and /register re-validates before the nonce claim, so
/// the wallet/server contract stays deterministic.
fn validate_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    if name.starts_with('-') || name.ends_with('-') || name.contains("--") {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Issue a single-use nonce for the challenge-response handshake and state the
/// exact message the client is expected to sign: the literal prefix
/// `dana-register` followed by the colon-separated fields network_key, nonce,
/// user_name, domain, in that order - `dana-register:{network_key}:{nonce}:{user_name}:{domain}`.
/// Assemble it with `challenge_message`, the single source of truth, and sign it
/// with the spend secret key whose public key derives the claimed SP address; the
/// resulting Schnorr signature is echoed back on the register request to be verified.
async fn handle_challenge(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ChallengeRequest>,
) -> (StatusCode, AxumJson<ChallengeResponse>) {
    // Domain must match the one we serve
    if request.domain != state.domain {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(ChallengeResponse {
                id: request.id,
                message: format!("Server registers for domain: {}", state.domain),
                nonce: String::new(),
                network_key: String::new(),
                expires_at: 0,
            }),
        );
    }

    // User name is required and must be DNS-valid (we bind the nonce to it)
    if request.user_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(ChallengeResponse {
                id: request.id,
                message: "User name is required".to_string(),
                nonce: String::new(),
                network_key: String::new(),
                expires_at: 0,
            }),
        );
    }
    if !validate_dns_name(&request.user_name) {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(ChallengeResponse {
                id: request.id,
                message:
                    "Invalid user name: must be a canonical RFC 1035 label (lowercase ASCII alphanumeric and hyphens, 1-63 chars, no leading/trailing/consecutive hyphen)"
                        .to_string(),
                nonce: String::new(),
                network_key: String::new(),
                expires_at: 0,
            }),
        );
    }

    // Parse and validate the SP address
    let sp_address = match SilentPaymentCode::try_from(request.sp_address.clone()) {
        Ok(addr) => {
            debug!("Valid SP address: {}", addr);
            addr
        }
        Err(e) => {
            error!("Invalid SP address '{}': {}", request.sp_address, e);
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(ChallengeResponse {
                    id: request.id,
                    message: format!("Invalid SP address: {}", e),
                    nonce: String::new(),
                    network_key: String::new(),
                    expires_at: 0,
                }),
            );
        }
    };

    // Network must match the one this server serves
    if sp_address.network() != state.network {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(ChallengeResponse {
                id: request.id,
                message: format!(
                    "Address has wrong network type: {:?}, expected: {:?}",
                    sp_address.network(),
                    state.network
                ),
                nonce: String::new(),
                network_key: String::new(),
                expires_at: 0,
            }),
        );
    }

    // We modify the key depending on the network (mainnet vs signet/testnet)
    let network_key = match sp_address.network() {
        SpNetwork::Mainnet => "sp",
        SpNetwork::Testnet => "tsp",
        SpNetwork::Regtest => {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(ChallengeResponse {
                    id: request.id,
                    message: "Can't issue a challenge for regtest addresses".to_string(),
                    nonce: String::new(),
                    network_key: String::new(),
                    expires_at: 0,
                }),
            );
        }
    };

    // Rate limiting: the aggregate cap is measured against the live nonce store
    // (non-expired entries) and the per-peer caps against peer_nonce_counts, so no
    // standalone counter can be skewed by a claim/cleanup interleaving
    // (R2 t_24b413be).
    // The peer key is the validated SP address, never the client-supplied request id.
    let peer = sp_address.to_string();
    {
        let mut counts = state.peer_nonce_counts.write().await;
        // Derive the aggregate pending count from the store itself (live, i.e.
        // non-expired entries only): no shadow atomics for claim/cleanup
        // interleavings to desynchronize.
        let live_pending = state
            .nonce_store
            .read()
            .await
            .values()
            .filter(|entry| !entry.is_expired())
            .count() as u64;
        if live_pending >= state.max_pending_nonces {
            warn!("Rejecting challenge request: nonce store at capacity");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                AxumJson(ChallengeResponse {
                    id: request.id,
                    message: "Too many pending challenges, please retry later".to_string(),
                    nonce: String::new(),
                    network_key: String::new(),
                    expires_at: 0,
                }),
            );
        }
        if !counts.contains_key(&peer) && counts.len() >= MAX_TRACKED_PEERS {
            warn!("Rejecting challenge request: tracked peer map at capacity");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                AxumJson(ChallengeResponse {
                    id: request.id,
                    message: "Too many distinct peers pending challenges, please retry later"
                        .to_string(),
                    nonce: String::new(),
                    network_key: String::new(),
                    expires_at: 0,
                }),
            );
        }
        let count = counts.entry(peer.clone()).or_insert(0);
        if *count >= state.max_nonces_per_peer {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                AxumJson(ChallengeResponse {
                    id: request.id,
                    message: "Too many pending challenges from this peer".to_string(),
                    nonce: String::new(),
                    network_key: String::new(),
                    expires_at: 0,
                }),
            );
        }
        *count += 1;
    }

    // Mint a 32-byte random nonce, hex-encoded
    let mut nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);

    // Store the nonce entry under the write guard
    {
        let mut store = state.nonce_store.write().await;
        store.insert(
            nonce.clone(),
            NonceEntry {
                user_name: request.user_name.clone(),
                sp_address: sp_address.to_string(),
                domain: state.domain.clone(),
                expires_at: Instant::now() + Duration::from_secs(NONCE_TTL_SECS),
            },
        );
    }

    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + NONCE_TTL_SECS)
        .unwrap_or(0);

    info!(
        "Generated nonce for user {} on domain {} (expires in {}s)",
        request.user_name, state.domain, NONCE_TTL_SECS
    );

    (
        StatusCode::OK,
        AxumJson(ChallengeResponse {
            id: request.id,
            message: challenge_message(network_key, &nonce, &request.user_name, &request.domain),
            nonce,
            network_key: network_key.to_string(),
            expires_at,
        }),
    )
}

/// Verify a Schnorr signature over `message` using the spend public key
/// derived from `sp_address`. The message is SHA-256 hashed before
/// verification, as required by the secp256k1 Schnorr signature scheme.
fn verify_schnorr_signature(
    signature_hex: &str,
    message: &str,
    sp_address: &SilentPaymentCode,
) -> Result<(), String> {
    use silentpayments::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};

    let sig_bytes = hex::decode(signature_hex).map_err(|e| format!("Invalid signature hex: {}", e))?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "Signature must be 64 bytes (got {})",
            sig_bytes.len()
        ));
    }
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("Invalid signature encoding: {}", e))?;

    // Spend public key from the SP address, converted to X-only
    let spend_pubkey = sp_address.m_pubkey();
    let pk_bytes = spend_pubkey.serialize();
    let x_only = XOnlyPublicKey::from_slice(&pk_bytes[1..])
        .map_err(|e| format!("Invalid X-only pubkey: {}", e))?;

    // SHA-256 hash the message
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(message.as_bytes());
    let msg = Message::from_digest_slice(&digest)
        .map_err(|e| format!("Invalid digest: {}", e))?;

    let secp = Secp256k1::new();
    secp.verify_schnorr(&sig, &msg, &x_only)
        .map_err(|e| format!("Signature verification failed: {}", e))
}

/// Atomically claim a nonce: it must exist, match the user_name / SP address /
/// domain, and not be expired. Claiming consumes it (single-use); on any later
/// failure the client must request a fresh challenge.
async fn claim_nonce(
    nonce_store: &Arc<RwLock<HashMap<String, NonceEntry>>>,
    nonce: &str,
    user_name: &str,
    sp_address: &str,
    domain: &str,
) -> Result<NonceEntry, String> {
    let mut store = nonce_store.write().await;
    let entry = match store.get(nonce) {
        Some(entry) => entry,
        None => {
            return Err("Invalid or missing nonce. Please call /challenge first.".to_string());
        }
    };
    if entry.is_expired() {
        return Err("Challenge nonce expired. Please request a new one.".to_string());
    }
    if entry.user_name != user_name || entry.sp_address != sp_address || entry.domain != domain {
        return Err("Nonce does not match this request. Request a new one.".to_string());
    }
    let claimed = store.remove(nonce).ok_or_else(|| {
        "Nonce already consumed or raced. Request a fresh challenge.".to_string()
    })?;
    drop(store);
    Ok(claimed)
}

/// Decrement a peer's outstanding-nonce counter, removing the key once it
/// reaches zero so dead per-peer entries cannot accumulate in the map.
fn decrement_peer_count(counts: &mut HashMap<String, u32>, peer: &str) {
    if let Some(count) = counts.get_mut(peer) {
        *count = count.saturating_sub(1);
    }
    if counts.get(peer) == Some(&0) {
        counts.remove(peer);
    }
}

/// Release one per-peer nonce slot after a nonce is consumed (the register
/// flow calls this whenever a claim succeeds).
async fn release_peer_nonce_slot(
    peer_nonce_counts: &Arc<RwLock<HashMap<String, u32>>>,
    peer: &str,
) {
    let mut counts = peer_nonce_counts.write().await;
    decrement_peer_count(&mut counts, peer);
}

/// Single source of truth for the message a client must sign: the literal prefix
/// `dana-register` followed by the colon-separated fields network_key, nonce,
/// user_name, domain, in that order.
    fn challenge_message(network_key: &str, nonce: &str, user_name: &str, domain: &str) -> String {
        format!("dana-register:{}:{}:{}:{}", network_key, nonce, user_name, domain)
    }

/// Remove expired nonce entries to bound the in-memory store, and decrement /
/// prune the per-peer counters for exactly the entries dropped in this pass.
async fn cleanup_expired_nonces(
    nonce_store: &Arc<RwLock<HashMap<String, NonceEntry>>>,
    peer_nonce_counts: &Arc<RwLock<HashMap<String, u32>>>,
) {
    let mut dropped_peers: Vec<String> = Vec::new();
    {
        let mut store = nonce_store.write().await;
        store.retain(|_, entry| {
            if entry.is_expired() {
                dropped_peers.push(entry.sp_address.clone());
                false
            } else {
                true
            }
        });
    }
    if !dropped_peers.is_empty() {
        let mut counts = peer_nonce_counts.write().await;
        for peer in &dropped_peers {
            decrement_peer_count(&mut counts, peer);
        }
    }
}

/// Canonical key for the per-name registration lock: DNS labels are
/// case-insensitive (RFC 1035), so the user name is lowercased before use.
/// Validation already restricts names to [a-z0-9-], so this never collides
/// distinct labels.
fn canonical_name_key(user_name: &str) -> String {
    user_name.to_lowercase()
}

/// Get (creating if absent) the per-name mutex guarding the DNS existence check
/// followed by TXT record creation in /register. Two concurrent, correctly
/// signed registrations for the same name take the same lock, so the second one
/// observes the record the first created instead of double-creating it.
///
/// The map is capped at MAX_TRACKED_NAMES: when that many names are tracked,
/// every lock not currently held is pruned before inserting a new entrant. Held
/// locks are never removed, so a guard obtained here always refers to the live
/// mutex for its name while any holder is inside the critical section.
async fn name_lock(
    locks: &Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    key: &str,
) -> Arc<Mutex<()>> {
    let mut map = locks.lock().await;
    if let Some(mtx) = map.get(key) {
        return mtx.clone();
    }
    if map.len() >= MAX_TRACKED_NAMES {
        // Keep only the locks a live holder is sitting on (try_lock fails while
        // held); idle entries are dropped to keep the map bounded.
        map.retain(|_, mtx| mtx.try_lock().is_err());
    }
    let mtx = Arc::new(Mutex::new(()));
    map.insert(key.to_string(), mtx.clone());
    mtx
}

async fn fetch_sp_address_from_txt_record(
    user_name: &str,
    domain: &str,
    network: SpNetwork,
) -> Result<Option<SilentPaymentCode>> {
    let dns_name = Name::try_from(format!("{}.user._bitcoin-payment.{}.", user_name, domain))
        .map_err(|_| anyhow::anyhow!("The provided HRN was too long to fit in a DNS name"))?;

    let proof = match build_txt_proof_async(DNS_RESOLVER_ADDR, &dns_name).await {
        Ok(proof) => proof,
        Err(e) => {
            let missing = e.get_ref().and_then(|inner| inner.downcast_ref::<ProofBuildingError>())
                .is_some_and(|p| {
                    matches!(
                        p,
                        ProofBuildingError::NoSuchName | ProofBuildingError::InvalidResponse
                    )
                });
            if missing {
                return Ok(None);
            }
            return Err(anyhow::anyhow!("DNS query for the HRN failed: {e}"));
        }
    };
    let rrs = parse_rr_stream(&proof.0).map_err(|_| anyhow::anyhow!("DNS proof could not be parsed"))?;
    let verified_rrs = verify_rr_stream(&rrs).map_err(|_| anyhow::anyhow!("DNSSEC validation failed"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("DNSSEC validation relies on a correct system clock"))?
        .as_secs();
    if now < verified_rrs.valid_from {
        return Err(anyhow::anyhow!("Some DNSSEC records are not yet valid. Check your system clock."));
    }
    if now > verified_rrs.expires {
        return Err(anyhow::anyhow!("Some DNSSEC records have expired. Check your system clock."));
    }

    let resolved_rrs = verified_rrs.resolve_name(&dns_name);

    let mut result: Option<Vec<u8>> = None;
    for rr in resolved_rrs {
        if let RR::Txt(txt) = rr {
            let data = txt.data.as_vec();
            if has_bitcoin_prefix(&data) {
                if result.is_some() {
                    return Err(anyhow::anyhow!(
                        "Multiple TXT records existed for the HRN, which is invalid"
                    ));
                }
                result = Some(data);
            }
        }
    }
    let res = match result {
        Some(data) => data,
        None => return Ok(None),
    };
    let uri_string = std::str::from_utf8(&res)
        .map_err(|_| anyhow::anyhow!("TXT record contained invalid UTF-8"))?;

    let uri = Bip321Uri::<SpUriExtension>::from_str(uri_string)
        .map_err(|_| anyhow::anyhow!("TXT record contained an invalid BIP-321 URI"))?;

    let addrs = match network {
        SpNetwork::Mainnet => parse_sp(uri.sp())
            .map_err(|_| anyhow::anyhow!("Failed to parse mainnet silent payment address"))?,
        _ => parse_tsp(uri.extensions().tsp())
            .map_err(|_| anyhow::anyhow!("Failed to parse testnet silent payment address"))?,
    };

    Ok(addrs.first().cloned())
}
async fn create_txt_record(
    client: &Client,
    zone_id: &str,
    api_token: &str,
    name: &str,
    content: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/zones/{}/dns_records", cloudflare_base_url(), zone_id);

    debug!("Creating TXT record: {} -> {}", name, content);
    debug!("Using Cloudflare API URL: {}", url);

    let record = CloudflareRequest {
        record_type: "TXT".to_string(),
        name: name.to_string(),
        content: serde_json::to_string(content)?,
        ttl: 3600, // 1 hour TTL
    };

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .header("Content-Type", "application/json")
        .json(&record)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        if let Some(id) = result["result"]["id"].as_str() {
            info!("Successfully created TXT record {} with ID: {}", name, id);
            Ok(Some(id.to_string()))
        } else {
            warn!(
                "Cloudflare API returned success but no record ID for {}",
                name
            );
            Ok(None)
        }
    } else {
        let error_text = response.text().await?;
        error!("Cloudflare API error for {}: {}", name, error_text);
        Ok(None)
    }
}

async fn list_bitcoin_records(
    zone_id: &str,
    api_token: &str,
    domain: &str,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/zones/{}/dns_records", cloudflare_base_url(), zone_id);
    info!(
        "Listing Bitcoin TXT records from Cloudflare API URL: {}",
        url
    );
    let client = Client::new();
    let resp = client
        .get(&url)
        .bearer_auth(api_token)
        .query(&[
            ("type", "TXT"),
            ("name.endswith", &format!("user._bitcoin-payment.{domain}")),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<ApiResponse>()
        .await?;

    info!(
        "Received {} Bitcoin TXT records from Cloudflare",
        resp.result.len()
    );

    debug!("Received Bitcoin TXT records: {:?}", resp.result);

    Ok(resp.result)
}

async fn handle_register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterRequest>,
) -> (StatusCode, AxumJson<RegisterResponse>) {
    // Just in case
    if state.zone_id.is_empty() || state.api_token.is_empty() {
        error!("Cloudflare credentials missing, DNS record creation failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            AxumJson(RegisterResponse {
                id: request.id,
                message: "Internal server error, please try again later".to_string(),
                dana_address: None,
                sp_address: None,
                dns_record_id: None,
            }),
        );
    }

    // If the domain asked by client is not the domain we're registering for, we return a bad request
    if request.domain != state.domain {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(RegisterResponse {
                id: request.id,
                message: format!("Server registers for domain: {}", state.domain),
                dana_address: None,
                sp_address: None,
                dns_record_id: None,
            }),
        );
    }

    // Validate SP address
    let sp_address =
        match silentpayments::SilentPaymentCode::try_from(request.sp_address.clone()) {
            Ok(sp_address) => {
                debug!("Valid SP address: {}", sp_address);
                sp_address
            }
            Err(e) => {
                error!("Invalid SP address '{}': {}", request.sp_address, e);
                return (
                    StatusCode::BAD_REQUEST,
                    AxumJson(RegisterResponse {
                        id: request.id,
                        message: format!("Invalid SP address: {}", e),
                        dana_address: None,
                        sp_address: None,
                        dns_record_id: None,
                    }),
                );
            }
        };

    if sp_address.network() != state.network {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(RegisterResponse {
                id: request.id,
                message: format!(
                    "Registered address has wrong network type: {:?}, expected: {:?}",
                    sp_address.network(),
                    state.network
                ),
                dana_address: None,
                sp_address: None,
                dns_record_id: None,
            }),
        );
    }

    // We modify the key depending on the network we're on (mainnet vs signet/testnet)
    let network_key = match sp_address.network() {
        SpNetwork::Mainnet => "sp",
        SpNetwork::Testnet => "tsp",
        SpNetwork::Regtest => {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: "Can't register regtest addresses".to_string(),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                }),
            );
        }
    };

    // if user_name is empty, we generate a random one
    let user_name = match request.user_name {
        Some(user_name) => user_name,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: "User name is required".to_string(),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                }),
            );
        }
    };

    // R5 (review Medium #5): /register accepts only already-canonical labels,
    // validated BEFORE the nonce claim so the compared strings match what
    // /challenge stored (which likewise requires the canonical form). DNS is
    // case-insensitive: silently lowercasing here would let "Alice" and "alice"
    // hold distinct map keys over one TXT name, so non-canonical input is
    // rejected explicitly (400) and the contract stays deterministic.
    if !validate_dns_name(&user_name) {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(RegisterResponse {
                id: request.id,
                message: "Invalid user name: must be a canonical RFC 1035 label (lowercase ASCII alphanumeric and hyphens, 1-63 chars, no leading/trailing/consecutive hyphen)".to_string(),
                dana_address: None,
                sp_address: None,
                dns_record_id: None,
            }),
        );
    }

    // ── Challenge-response enforcement ──
    // Refuse any DNS mutation unless the client presents a valid nonce issued
    // by /challenge AND a Schnorr signature over the challenge message
    // (dana-register:{network_key}:{nonce}:{user_name}:{domain}) signed with the spend private
    // key that derives the claimed SP address.
    let nonce = match request.nonce {
        Some(nonce) => nonce,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                AxumJson(RegisterResponse {
                    id: request.id.clone(),
                    message: "Missing nonce: call /challenge first to obtain a challenge nonce"
                        .to_string(),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                }),
            );
        }
    };
    let signature = match request.signature {
        Some(signature) => signature,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                AxumJson(RegisterResponse {
                    id: request.id.clone(),
                    message: "Missing signature: sign the challenge message with the spend private key"
                        .to_string(),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                }),
            );
        }
    };

    // Claim the single-use nonce: it must exist, not be expired, and match this
    // request's user_name / SP address / domain.
    let claimed = match claim_nonce(
        &state.nonce_store,
        &nonce,
        &user_name,
        &sp_address.to_string(),
        &state.domain,
    )
    .await
    {
        Ok(claimed) => {
            // The nonce is consumed: free this peer's rate-limit slot and drop the
            // key at zero so completed challenge-register cycles cannot pin entries
            // in peer_nonce_counts forever.
            release_peer_nonce_slot(&state.peer_nonce_counts, &sp_address.to_string()).await;
            claimed
        }
        Err(e) => {
            error!("Nonce claim failed for user {}: {}", user_name, e);
            return (
                StatusCode::UNAUTHORIZED,
                AxumJson(RegisterResponse {
                    id: request.id.clone(),
                    message: e,
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                }),
            );
        }
    };

    // Verify the Schnorr signature over the challenge message for this nonce.
    // The bindings below come from the CLAIMED entry, so they are exactly the
    // values claim_nonce just validated against this request.
    let message = challenge_message(network_key, &nonce, &claimed.user_name, &claimed.domain);
    if let Err(e) = verify_schnorr_signature(&signature, &message, &sp_address) {
        error!(
            "Signature verification failed for user {} on {}: {}",
            user_name, state.domain, e
        );
        return (
            StatusCode::UNAUTHORIZED,
            AxumJson(RegisterResponse {
                id: request.id.clone(),
                message: e,
                dana_address: None,
                sp_address: None,
                dns_record_id: None,
            }),
        );
    }
    info!(
        "Challenge-response verified for {}@{} (nonce {})",
        user_name, state.domain, nonce
    );

    // R4: the DNS existence check and the Cloudflare TXT create below form a
    // check-then-create critical section. Two concurrent, correctly signed
    // registrations for the same name could both observe 'absent' and both POST a
    // record; authentication does not close that race. Serialise them on a
    // per-name mutex (canonicalised lowercase label). The guard is scoped to the
    // check-then-create block only (dropped explicitly below) - never held across
    // the whole handler - and is taken after signature verification so an
    // unauthenticated request cannot contend for, or pin, a victim's lock.
    let held_name = canonical_name_key(&user_name);
    let name_mutex = name_lock(&state.name_locks, &held_name).await;
    let _name_guard = name_mutex.lock().await;

    let dana_address = format!("{}@{}", user_name, state.domain);
    let txt_name = format!("{}.user._bitcoin-payment.{}", user_name, state.domain);
    let txt_content = format!("bitcoin:?{}={}", network_key, sp_address);

    // R4: still inside the critical section, consult the in-memory registration
    // maps before the live lookup. A winner that has just created the record may
    // not be visible yet to a DNSSEC query against the zone, so every follower
    // must observe the winner's in-process state and take the already-registered
    // path instead of issuing a second create. The live DNS check below remains
    // the authoritative source for names registered outside this process.
    let in_memory_owner = {
        let dana_map = state.dana_to_sp.read().await;
        dana_map.get(&dana_address).cloned()
    };
    if let Some(existing_sp) = in_memory_owner {
        if existing_sp == sp_address {
            // Same owner: refresh the maps and return the existing record, the
            // same outcome the already-registered-same-SP DNS path produces.
            let mut sp_map = state.sp_to_dana.write().await;
            let existing = sp_map.entry(sp_address).or_insert_with(Vec::new);
            if !existing.contains(&dana_address) {
                existing.push(dana_address.clone());
            }
            drop(sp_map);
            debug!(
                "R4: registration for {} already completed by a concurrent request",
                dana_address
            );
            return (
                StatusCode::OK,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: "TXT record already exists".to_string(),
                    dana_address: Some(dana_address),
                    sp_address: Some(sp_address.to_string()),
                    dns_record_id: None,
                }),
            );
        }
        // A different owner claimed this name in-process: same conflict verdict as
        // the live-check branch, and it can never be overwritten.
        error!("TXT record already exists for user name: {}", user_name);
        return (
            StatusCode::CONFLICT,
            AxumJson(RegisterResponse {
                id: request.id,
                message: "TXT record already exists".to_string(),
                dana_address: Some(dana_address),
                sp_address: Some(existing_sp.to_string()),
                dns_record_id: None,
            }),
        );
    }

    // First check if the record already exists using DNS-over-HTTPS
    match fetch_sp_address_from_txt_record(&user_name, &state.domain, sp_address.network())
        .await
    {
        Ok(Some(registered_sp_address)) => {
            if registered_sp_address == sp_address {
                // The record already exists and the SP address is the same, we can return the existing record
                // Update maps to ensure they're in sync
                let mut sp_map = state.sp_to_dana.write().await;
                let mut dana_map = state.dana_to_sp.write().await;
                let existing = sp_map.entry(sp_address).or_insert_with(Vec::new);
                if !existing.contains(&dana_address) {
                    existing.push(dana_address.clone());
                }
                dana_map.insert(dana_address.clone(), sp_address);
                drop(sp_map);
                drop(dana_map);
                debug!(
                    "Updated maps for existing record: {} -> {}",
                    dana_address, sp_address
                );
                return (
                    StatusCode::OK,
                    AxumJson(RegisterResponse {
                        id: request.id,
                        message: "TXT record already exists".to_string(),
                        dana_address: Some(dana_address),
                        sp_address: Some(sp_address.to_string()),
                        dns_record_id: None,
                    }),
                );
            }
            error!("TXT record already exists for user name: {}", user_name);
            return (
                StatusCode::CONFLICT,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: "TXT record already exists".to_string(),
                    dana_address: Some(format!("{}@{}", user_name, state.domain)),
                    sp_address: Some(sp_address.to_string()),
                    dns_record_id: None, // We don't have the Cloudflare record ID from DNS check
                }),
            );
        }
        Ok(None) => debug!(
            "Didn't find a sp address for network {:?} and user name {}",
            sp_address.network(),
            user_name
        ),
        Err(e) => {
            error!(
                "Error checking for existing TXT record for user name {}: {}",
                user_name, e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: format!("Error checking for existing TXT record: {}", e),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                }),
            );
        }
    };

    info!("Attempting to create TXT record: {}", txt_name);
    let client = Client::new();

    let dns_record_id = match create_txt_record(
        &client,
        &state.zone_id,
        &state.api_token,
        &txt_name,
        &txt_content,
    )
    .await
    {
        Ok(Some(id)) => {
            info!(
                "Successfully created TXT record: {} -> {}",
                txt_name, txt_content
            );
            // Update both maps with the new registration
            let mut sp_map = state.sp_to_dana.write().await;
            let mut dana_map = state.dana_to_sp.write().await;
            let existing = sp_map.entry(sp_address).or_insert_with(Vec::new);
            if !existing.contains(&dana_address) {
                existing.push(dana_address.clone());
                info!(
                    "Added Dana address {} to SP address {} mapping",
                    dana_address, sp_address
                );
            }
            dana_map.insert(dana_address.clone(), sp_address);
            drop(sp_map);
            drop(dana_map);
            debug!(
                "Updated maps for new registration: {} -> {}",
                dana_address, sp_address
            );
            Some(id)
        }
        Ok(None) => {
            warn!(
                "Failed to create TXT record: No ID returned from Cloudflare for {}",
                txt_name
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: "Failed to create DNS record: No ID returned from Cloudflare"
                        .to_string(),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                }),
            );
        }
        Err(e) => {
            error!("Error creating TXT record {}: {}", txt_name, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: format!("Failed to create DNS record: {}", e),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                }),
            );
        }
    };

    // End of the check-then-create critical section (early returns above drop
    // the guard when the handler body returns); release it before building the
    // success response.
    drop(_name_guard);

    let response_body = RegisterResponse {
        id: request.id,
        message: "Successfully registered silent payment address".to_string(),
        dana_address: Some(dana_address),
        sp_address: Some(sp_address.to_string()),
        dns_record_id,
    };

    debug!(
        "Sending response for record: {}",
        response_body
            .dana_address
            .as_ref()
            .unwrap_or(&"unknown".to_string())
    );
    (StatusCode::OK, AxumJson(response_body))
}

/// Lookup Dana address(es) for a given SP address
async fn handle_lookup_sp_address(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LookupRequest>,
) -> (StatusCode, AxumJson<LookupResponse>) {
    debug!(
        "Lookup request received for SP address: {}",
        query.sp_address
    );

    // Validate SP address
    let sp_address = match SilentPaymentCode::try_from(query.sp_address.clone()) {
        Ok(sp_address) => {
            debug!(
                "Successfully parsed SP address: {} (network: {:?})",
                sp_address,
                sp_address.network()
            );
            sp_address
        }
        Err(e) => {
            error!("Invalid SP address '{}': {}", query.sp_address, e);
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(LookupResponse {
                    id: query.id,
                    message: format!("Invalid SP address: {}", e),
                    dana_addresses: Vec::new(),
                    sp_address: None,
                }),
            );
        }
    };

    // Lookup in the map
    debug!("Looking up SP address in cache map...");
    let map = state.sp_to_dana.read().await;
    debug!("Cache map contains {} entries", map.len());

    match map.get(&sp_address) {
        Some(dana_addresses) => {
            info!(
                "Found {} Dana address(es) for SP address {}: {:?}",
                dana_addresses.len(),
                sp_address,
                dana_addresses
            );
            (
                StatusCode::OK,
                AxumJson(LookupResponse {
                    id: query.id,
                    message: "Successfully found Dana address(es)".to_string(),
                    dana_addresses: dana_addresses.clone(),
                    sp_address: Some(sp_address.to_string()),
                }),
            )
        }
        None => {
            warn!("SP address {} not found in cache map", sp_address);
            (
                StatusCode::NOT_FOUND,
                AxumJson(LookupResponse {
                    id: query.id,
                    message: "SP address not found".to_string(),
                    dana_addresses: Vec::new(),
                    sp_address: Some(sp_address.to_string()),
                }),
            )
        }
    }
}

/// Search for Dana addresses by prefix (minimum 3 characters)
async fn handle_prefix_search(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PrefixSearchRequest>,
) -> (StatusCode, AxumJson<PrefixSearchResponse>) {
    debug!(
        "Prefix search request received for prefix: {}",
        query.prefix
    );

    // Validate prefix length (minimum 3 characters)
    if query.prefix.len() < 3 {
        error!(
            "Prefix too short: '{}' (minimum 3 characters required)",
            query.prefix
        );
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(PrefixSearchResponse {
                id: query.id,
                message: "Prefix must be at least 3 characters long".to_string(),
                dana_addresses: Vec::new(),
                count: 0,
                total_count: 0,
            }),
        );
    }

    // Convert prefix to lowercase for case-insensitive search
    let prefix_lower = query.prefix.to_lowercase();

    // Search through all dana addresses using the reverse map
    debug!("Searching for dana addresses with prefix: {}", prefix_lower);
    let map = state.dana_to_sp.read().await;
    debug!("Cache map contains {} Dana address entries", map.len());

    const MAX_RESULTS: usize = 25;

    // Collect all matching addresses first
    let mut matching_addresses: Vec<String> = Vec::new();

    // Iterate through all dana addresses (keys of the map)
    for dana_address in map.keys() {
        // Case-insensitive prefix match
        if dana_address.to_lowercase().starts_with(&prefix_lower) {
            matching_addresses.push(dana_address.clone());
        }
    }

    // Sort for consistent results (no need to dedup since keys are unique)
    matching_addresses.sort();

    // Get total count before limiting
    let total_count = matching_addresses.len();

    // Limit to MAX_RESULTS
    let limited_addresses: Vec<String> = matching_addresses.into_iter().take(MAX_RESULTS).collect();
    let result_count = limited_addresses.len();

    let message = if total_count > MAX_RESULTS {
        format!(
            "Found {} matching Dana address(es) (showing first {})",
            total_count, MAX_RESULTS
        )
    } else {
        format!("Found {} matching Dana address(es)", total_count)
    };

    info!(
        "Found {} Dana address(es) matching prefix '{}' (returning {})",
        total_count, query.prefix, result_count
    );

    (
        StatusCode::OK,
        AxumJson(PrefixSearchResponse {
            id: query.id,
            message,
            dana_addresses: limited_addresses,
            count: result_count,
            total_count,
        }),
    )
}

#[tokio::main]
async fn main() {
    // Initialize logging with default level of 'info' if RUST_LOG is not set
    // RUST_LOG can still override this (e.g., RUST_LOG=debug cargo run)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    info!("Starting Dana Name Server");

    if let Err(e) = dotenv::dotenv() {
        error!("Could not load .env file: {}", e);
        std::process::exit(1);
    } else {
        info!("Successfully loaded .env file");
    }

    let zone_id = std::env::var("CLOUDFLARE_ZONE_ID")
        .expect("CLOUDFLARE_ZONE_ID environment variable is required");
    let api_token = std::env::var("CLOUDFLARE_API_TOKEN")
        .expect("CLOUDFLARE_API_TOKEN environment variable is required");
    let domain =
        std::env::var("DOMAIN_NAME").expect("DOMAIN_NAME environment variable is required");
    let server_host =
        std::env::var("SERVER_HOST").expect("SERVER_HOST environment variable is required");
    let server_port: u32 = std::env::var("SERVER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .expect("SERVER_PORT environment variable is required");
    let network: String =
        std::env::var("NETWORK").expect("NETWORK environemnt variable is required");

    // we don't allow regtest for a public server
    let network = match &network[..] {
        "Mainnet" => SpNetwork::Mainnet,
        "Testnet" => SpNetwork::Testnet,
        "Regtest" => panic!("Regtest not allowed"),
        _ => panic!("Unable to parse network"),
    };

    if zone_id.is_empty() || api_token.is_empty() {
        error!("Cloudflare credentials not provided. Can't proceed.");
        error!(
            "Set CLOUDFLARE_ZONE_ID and CLOUDFLARE_API_TOKEN environment variables to enable DNS integration."
        );
        std::process::exit(1);
    } else {
        info!("Cloudflare credentials loaded successfully");
        debug!("Zone ID: {}", zone_id);
        debug!("API Token: {}...", &api_token[..8.min(api_token.len())]);
    }

    let sp_to_dana: Arc<RwLock<HashMap<SilentPaymentCode, Vec<String>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let dana_to_sp: Arc<RwLock<HashMap<String, SilentPaymentCode>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Populate the maps of sp addresses to dana addresses and vice versa on startup
    info!("Populating SP address to Dana address maps from Cloudflare records...");
    match list_bitcoin_records(&zone_id, &api_token, &domain).await {
        Ok(records) => {
            info!(
                "Fetched {} Bitcoin TXT records from Cloudflare",
                records.len()
            );
            let mut map = sp_to_dana.write().await;
            let mut reverse_map = dana_to_sp.write().await;
            let mut processed_count = 0;
            let mut skipped_count = 0;
            let mut error_count = 0;

            for record in records {
                // Since DNS records have a max length of 255 bytes, content may be split in
                // multiple chunks, separated by a single space.
                let content: String = record
                    .content
                    .split_whitespace()
                    .map(|chunk| match serde_json::from_str(chunk) {
                        Ok(chunk) => chunk,
                        // if the chunk is not string-serialized, we take the raw value
                        Err(_) => chunk,
                    })
                    .collect();
                debug!(
                    "Processing record: name='{}', content='{}'",
                    record.name, content
                );

                // Parse record name: {user_name}.user._bitcoin-payment.{domain}
                // Extract user_name from the name (user_name can contain dots)
                let pattern = ".user._bitcoin-payment.";
                if let Some(pattern_pos) = record.name.find(pattern) {
                    let user_name = &record.name[..pattern_pos];
                    let dana_address = format!("{}@{}", user_name, domain);
                    debug!(
                        "Extracted user_name: '{}', Dana address: '{}'",
                        user_name, dana_address
                    );

                    // Parse record content: bitcoin:?{network_key}={sp_address}
                    // Extract SP address from content
                    if let Some(sp_part) = content.strip_prefix("bitcoin:?") {
                        debug!("Found bitcoin: prefix, parsing parameters: {}", sp_part);
                        let mut found_sp = false;

                        // Try to find sp= or tsp= parameter
                        for param in sp_part.split('&') {
                            if let Some(sp_addr_str) = param.strip_prefix("sp=") {
                                debug!("Found sp= parameter: {}", sp_addr_str);
                                match SilentPaymentCode::try_from(sp_addr_str.to_string()) {
                                    Ok(sp_address) => {
                                        let dana_addr = dana_address.clone();
                                        let existing =
                                            map.entry(sp_address).or_insert_with(Vec::new);
                                        existing.push(dana_addr.clone());
                                        reverse_map.insert(dana_addr.clone(), sp_address);
                                        info!(
                                            "Mapped SP address {} to Dana address {} (total mappings for this SP: {})",
                                            sp_addr_str,
                                            dana_address,
                                            existing.len()
                                        );
                                        processed_count += 1;
                                        found_sp = true;
                                        break;
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to parse SP address '{}' from record '{}': {}",
                                            sp_addr_str, record.name, e
                                        );
                                        error_count += 1;
                                    }
                                }
                            } else if let Some(sp_addr_str) = param.strip_prefix("tsp=") {
                                debug!("Found tsp= parameter: {}", sp_addr_str);
                                match SilentPaymentCode::try_from(sp_addr_str.to_string()) {
                                    Ok(sp_address) => {
                                        let dana_addr = dana_address.clone();
                                        let existing =
                                            map.entry(sp_address).or_insert_with(Vec::new);
                                        existing.push(dana_addr.clone());
                                        reverse_map.insert(dana_addr.clone(), sp_address);
                                        info!(
                                            "Mapped SP address {} to Dana address {} (total mappings for this SP: {})",
                                            sp_addr_str,
                                            dana_address,
                                            existing.len()
                                        );
                                        processed_count += 1;
                                        found_sp = true;
                                        break;
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to parse SP address '{}' from record '{}': {}",
                                            sp_addr_str, record.name, e
                                        );
                                        error_count += 1;
                                    }
                                }
                            }
                        }

                        if !found_sp {
                            debug!(
                                "No valid sp= or tsp= parameter found in record '{}'",
                                record.name
                            );
                            skipped_count += 1;
                        }
                    } else {
                        debug!(
                            "Record '{}' does not start with 'bitcoin:?' prefix, skipping",
                            record.name
                        );
                        skipped_count += 1;
                    }
                } else {
                    debug!(
                        "Record '{}' does not match expected pattern '.user._bitcoin-payment.', skipping",
                        record.name
                    );
                    skipped_count += 1;
                }
            }

            info!(
                "Map population complete: {} SP->Dana entries, {} Dana->SP entries, {} records processed, {} skipped, {} errors",
                map.len(),
                reverse_map.len(),
                processed_count,
                skipped_count,
                error_count
            );
        }
        Err(e) => {
            warn!(
                "Failed to populate SP address map on startup: {}. Continuing without cache.",
                e
            );
        }
    }

    let state = Arc::new(AppState {
        zone_id,
        api_token,
        domain,
        sp_to_dana,
        dana_to_sp,
        network,
        nonce_store: Arc::new(RwLock::new(HashMap::new())),
        peer_nonce_counts: Arc::new(RwLock::new(HashMap::new())),
        name_locks: Arc::new(Mutex::new(HashMap::new())),
        max_pending_nonces: MAX_PENDING_NONCES,
        max_nonces_per_peer: MAX_NONCES_PER_PEER,
    });

    let v1_router = Router::new()
        .route("/info", get(handle_get_info))
        .route("/challenge", post(handle_challenge))
        .route("/register", post(handle_register))
        .route("/lookup", get(handle_lookup_sp_address))
        .route("/search", get(handle_prefix_search));

    // Periodically evict expired nonces to bound the in-memory store
    {
        let store = state.nonce_store.clone();
        let counts = state.peer_nonce_counts.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_expired_nonces(&store, &counts).await;
            }
        });
    }

    let app = Router::new().nest("/v1", v1_router).with_state(state);

    let server_addr = format!("{server_host}:{server_port}");

    let listener = tokio::net::TcpListener::bind(&server_addr)
        .await
        .expect("Failed to bind to server address");

    info!("Server starting on {server_addr}");
    info!("API endpoint available at: http://{server_addr}/v1/info");
    info!("API endpoint available at: http://{server_addr}/v1/register");
    info!("API endpoint available at: http://{server_addr}/v1/lookup");
    info!("API endpoint available at: http://{server_addr}/v1/search");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}

#[cfg(test)]
mod tests {
    use super::*;
    use silentpayments::SilentPaymentCode;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path, header, query_param};

    #[tokio::test]
    async fn test_check_txt_record_exists_with_address() {
        let address_to_register = SilentPaymentCode::try_from("sp1qq0cygnetgn3rz2kla5cp05nj5uetlsrzez0l4p8g7wehf7ldr93lcqadw65upymwzvp5ed38l8ur2rznd6934xh95msevwrdwtrpk372hyz4vr6g").unwrap();
        let result = fetch_sp_address_from_txt_record(
            "donate",
            "danawallet.app",
            address_to_register.network(),
        )
        .await;

        assert!(result.is_ok());

        assert_eq!(result.unwrap(), Some(address_to_register));
    }

    #[tokio::test]
    async fn test_check_txt_record_exists_with_no_address() {
        let result = fetch_sp_address_from_txt_record(
            "matt",
            "mattcorallo.com",
            silentpayments::Network::Mainnet,
        )
        .await;

        assert!(result.is_ok());

        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    async fn test_check_no_txt_record() {
        let result = fetch_sp_address_from_txt_record(
            "unknown",
            "danawallet.app",
            silentpayments::Network::Mainnet,
        )
        .await;

        assert!(result.is_ok());

        assert_eq!(result.unwrap(), None);
    }
    // --- Cloudflare API helper tests against a local mock server ---
    // These exercise create_txt_record / list_bitcoin_records without needing a
    // real Cloudflare API key: the base URL is pointed at a wiremock server via
    // the CLOUDFLARE_API_BASE_URL env var. The env var is process-global, so
    // these tests are serialized against each other with CF_ENV_LOCK.
    static CF_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn test_create_txt_record_mock_success() {
        let _guard = CF_ENV_LOCK.lock().unwrap();
        let m = MockServer::start().await;
        let zone = "testzone123";
        let token = "test-token";

        Mock::given(method("POST"))
            .and(path(format!("/zones/{}/dns_records", zone)))
            .and(header("Authorization", format!("Bearer {}", token)))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(&serde_json::json!({
                    "success": true,
                    "result": { "id": "rec-abc-123" },
                })),
            )
            .expect(1)
            .mount(&m)
            .await;

        unsafe { std::env::set_var("CLOUDFLARE_API_BASE_URL", m.uri()) };
        let client = Client::new();
        let got = create_txt_record(
            &client,
            zone,
            token,
            "user._bitcoin-payment.example.com",
            "bitcoin:sp1qq...",
        )
        .await
        .unwrap();
        unsafe { std::env::remove_var("CLOUDFLARE_API_BASE_URL") };

        assert_eq!(got, Some("rec-abc-123".to_string()));
    }

    #[tokio::test]
    async fn test_create_txt_record_mock_no_id() {
        let _guard = CF_ENV_LOCK.lock().unwrap();
        let m = MockServer::start().await;
        let zone = "testzone456";
        let token = "test-token2";

        Mock::given(method("POST"))
            .and(path(format!("/zones/{}/dns_records", zone)))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(&serde_json::json!({
                    "success": true,
                    "result": {},
                })),
            )
            .expect(1)
            .mount(&m)
            .await;

        unsafe { std::env::set_var("CLOUDFLARE_API_BASE_URL", m.uri()) };
        let client = Client::new();
        let got = create_txt_record(&client, zone, token, "a", "b").await.unwrap();
        unsafe { std::env::remove_var("CLOUDFLARE_API_BASE_URL") };

        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn test_create_txt_record_mock_error_status() {
        let _guard = CF_ENV_LOCK.lock().unwrap();
        let m = MockServer::start().await;
        let zone = "testzone789";
        let token = "test-token3";

        Mock::given(method("POST"))
            .and(path(format!("/zones/{}/dns_records", zone)))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&m)
            .await;

        unsafe { std::env::set_var("CLOUDFLARE_API_BASE_URL", m.uri()) };
        let client = Client::new();
        let got = create_txt_record(&client, zone, token, "a", "b").await.unwrap();
        unsafe { std::env::remove_var("CLOUDFLARE_API_BASE_URL") };

        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn test_list_bitcoin_records_mock() {
        let _guard = CF_ENV_LOCK.lock().unwrap();
        let m = MockServer::start().await;
        let zone = "testzone000";
        let token = "test-token4";
        let domain = "example.com";
        let suffix = format!("user._bitcoin-payment.{}", domain);

        Mock::given(method("GET"))
            .and(path(format!("/zones/{}/dns_records", zone)))
            .and(query_param("type", "TXT"))
            .and(query_param("name.endswith", suffix.as_str()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(&serde_json::json!({
                    "success": true,
                    "result": [{
                        "id": "rec1",
                        "name": "user._bitcoin-payment.example.com.",
                        "type": "TXT",
                        "content": "bitcoin:sp1qq..."
                    }],
                })),
            )
            .expect(1)
            .mount(&m)
            .await;

        unsafe { std::env::set_var("CLOUDFLARE_API_BASE_URL", m.uri()) };
        let got = list_bitcoin_records(zone, token, domain).await.unwrap();
        unsafe { std::env::remove_var("CLOUDFLARE_API_BASE_URL") };

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "rec1");
        assert_eq!(got[0].name, "user._bitcoin-payment.example.com.");
        assert_eq!(got[0].record_type, "TXT");
        assert_eq!(got[0].content, "bitcoin:sp1qq...");
    }

    // ── Challenge-auth (branch 1): DNS name validation ──

    #[test]
    fn test_validate_dns_name_valid() {
        assert!(validate_dns_name("alice"));
        assert!(validate_dns_name("alice-1"));
        assert!(validate_dns_name("a-b"));
        assert!(validate_dns_name("a1-b2-c3"));
        assert!(validate_dns_name("a".repeat(63).as_str()));
    }

    #[test]
    fn test_validate_dns_name_invalid() {
        assert!(!validate_dns_name(""));
        assert!(!validate_dns_name("a".repeat(64).as_str()));
        assert!(!validate_dns_name("alice@example"));
        assert!(!validate_dns_name("alice bob"));
        assert!(!validate_dns_name("alice."));
        // R5: non-canonical input is rejected, never silently lowercased.
        assert!(!validate_dns_name("Alice"));
        assert!(!validate_dns_name("aLiCe"));
        assert!(!validate_dns_name("-a"));
        assert!(!validate_dns_name("a-"));
        assert!(!validate_dns_name("a--b"));
        assert!(!validate_dns_name("a-B"));
        assert!(!validate_dns_name("A-b"));
        assert!(!validate_dns_name("-Alice-"));
    }

    // ── R5: canonical labels enforced on BOTH endpoints ──
    // /challenge must mint only for the canonical form: same name with a
    // different case is a single label path, so one rejected variant can never
    // fork a second nonce/map key over the one TXT name.
    #[tokio::test]
    async fn test_challenge_rejects_non_canonical_name() {
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";
        let state = Arc::new(register_state(domain));

        for bad in ["Alice", "-alice", "alice-", "a--b", "Alice-Bob"] {
            let resp = handle_challenge(
                State(state.clone()),
                Json(ChallengeRequest {
                    id: format!("nc-{}", bad),
                    domain: domain.to_string(),
                    user_name: bad.to_string(),
                    sp_address: sp_addr.to_string(),
                }),
            )
            .await;
            assert_eq!(
                resp.0,
                StatusCode::BAD_REQUEST,
                "{} must be rejected as non-canonical",
                bad
            );
        }

        // The canonical form still mints, and it is the ONLY stored label:
        // same-name-different-case collapsed to the one canonical path.
        let resp = handle_challenge(
            State(state.clone()),
            Json(ChallengeRequest {
                id: "nc-ok".to_string(),
                domain: domain.to_string(),
                user_name: "alice".to_string(),
                sp_address: sp_addr.to_string(),
            }),
        )
        .await;
        assert_eq!(resp.0, StatusCode::OK);
        let store = state.nonce_store.read().await;
        assert_eq!(store.len(), 1);
        assert_eq!(store.values().next().unwrap().user_name, "alice");
    }

    // /register re-validates the claimed label BEFORE claim_nonce: a request
    // whose case differs from the stored canonical entry is a 400 (not the
    // 401 claim mismatch) and must not burn the nonce.
    #[tokio::test]
    async fn test_register_rejects_non_canonical_name_before_claim() {
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";
        let nonce = "nonce-r5-noncanon";
        let canonical = "alice".to_string();
        let mixed = "Alice".to_string();
        let sp_str = sp_addr.to_string();
        let state = Arc::new(register_state(domain));
        make_nonce(
            &state.nonce_store,
            nonce,
            &canonical,
            &sp_str,
            domain,
            Instant::now() + Duration::from_secs(60),
        )
        .await;
        let sig = sign_challenge(&secp, &spend_secret, "sp", nonce, &mixed, domain);

        let resp = handle_register(
            State(state.clone()),
            Json(RegisterRequest {
                id: "req-r5".to_string(),
                domain: domain.to_string(),
                user_name: Some(mixed.clone()),
                sp_address: sp_str.clone(),
                nonce: Some(nonce.to_string()),
                signature: Some(sig),
            }),
        )
        .await;
        assert_eq!(resp.0, StatusCode::BAD_REQUEST);

        // The rejected request never reached claim_nonce: the nonce survives
        // for the legitimate canonical retry.
        assert!(
            claim_nonce(&state.nonce_store, nonce, &canonical, &sp_str, domain)
                .await
                .is_ok(),
            "400 rejection must not consume the nonce"
        );

        // Even without any challenge material the 400 wins over the 401
        // missing-nonce path, proving the check runs first in the handler.
        let resp = handle_register(
            State(state.clone()),
            Json(RegisterRequest {
                id: "req-r5-b".to_string(),
                domain: domain.to_string(),
                user_name: Some(mixed),
                sp_address: sp_str,
                nonce: None,
                signature: None,
            }),
        )
        .await;
        assert_eq!(resp.0, StatusCode::BAD_REQUEST);
    }

    // Helper: build a SilentPaymentAddress from a scan key and a spend key.
    fn make_sp_address(
        secp: &silentpayments::secp256k1::Secp256k1<silentpayments::secp256k1::All>,
        scan_secret: &silentpayments::secp256k1::SecretKey,
        spend_secret: &silentpayments::secp256k1::SecretKey,
    ) -> SilentPaymentCode {
        let scan_pub = scan_secret.public_key(secp);
        let spend_pub = spend_secret.public_key(secp);
        SilentPaymentCode::new_v0(scan_pub, spend_pub, SpNetwork::Mainnet)
    }

    #[test]
    fn test_verify_schnorr_signature_valid() {
        use silentpayments::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
        use sha2::{Digest, Sha256};
        use rand::thread_rng;

        let secp = Secp256k1::new();
        let scan_secret = SecretKey::new(&mut thread_rng());
        let spend_secret = SecretKey::new(&mut thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);

        let message = "dana-register:sp:deadbeef:alice:example.com";
        let digest = Sha256::digest(message.as_bytes());
        let msg = Message::from_digest_slice(&digest).unwrap();

        let keypair = Keypair::from_seckey_slice(&secp, &spend_secret.secret_bytes()).unwrap();
        let sig = secp.sign_schnorr_with_rng(&msg, &keypair, &mut thread_rng());
        let sig_hex = hex::encode(sig.serialize());

        assert!(verify_schnorr_signature(&sig_hex, message, &sp_addr).is_ok());
    }

    #[test]
    fn test_verify_schnorr_signature_invalid() {
        use silentpayments::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
        use sha2::{Digest, Sha256};
        use rand::thread_rng;

        let secp = Secp256k1::new();
        let scan_secret = SecretKey::new(&mut thread_rng());
        let spend_secret = SecretKey::new(&mut thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);

        let message = "dana-register:sp:deadbeef:alice:example.com";
        let digest = Sha256::digest(message.as_bytes());
        let msg = Message::from_digest_slice(&digest).unwrap();

        // Sign with a different key than the spend key embedded in sp_addr
        let other_secret = SecretKey::new(&mut thread_rng());
        let keypair = Keypair::from_seckey_slice(&secp, &other_secret.secret_bytes()).unwrap();
        let sig = secp.sign_schnorr_with_rng(&msg, &keypair, &mut thread_rng());
        let sig_hex = hex::encode(sig.serialize());

        assert!(verify_schnorr_signature(&sig_hex, message, &sp_addr).is_err());

        // Also reject a malformed / wrong-length signature
        assert!(verify_schnorr_signature("deadbeef", message, &sp_addr).is_err());
    }

    // ── Challenge-auth (branch 1): nonce claim + expiry ──

    #[tokio::test]
    async fn test_claim_nonce_single_use() {
        let store: Arc<RwLock<HashMap<String, NonceEntry>>> = Arc::new(RwLock::new(HashMap::new()));

        store.write().await.insert(
            "nonce1".to_string(),
            NonceEntry {
                user_name: "alice".to_string(),
                sp_address: "sp1qq...".to_string(),
                domain: "danawallet.app".to_string(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );

        assert!(
            claim_nonce(&store, "nonce1", "alice", "sp1qq...", "danawallet.app")
                .await
                .is_ok()
        );

        // Single-use: a second claim fails because the nonce was consumed
        assert!(
            claim_nonce(&store, "nonce1", "alice", "sp1qq...", "danawallet.app")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_claim_nonce_mismatch() {
        let store: Arc<RwLock<HashMap<String, NonceEntry>>> = Arc::new(RwLock::new(HashMap::new()));

        store.write().await.insert(
            "nonce1".to_string(),
            NonceEntry {
                user_name: "alice".to_string(),
                sp_address: "sp1qq...".to_string(),
                domain: "danawallet.app".to_string(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );

        // Wrong user name
        assert!(
            claim_nonce(&store, "nonce1", "bob", "sp1qq...", "danawallet.app")
                .await
                .is_err()
        );
        // Wrong SP address
        assert!(
            claim_nonce(&store, "nonce1", "alice", "sp1qq2...", "danawallet.app")
                .await
                .is_err()
        );
        // Wrong domain
        assert!(
            claim_nonce(&store, "nonce1", "alice", "sp1qq...", "example.com")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_claim_nonce_expired() {
        let store: Arc<RwLock<HashMap<String, NonceEntry>>> = Arc::new(RwLock::new(HashMap::new()));

        store.write().await.insert(
            "nonce1".to_string(),
            NonceEntry {
                user_name: "alice".to_string(),
                sp_address: "sp1qq...".to_string(),
                domain: "danawallet.app".to_string(),
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );

        assert!(
            claim_nonce(&store, "nonce1", "alice", "sp1qq...", "danawallet.app")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_cleanup_expired_nonces() {
        let store: Arc<RwLock<HashMap<String, NonceEntry>>> = Arc::new(RwLock::new(HashMap::new()));
        store.write().await.insert(
            "expired".to_string(),
            NonceEntry {
                user_name: "alice".to_string(),
                sp_address: "sp1qq...".to_string(),
                domain: "danawallet.app".to_string(),
                expires_at: Instant::now() - Duration::from_secs(10),
            },
        );
        store.write().await.insert(
            "fresh".to_string(),
            NonceEntry {
                user_name: "bob".to_string(),
                sp_address: "sp1qq2...".to_string(),
                domain: "danawallet.app".to_string(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );

        let counts: Arc<RwLock<HashMap<String, u32>>> = Arc::new(RwLock::new(HashMap::from([
            ("sp1qq...".to_string(), 1u32),
            ("sp1qq2...".to_string(), 1u32),
        ])));
        cleanup_expired_nonces(&store, &counts).await;

        let store = store.read().await;
        assert!(store.contains_key("fresh"));
        assert!(!store.contains_key("expired"));
        drop(store);

        // The expired entry's peer dropped to zero and its key must be pruned;
        // the live peer's key survives with its outstanding count intact.
        let counts = counts.read().await;
        assert!(!counts.contains_key("sp1qq..."));
        assert_eq!(counts.get("sp1qq2..."), Some(&1));
    }

    #[tokio::test]
    async fn test_challenge_id_rotation_same_sp_address_hits_peer_cap() {
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";

        let state = register_state(domain);
        let counts = state.peer_nonce_counts.clone();

        for i in 0..MAX_NONCES_PER_PEER {
            let resp = handle_challenge(
                State(Arc::new(state.clone())),
                Json(ChallengeRequest {
                    id: format!("rotating-id-{}", i),
                    domain: domain.to_string(),
                    user_name: "alice".to_string(),
                    sp_address: sp_addr.to_string(),
                }),
            )
            .await;
            assert_eq!(resp.0, StatusCode::OK);
        }

        let resp = handle_challenge(
            State(Arc::new(state.clone())),
            Json(ChallengeRequest {
                id: "rotating-id-overflow".to_string(),
                domain: domain.to_string(),
                user_name: "alice".to_string(),
                sp_address: sp_addr.to_string(),
            }),
        )
        .await;
        assert_eq!(resp.0, StatusCode::TOO_MANY_REQUESTS);

        // Rotating request.id never created extra keys: one validated-SP key at the cap.
        let snap = counts.read().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap.get(&sp_addr.to_string()), Some(&MAX_NONCES_PER_PEER));
    }

    #[tokio::test]
    async fn test_challenge_re_mint_after_claim_and_prune() {
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";
        let peer = sp_addr.to_string();

        let state = register_state(domain);
        let counts = state.peer_nonce_counts.clone();
        counts.write().await.insert(peer.clone(), MAX_NONCES_PER_PEER);

        // At the per-peer cap, an honest client cannot mint another challenge.
        let resp = handle_challenge(
            State(Arc::new(state.clone())),
            Json(ChallengeRequest {
                id: "blocked".to_string(),
                domain: domain.to_string(),
                user_name: "alice".to_string(),
                sp_address: peer.clone(),
            }),
        )
        .await;
        assert_eq!(resp.0, StatusCode::TOO_MANY_REQUESTS);

        // Complete the challenge-register cycle: the nonce is claimed and the
        // register flow releases the peer slot (same call handle_register makes).
        state.nonce_store.write().await.insert(
            "n1".to_string(),
            NonceEntry {
                user_name: "alice".to_string(),
                sp_address: peer.clone(),
                domain: domain.to_string(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
        claim_nonce(&state.nonce_store, "n1", "alice", &peer, domain)
            .await
            .expect("claim of a live matching nonce must succeed");
        release_peer_nonce_slot(&state.peer_nonce_counts, &peer).await;

        // Slot freed: the client can mint again.
        let resp = handle_challenge(
            State(Arc::new(state.clone())),
            Json(ChallengeRequest {
                id: "re-mint".to_string(),
                domain: domain.to_string(),
                user_name: "alice".to_string(),
                sp_address: peer.clone(),
            }),
        )
        .await;
        assert_eq!(resp.0, StatusCode::OK);
        assert_eq!(counts.read().await.get(&peer), Some(&MAX_NONCES_PER_PEER));

        // Releasing every slot to zero must delete the key: the map cannot
        // accumulate dead per-peer entries from finished cycles.
        for _ in 0..MAX_NONCES_PER_PEER {
            release_peer_nonce_slot(&state.peer_nonce_counts, &peer).await;
        }
        let snap = counts.read().await;
        assert!(!snap.contains_key(&peer), "zero-valued peer key must be pruned");
    }

    #[tokio::test]
    async fn test_challenge_total_peer_keys_cap_429() {
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";

        // Map full of unrelated peers and a brand-new validated SP address => 429.
        let state = register_state(domain);
        {
            let mut snap = state.peer_nonce_counts.write().await;
            for i in 0..MAX_TRACKED_PEERS {
                snap.insert(format!("sp_dummy_{}", i), 1);
            }
        }
        let resp = handle_challenge(
            State(Arc::new(state.clone())),
            Json(ChallengeRequest {
                id: "new-peer".to_string(),
                domain: domain.to_string(),
                user_name: "carol".to_string(),
                sp_address: sp_addr.to_string(),
            }),
        )
        .await;
        assert_eq!(resp.0, StatusCode::TOO_MANY_REQUESTS);

        // At the same cap, a peer already tracked below max_nonces_per_peer passes.
        let state2 = register_state(domain);
        {
            let mut snap = state2.peer_nonce_counts.write().await;
            for i in 0..(MAX_TRACKED_PEERS - 1) {
                snap.insert(format!("sp_dummy_{}", i), 1);
            }
            snap.insert(sp_addr.to_string(), 1);
        }
        let resp2 = handle_challenge(
            State(Arc::new(state2)),
            Json(ChallengeRequest {
                id: "known-peer".to_string(),
                domain: domain.to_string(),
                user_name: "carol".to_string(),
                sp_address: sp_addr.to_string(),
            }),
        )
        .await;
        assert_eq!(resp2.0, StatusCode::OK);
    }


    // ── Integrated /register challenge-response tests ──
    // These drive the full handle_register handler, exercising the
    // challenge-response enforcement (missing/invalid signature, expired or
    // single-use nonce) plus the happy path (valid signature + valid nonce).

    // Helper: a nonce entry bound to the given user_name / sp_address / domain.
    async fn make_nonce(
        store: &Arc<RwLock<HashMap<String, NonceEntry>>>,
        nonce: &str,
        user_name: &str,
        sp_address: &str,
        domain: &str,
        expires_at: Instant,
    ) {
        store.write().await.insert(
            nonce.to_string(),
            NonceEntry {
                user_name: user_name.to_string(),
                sp_address: sp_address.to_string(),
                domain: domain.to_string(),
                expires_at,
            },
        );
    }

    // Helper: build an AppState with the challenge-response plumbing wired up.
    fn register_state(domain: &str) -> AppState {
        AppState {
            zone_id: "zone-test".to_string(),
            api_token: "token-test".to_string(),
            domain: domain.to_string(),
            sp_to_dana: Arc::new(RwLock::new(HashMap::new())),
            dana_to_sp: Arc::new(RwLock::new(HashMap::new())),
            network: SpNetwork::Mainnet,
            nonce_store: Arc::new(RwLock::new(HashMap::new())),
            peer_nonce_counts: Arc::new(RwLock::new(HashMap::new())),
            name_locks: Arc::new(Mutex::new(HashMap::new())),
                max_pending_nonces: 100,
            max_nonces_per_peer: 10,
        }
    }

    // ── R4: per-name check-then-create serialisation ──
    // Two concurrent, correctly-signed /register calls for the same name must
    // produce exactly ONE Cloudflare POST: the per-name mutex turns the loser into
    // the already-registered-same-SP path (200 OK, no dns_record_id) instead of a
    // double create. The .expect(1) on the mock is verified on drop by wiremock.
    #[tokio::test]
    async fn test_concurrent_register_same_name_single_create() {
        let _guard = CF_ENV_LOCK.lock().unwrap();
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";
        // Random name so the DNS existence check reports absent on the first pass.
        let user_name = format!("dana-test-user-{}", rand::random::<u64>());

        let m = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/zones/zone-test/dns_records"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(&serde_json::json!({
                        "success": true,
                        "result": { "id": "rec-xyz" },
                    })),
            )
            .expect(1)
            .mount(&m)
            .await;
        unsafe { std::env::set_var("CLOUDFLARE_API_BASE_URL", m.uri()); }

        // One shared AppState so both contenders take the same per-name lock.
        let state = Arc::new(register_state(domain));
        let sp_str = sp_addr.to_string();
        // Two clients, two valid single-use nonces, same user_name, same SP address.
        let nonce_a = "nonce-r4-a";
        let nonce_b = "nonce-r4-b";
        make_nonce(
            &state.nonce_store,
            nonce_a,
            &user_name,
            &sp_str,
            domain,
            Instant::now() + Duration::from_secs(60),
        ).await;
        make_nonce(
            &state.nonce_store,
            nonce_b,
            &user_name,
            &sp_str,
            domain,
            Instant::now() + Duration::from_secs(60),
        ).await;
        let sig_a = sign_challenge(&secp, &spend_secret, "sp", nonce_a, &user_name, domain);
        let sig_b = sign_challenge(&secp, &spend_secret, "sp", nonce_b, &user_name, domain);

        let req_a = RegisterRequest {
            id: "req-a".to_string(),
            domain: domain.to_string(),
            user_name: Some(user_name.clone()),
            sp_address: sp_str.clone(),
            nonce: Some(nonce_a.to_string()),
            signature: Some(sig_a),
        };
        let req_b = RegisterRequest {
            id: "req-b".to_string(),
            domain: domain.to_string(),
            user_name: Some(user_name.clone()),
            sp_address: sp_str.clone(),
            nonce: Some(nonce_b.to_string()),
            signature: Some(sig_b),
        };
        let state_a = state.clone();
        let state_b = state.clone();

        let (ra, rb) = tokio::join!(
            handle_register(State(state_a), Json(req_a)),
            handle_register(State(state_b), Json(req_b)),
        );

        unsafe { std::env::remove_var("CLOUDFLARE_API_BASE_URL"); }

        // Exactly one POST /zones/zone-test/dns_records (double-check of the
        // verified .expect(1): the winner created, the loser took the existing-
        // record path).
        // Exactly one POST /zones/zone-test/dns_records: the winner created, the
        // follower took the already-registered-same-SP path. Asserted two ways - the
        // `.expect(1)` expectation is checked by MockServer::verify (and again by its
        // Drop impl), and the recorded hits are counted explicitly here.
        m.verify().await;
        let posts = m
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| {
                r.method.as_str() == "POST"
                    && r.url.path() == "/zones/zone-test/dns_records"
            })
            .count();
        assert_eq!(posts, 1, "second concurrent registration must not create a TXT record");

        // Both finish authenticated and owner-consistent: winner reports the created
        // record, loser the already-registered-same-SP outcome (200 OK, no id).
        assert_eq!(ra.0, StatusCode::OK);
        assert_eq!(rb.0, StatusCode::OK);
        let mut ids = vec![ra.1.dns_record_id.clone(), rb.1.dns_record_id.clone()];
        ids.sort();
        assert_eq!(
            ids,
            vec![None, Some("rec-xyz".to_string())],
            "exactly one response must carry the created record id"
        );
    }

    // Helper: Schnorr-sign the challenge message for a spend secret key.
    fn sign_challenge(
        secp: &silentpayments::secp256k1::Secp256k1<silentpayments::secp256k1::All>,
        spend_secret: &silentpayments::secp256k1::SecretKey,
        network_key: &str,
        nonce: &str,
        user_name: &str,
        domain: &str,
    ) -> String {
        use silentpayments::secp256k1::{Keypair, Message};
        use sha2::{Digest, Sha256};
        use rand::thread_rng;

        let message = challenge_message(network_key, nonce, user_name, domain);
        let digest = Sha256::digest(message.as_bytes());
        let msg = Message::from_digest_slice(&digest).unwrap();
        let keypair = Keypair::from_seckey_slice(secp, &spend_secret.secret_bytes()).unwrap();
        let sig = secp.sign_schnorr_with_rng(&msg, &keypair, &mut thread_rng());
        hex::encode(sig.serialize())
    }

    #[tokio::test]
    async fn test_register_missing_signature_rejected() {
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";
        let nonce = "nonce-missing-sig";

        let state = register_state(domain);
        make_nonce(
            &state.nonce_store,
            nonce,
            "alice",
            &sp_addr.to_string(),
            domain,
            Instant::now() + Duration::from_secs(60),
        ).await;

        let resp = handle_register(
            State(Arc::new(state)),
            Json(RegisterRequest {
                id: "req1".to_string(),
                domain: domain.to_string(),
                user_name: Some("alice".to_string()),
                sp_address: sp_addr.to_string(),
                nonce: Some(nonce.to_string()),
                signature: None, // missing signature
            }),
        )
        .await;

        assert_eq!(resp.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_register_missing_nonce_rejected() {
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";

        let state = register_state(domain);

        let resp = handle_register(
            State(Arc::new(state)),
            Json(RegisterRequest {
                id: "req1".to_string(),
                domain: domain.to_string(),
                user_name: Some("alice".to_string()),
                sp_address: sp_addr.to_string(),
                nonce: None, // missing nonce
                signature: Some("00".repeat(64)),
            }),
        )
        .await;

        assert_eq!(resp.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_register_invalid_signature_rejected() {
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";
        let nonce = "nonce-bad-sig";

        let state = register_state(domain);
        make_nonce(
            &state.nonce_store,
            nonce,
            "alice",
            &sp_addr.to_string(),
            domain,
            Instant::now() + Duration::from_secs(60),
        ).await;

        // Signature over a *different* nonce/message => verification must fail.
        let bad_sig = sign_challenge(&secp, &spend_secret, "sp", "wrong-nonce", "alice", domain);

        let resp = handle_register(
            State(Arc::new(state)),
            Json(RegisterRequest {
                id: "req1".to_string(),
                domain: domain.to_string(),
                user_name: Some("alice".to_string()),
                sp_address: sp_addr.to_string(),
                nonce: Some(nonce.to_string()),
                signature: Some(bad_sig),
            }),
        )
        .await;

        assert_eq!(resp.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_register_expired_nonce_rejected() {
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";
        let nonce = "nonce-expired";
        let sig = sign_challenge(&secp, &spend_secret, "sp", nonce, "alice", domain);

        let state = register_state(domain);
        // Nonce already expired.
        make_nonce(
            &state.nonce_store,
            nonce,
            "alice",
            &sp_addr.to_string(),
            domain,
            Instant::now() - Duration::from_secs(10),
        ).await;

        let resp = handle_register(
            State(Arc::new(state)),
            Json(RegisterRequest {
                id: "req1".to_string(),
                domain: domain.to_string(),
                user_name: Some("alice".to_string()),
                sp_address: sp_addr.to_string(),
                nonce: Some(nonce.to_string()),
                signature: Some(sig),
            }),
        )
        .await;

        assert_eq!(resp.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_register_reused_nonce_rejected() {
        let _guard = CF_ENV_LOCK.lock().unwrap();
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";
        let nonce = "nonce-reuse";
        let sig = sign_challenge(&secp, &spend_secret, "sp", nonce, "alice", domain);

        let state = register_state(domain);
        make_nonce(
            &state.nonce_store,
            nonce,
            "alice",
            &sp_addr.to_string(),
            domain,
            Instant::now() + Duration::from_secs(60),
        ).await;

        // First call: valid signature + valid nonce, but we force an early
        // non-401 outcome by pointing Cloudflare at a wiremock that fails, so
        // the nonce is still *claimed* (consumed) during this first attempt.
        // The important part is that the nonce is single-use: a second call
        // with the same nonce must be rejected regardless of signature.
        let m = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/zones/zone-test/dns_records"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&m)
            .await;
        unsafe { std::env::set_var("CLOUDFLARE_API_BASE_URL", m.uri()); }

        let first = handle_register(
            State(Arc::new(state.clone())),
            Json(RegisterRequest {
                id: "req1".to_string(),
                domain: domain.to_string(),
                user_name: Some("alice".to_string()),
                sp_address: sp_addr.to_string(),
                nonce: Some(nonce.to_string()),
                signature: Some(sig.clone()),
            }),
        )
        .await;

        // Second attempt with the *same* single-use nonce must be rejected.
        let resp = handle_register(
            State(Arc::new(state.clone())),
            Json(RegisterRequest {
                id: "req2".to_string(),
                domain: domain.to_string(),
                user_name: Some("alice".to_string()),
                sp_address: sp_addr.to_string(),
                nonce: Some(nonce.to_string()),
                signature: Some(sig),
            }),
        )
        .await;

        unsafe { std::env::remove_var("CLOUDFLARE_API_BASE_URL"); }
        // Regardless of what the first call returned, the reused nonce must 401.
        assert_eq!(resp.0, StatusCode::UNAUTHORIZED);
        let _ = first;
    }

    #[tokio::test]
    async fn test_register_valid_signature_success() {
        let _guard = CF_ENV_LOCK.lock().unwrap();
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";
        let nonce = "nonce-good";
                // Use a name almost certain to have no DNS record yet, so the DNS
        // existence check returns Ok(None) and registration proceeds.
        let user_name = format!("dana-test-user-{}", rand::random::<u64>());
        let sig = sign_challenge(&secp, &spend_secret, "sp", nonce, &user_name, domain);

        let m = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/zones/zone-test/dns_records"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(&serde_json::json!({
                        "success": true,
                        "result": { "id": "rec-xyz" },
                    })),
            )
            .expect(1)
            .mount(&m)
            .await;
        unsafe { std::env::set_var("CLOUDFLARE_API_BASE_URL", m.uri()); }

        let state = register_state(domain);
        make_nonce(
            &state.nonce_store,
            nonce,
            &user_name,
            &sp_addr.to_string(),
            domain,
            Instant::now() + Duration::from_secs(60),
        ).await;

        let resp = handle_register(
            State(Arc::new(state)),
            Json(RegisterRequest {
                id: "req1".to_string(),
                domain: domain.to_string(),
                user_name: Some(user_name.clone()),
                sp_address: sp_addr.to_string(),
                nonce: Some(nonce.to_string()),
                signature: Some(sig),
            }),
        )
        .await;

        unsafe { std::env::remove_var("CLOUDFLARE_API_BASE_URL"); }
        // Valid signature + valid nonce must pass challenge-response: any
        // outcome other than UNAUTHORIZED proves the enforcement accepted it.
        assert_ne!(resp.0, StatusCode::UNAUTHORIZED);
    }


    // ── R3: identity fields are covered by the wallet signature ──
    // The signed message is now challenge_message(...) =
    // dana-register:{network_key}:{nonce}:{user_name}:{domain}. These cases
    // prove the retired pre-R3 format can never be accepted again, and that
    // user_name/domain mismatches are caught by the signature itself, not only
    // by claim_nonce's server-side comparison.

    // Helper: sign an arbitrary message with the spend key (for messages the
    // production builder must reject: legacy format / foreign identity fields).
    fn sign_message_raw(
        spend_secret: &silentpayments::secp256k1::SecretKey,
        message: &str,
    ) -> String {
        use silentpayments::secp256k1::{Keypair, Message, Secp256k1};
        use sha2::{Digest, Sha256};
        use rand::thread_rng;

        let secp = Secp256k1::new();
        let digest = Sha256::digest(message.as_bytes());
        let msg = Message::from_digest_slice(&digest).unwrap();
        let keypair = Keypair::from_seckey_slice(&secp, &spend_secret.secret_bytes()).unwrap();
        let sig = secp.sign_schnorr_with_rng(&msg, &keypair, &mut thread_rng());
        hex::encode(sig.serialize())
    }

    #[tokio::test]
    async fn test_register_old_format_signature_rejected() {
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(
            &silentpayments::secp256k1::Secp256k1::new(),
            &scan_secret,
            &spend_secret,
        );
        let domain = "danawallet.app";
        let nonce = "nonce-old-fmt";

        // Signature over the retired pre-R3 message (legacy prefix, no identity
        // binding). Everything else is valid, so only the format can reject it.
        let legacy_sig = sign_message_raw(&spend_secret, &format!("dana:v1:challenge:sp:{}", nonce));

        let state = register_state(domain);
        make_nonce(
            &state.nonce_store,
            nonce,
            "alice",
            &sp_addr.to_string(),
            domain,
            Instant::now() + Duration::from_secs(60),
        ).await;

        let resp = handle_register(
            State(Arc::new(state)),
            Json(RegisterRequest {
                id: "req1".to_string(),
                domain: domain.to_string(),
                user_name: Some("alice".to_string()),
                sp_address: sp_addr.to_string(),
                nonce: Some(nonce.to_string()),
                signature: Some(legacy_sig),
            }),
        )
        .await;

        assert_eq!(resp.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_register_new_format_signature_accepted() {
        let _guard = CF_ENV_LOCK.lock().unwrap();
        let secp = silentpayments::secp256k1::Secp256k1::new();
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(&secp, &scan_secret, &spend_secret);
        let domain = "danawallet.app";
        let nonce = "nonce-new-fmt";
        // Name almost certainly unregistered, so the DNS existence check passes.
        let user_name = format!("dana-test-user-{}", rand::random::<u64>());

        // Happy path under the new bound format: signed over the very values the
        // claimed NonceEntry carries.
        let sig = sign_challenge(&secp, &spend_secret, "sp", nonce, &user_name, domain);

        let m = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/zones/zone-test/dns_records"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(&serde_json::json!({
                        "success": true,
                        "result": { "id": "rec-xyz" },
                    })),
            )
            .expect(1)
            .mount(&m)
            .await;
        unsafe { std::env::set_var("CLOUDFLARE_API_BASE_URL", m.uri()); }

        let state = register_state(domain);
        make_nonce(
            &state.nonce_store,
            nonce,
            &user_name,
            &sp_addr.to_string(),
            domain,
            Instant::now() + Duration::from_secs(60),
        ).await;

        let resp = handle_register(
            State(Arc::new(state)),
            Json(RegisterRequest {
                id: "req1".to_string(),
                domain: domain.to_string(),
                user_name: Some(user_name.clone()),
                sp_address: sp_addr.to_string(),
                nonce: Some(nonce.to_string()),
                signature: Some(sig),
            }),
        )
        .await;

        unsafe { std::env::remove_var("CLOUDFLARE_API_BASE_URL"); }
        assert_ne!(resp.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_register_signature_user_name_mismatch_rejected() {
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(
            &silentpayments::secp256k1::Secp256k1::new(),
            &scan_secret,
            &spend_secret,
        );
        let domain = "danawallet.app";
        let nonce = "nonce-user-mismatch";

        // New-format message over a *different* user_name than the claimed entry.
        // The request carries the entry's real name, so claim_nonce matches and
        // only the signature check can reject this.
        let sig = sign_message_raw(
            &spend_secret,
            &challenge_message("sp", nonce, "mallory", domain),
        );

        let state = register_state(domain);
        make_nonce(
            &state.nonce_store,
            nonce,
            "alice",
            &sp_addr.to_string(),
            domain,
            Instant::now() + Duration::from_secs(60),
        ).await;

        let resp = handle_register(
            State(Arc::new(state)),
            Json(RegisterRequest {
                id: "req1".to_string(),
                domain: domain.to_string(),
                user_name: Some("alice".to_string()),
                sp_address: sp_addr.to_string(),
                nonce: Some(nonce.to_string()),
                signature: Some(sig),
            }),
        )
        .await;

        assert_eq!(resp.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_register_signature_domain_mismatch_rejected() {
        let scan_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let spend_secret = silentpayments::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let sp_addr = make_sp_address(
            &silentpayments::secp256k1::Secp256k1::new(),
            &scan_secret,
            &spend_secret,
        );
        let domain = "danawallet.app";
        let nonce = "nonce-domain-mismatch";

        // Same as above with the domain field foreign instead of the user name.
        let sig = sign_message_raw(
            &spend_secret,
            &challenge_message("sp", nonce, "alice", "example.com"),
        );

        let state = register_state(domain);
        make_nonce(
            &state.nonce_store,
            nonce,
            "alice",
            &sp_addr.to_string(),
            domain,
            Instant::now() + Duration::from_secs(60),
        ).await;

        let resp = handle_register(
            State(Arc::new(state)),
            Json(RegisterRequest {
                id: "req1".to_string(),
                domain: domain.to_string(),
                user_name: Some("alice".to_string()),
                sp_address: sp_addr.to_string(),
                nonce: Some(nonce.to_string()),
                signature: Some(sig),
            }),
        )
        .await;

        assert_eq!(resp.0, StatusCode::UNAUTHORIZED);
    }
}
