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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tokio::sync::RwLock;

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
    // Per-peer outstanding nonce counts (keyed by request id) for rate limiting
    peer_nonce_counts: Arc<RwLock<HashMap<String, u32>>>,
    // Global outstanding-nonce counter for the aggregate cap
    outstanding_nonces: Arc<AtomicU64>,
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

/// Validate that a string is a well-formed DNS label (RFC 1035).
fn validate_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Challenge endpoint: issue a single-use nonce bound to the user_name / SP
/// address / domain. The client signs the returned message with the spend
/// private key; a later register/remove request supplies signature + nonce so
/// the server can verify ownership of the SP address.
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
                    "Invalid user name: must be ASCII alphanumeric and hyphens only, 1-63 chars"
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

    // Rate limiting: global aggregate cap, then per-peer cap.
    // The peer key is the client-supplied request id.
    let peer = request.id.clone();
    if state.outstanding_nonces.load(Ordering::SeqCst) >= state.max_pending_nonces {
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
    {
        let mut counts = state.peer_nonce_counts.write().await;
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

    // Store the nonce entry and bump the global counter
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
    state.outstanding_nonces.fetch_add(1, Ordering::SeqCst);

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
            message: format!("dana:v1:challenge:{}:{}", network_key, nonce),
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
    outstanding_nonces: &AtomicU64,
    nonce: &str,
    user_name: &str,
    sp_address: &str,
    domain: &str,
) -> Result<(), String> {
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
    if store.remove(nonce).is_none() {
        return Err("Nonce already consumed or raced. Request a fresh challenge.".to_string());
    }
    drop(store);
    outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
    Ok(())
}

/// Remove expired nonce entries to bound the in-memory store.
async fn cleanup_expired_nonces(nonce_store: &Arc<RwLock<HashMap<String, NonceEntry>>>) {
    let mut store = nonce_store.write().await;
    store.retain(|_, entry| !entry.is_expired());
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

    // ── Challenge-response enforcement ──
    // Refuse any DNS mutation unless the client presents a valid nonce issued
    // by /challenge AND a Schnorr signature over the challenge message
    // (dana:v1:challenge:{network_key}:{nonce}) signed with the spend private
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
    match claim_nonce(
        &state.nonce_store,
        &state.outstanding_nonces,
        &nonce,
        &user_name,
        &sp_address.to_string(),
        &state.domain,
    )
    .await
    {
        Ok(()) => {}
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
    }

    // Verify the Schnorr signature over the challenge message for this nonce.
    let message = format!("dana:v1:challenge:{}:{}", network_key, nonce);
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

    let dana_address = format!("{}@{}", user_name, state.domain);
    let txt_name = format!("{}.user._bitcoin-payment.{}", user_name, state.domain);
    let txt_content = format!("bitcoin:?{}={}", network_key, sp_address);

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
        outstanding_nonces: Arc::new(AtomicU64::new(0)),
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
        let counter = state.outstanding_nonces.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_expired_nonces(&store).await;
                // Reset the global counter to the live store size
                let size = store.read().await.len() as u64;
                counter.store(size, Ordering::SeqCst);
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
        assert!(validate_dns_name("a".repeat(63).as_str()));
    }

    #[test]
    fn test_validate_dns_name_invalid() {
        assert!(!validate_dns_name(""));
        assert!(!validate_dns_name("a".repeat(64).as_str()));
        assert!(!validate_dns_name("alice@example"));
        assert!(!validate_dns_name("alice bob"));
        assert!(!validate_dns_name("alice."));
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

        let message = "dana:v1:challenge:sp:deadbeef";
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

        let message = "dana:v1:challenge:sp:deadbeef";
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
        let counter = Arc::new(AtomicU64::new(1));

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
            claim_nonce(&store, &counter, "nonce1", "alice", "sp1qq...", "danawallet.app")
                .await
                .is_ok()
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // Single-use: a second claim fails because the nonce was consumed
        assert!(
            claim_nonce(&store, &counter, "nonce1", "alice", "sp1qq...", "danawallet.app")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_claim_nonce_mismatch() {
        let store: Arc<RwLock<HashMap<String, NonceEntry>>> = Arc::new(RwLock::new(HashMap::new()));
        let counter = Arc::new(AtomicU64::new(1));

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
            claim_nonce(&store, &counter, "nonce1", "bob", "sp1qq...", "danawallet.app")
                .await
                .is_err()
        );
        // Wrong SP address
        assert!(
            claim_nonce(&store, &counter, "nonce1", "alice", "sp1qq2...", "danawallet.app")
                .await
                .is_err()
        );
        // Wrong domain
        assert!(
            claim_nonce(&store, &counter, "nonce1", "alice", "sp1qq...", "example.com")
                .await
                .is_err()
        );
        // Counter is not decremented on failure
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_claim_nonce_expired() {
        let store: Arc<RwLock<HashMap<String, NonceEntry>>> = Arc::new(RwLock::new(HashMap::new()));
        let counter = Arc::new(AtomicU64::new(1));

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
            claim_nonce(&store, &counter, "nonce1", "alice", "sp1qq...", "danawallet.app")
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

        cleanup_expired_nonces(&store).await;

        let store = store.read().await;
        assert!(store.contains_key("fresh"));
        assert!(!store.contains_key("expired"));
    }

}
