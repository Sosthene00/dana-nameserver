mod api_structs;

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::Json as AxumJson,
    routing::{get, post},
};
use bitcoin_payment_instructions::{
    Network, PaymentInstructions, PaymentMethod, amount::Amount, dns_resolver::DNSHrnResolver,
};
use log::{debug, error, info, warn};
use rand::RngCore;
use reqwest::Client;
use silentpayments::{Network as SpNetwork, SilentPaymentAddress};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tokio::sync::RwLock;

use crate::api_structs::{
    ApiResponse, CloudflareRequest, GetInfoResponse, LookupRequest, LookupResponse,
    PrefixSearchRequest, PrefixSearchResponse, Record, RegisterPrepareRequest,
    RegisterPrepareResponse, RegisterRequest, RegisterResponse,
};

const CLOUDFLARE_API_BASE_URL: &str = "https://api.cloudflare.com/client/v4";
const CLOUDFLARE_DNS_RESOLVER_IP: &str = "1.1.1.1:53";

/// Base URL for the Cloudflare API. Defaults to the real API; override with the
/// `CLOUDFLARE_API_BASE_URL` env var to point at a local mock server for testing.
fn cloudflare_base_url() -> String {
    std::env::var("CLOUDFLARE_API_BASE_URL")
        .unwrap_or_else(|_| CLOUDFLARE_API_BASE_URL.to_string())
}

/// Bounded HTTP client for the Cloudflare round-trips made during /register.
/// Both deadlines are mandatory while the global register-create mutex is
/// held (per-name locking is absent on this lane): without them a single
/// stalled API peer head-of-line-blocks every registration until a restart
/// (HIGH-availability finding t_466ace42).
fn register_http_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .connect_timeout(Duration::from_secs(REGISTER_CREATE_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(REGISTER_CREATE_TIMEOUT_SECS))
        .build()
}

const NONCE_TTL_SECS: u64 = 300; // 5 minutes

/// Hard deadline for the DNS TXT exists-check round-trip during /register: the
/// proof build over plain DNS-over-TCP to the configured resolver plus the
/// follow-up HRN resolution. Expiry fails only that one request (503) and
/// releases the register-create guard — a stalled resolver must no longer
/// head-of-line-block every registration (HIGH-availability finding t_466ace42).
const REGISTER_DNS_PROOF_TIMEOUT_SECS: u64 = 12;
/// Full-request deadline for the Cloudflare TXT create made while the
/// register-create guard is held; bounds the guard hold time against a
/// stalled Cloudflare API peer.
const REGISTER_CREATE_TIMEOUT_SECS: u64 = 15;
/// TCP/TLS connect deadline for that same Cloudflare client.
const REGISTER_CREATE_CONNECT_TIMEOUT_SECS: u64 = 5;

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
    sp_to_dana: Arc<RwLock<HashMap<SilentPaymentAddress, Vec<String>>>>,
    dana_to_sp: Arc<RwLock<HashMap<String, SilentPaymentAddress>>>,
    // we only accept registration requests from this network
    network: SpNetwork,
    // Challenge-response nonce store for signature auth
    nonce_store: Arc<RwLock<HashMap<String, NonceEntry>>>,
    // Serializes DNS exists-check + TXT creation so concurrent registrations
    // cannot both see "absent" and both create a record (MODERATE-5).
    // Hold time is bounded: every outbound call made under the guard carries a hard
    // deadline (REGISTER_*_TIMEOUT_SECS below), so a stalled upstream fails that one
    // request closed instead of stalling registrations until a process restart.
    register_create_lock: Arc<tokio::sync::Mutex<()>>,
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

async fn fetch_sp_address_from_txt_record(
    user_name: &str,
    domain: &str,
    network: SpNetwork,
) -> Result<Option<SilentPaymentAddress>> {
    debug!(
        "Checking if TXT record exists for user {} on domain {} and network {:?}",
        user_name, domain, network
    );
    // Let's not allow regtest address is doesn't make much sense anyway
    let core_network = match network {
        SpNetwork::Mainnet => Network::Bitcoin,
        SpNetwork::Testnet => Network::Testnet,
        SpNetwork::Regtest => return Err(anyhow::anyhow!("Don't allow for regtest address")),
    };
    // Basically silent payments doesn't make the distinction between different testnet
    let dns_resolver = DNSHrnResolver(SocketAddr::from_str(CLOUDFLARE_DNS_RESOLVER_IP).unwrap());
    let payment_instructions = match PaymentInstructions::parse(
        format!("{}@{}", user_name, domain).as_str(),
        core_network,
        &dns_resolver,
        true,
    )
    .await
    {
        Ok(instructions) => instructions,
        Err(e) => {
            if format!("{:?}", e).contains("Multiple TXT records") {
                warn!(
                    "Multiple TXT records found for {}@{}. This should have been cleaned up before DNS query.",
                    user_name, domain
                );
                return Err(anyhow::anyhow!(
                    "Multiple TXT records exist for {}@{}, which is invalid. Please clean up duplicate records.",
                    user_name,
                    domain
                ));
            } else {
                error!("Error parsing payment instructions: {:?}", e);
                match e {
                    bitcoin_payment_instructions::ParseError::HrnResolutionError(_) => {
                        return Ok(None);
                    } // We can't find a record for this user name
                    _ => {
                        return Err(anyhow::anyhow!(
                            "Error parsing payment instructions: {:?}",
                            e
                        ));
                    }
                }
            }
        }
    };
    match payment_instructions {
        PaymentInstructions::ConfigurableAmount(instructions) => {
            // The resolver is pretty much useless here since we're only interested in silent payment
            let hrn_resolver = DNSHrnResolver(dns_resolver.0);
            let dummy_amount = Amount::from_sats(10_000).unwrap(); // Just defining something unlikely to fail in case there's a lnurl in the same entry
            let fixed_amt_instructions =
                match instructions.set_amount(dummy_amount, &hrn_resolver).await {
                    Ok(instructions) => instructions,
                    Err(e) => return Err(anyhow::anyhow!("Error setting amount: {:?}", e)),
                };
            for method in fixed_amt_instructions.methods().iter() {
                match method {
                    PaymentMethod::SilentPayment(sp_address) => {
                        return Ok(Some(*sp_address));
                    }
                    _ => continue,
                }
            }
        }
        PaymentInstructions::FixedAmount(instructions) => {
            for method in instructions.methods().iter() {
                match method {
                    PaymentMethod::SilentPayment(sp_address) => {
                        return Ok(Some(*sp_address));
                    }
                    _ => continue,
                }
            }
        }
    };

    Ok(None)
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

async fn cleanup_expired_nonces(nonce_store: &Arc<RwLock<HashMap<String, NonceEntry>>>) {
    let mut store = nonce_store.write().await;
    store.retain(|_, entry| !entry.is_expired());
}

/// Prepare a nonce for challenge-response registration authentication
async fn handle_register_prepare(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterPrepareRequest>,
) -> (StatusCode, AxumJson<RegisterPrepareResponse>) {
    // Bound the in-memory nonce store by evicting expired entries
    cleanup_expired_nonces(&state.nonce_store).await;
    // Validate domain matches state domain
    if request.domain != state.domain {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(RegisterPrepareResponse {
                id: request.id,
                message: format!("Server registers for domain: {}", state.domain),
                nonce: None,
                error: None,
            }),
        );
    }

    // Validate user_name is present and non-empty
    let user_name = match request.user_name {
        Some(ref name) if !name.is_empty() => name.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(RegisterPrepareResponse {
                    id: request.id,
                    message: "User name is required".to_string(),
                    nonce: None,
                    error: None,
                }),
            );
        }
    };
    // Reject DNS-invalid user names before issuing a nonce (RFC 1035: ASCII alphanumeric + hyphens, 1-63)
    if !validate_dns_name(&user_name) {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(RegisterPrepareResponse {
                id: request.id,
                message:
                    "Invalid user name: must be ASCII alphanumeric and hyphens only, 1-63 chars"
                        .to_string(),
                nonce: None,
                error: None,
            }),
        );
    }

    // Parse SP address
    let sp_address = match SilentPaymentAddress::try_from(request.sp_address.clone()) {
        Ok(sp_address) => {
            debug!("Valid SP address: {}", sp_address);
            sp_address
        }
        Err(e) => {
            error!("Invalid SP address '{}': {}", request.sp_address, e);
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(RegisterPrepareResponse {
                    id: request.id,
                    message: format!("Invalid SP address: {}", e),
                    nonce: None,
                    error: None,
                }),
            );
        }
    };

    // Validate SP address network matches state network
    if sp_address.get_network() != state.network {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(RegisterPrepareResponse {
                id: request.id,
                message: format!(
                    "Registered address has wrong network type: {:?}, expected: {:?}",
                    sp_address.get_network(),
                    state.network
                ),
                nonce: None,
                error: None,
            }),
        );
    }

    // Clean up expired nonces
    cleanup_expired_nonces(&state.nonce_store).await;

    // Generate a 32-byte random nonce
    let mut nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);

    // Store the nonce in the nonce store
    let nonce_entry = NonceEntry {
        user_name: user_name.clone(),
        sp_address: sp_address.to_string(),
        domain: state.domain.clone(),
        expires_at: Instant::now() + Duration::from_secs(NONCE_TTL_SECS),
    };

    let mut store = state.nonce_store.write().await;
    store.insert(nonce_hex.clone(), nonce_entry);
    drop(store);

    info!(
        "Generated nonce for user {} on domain {} (expires in {}s)",
        user_name, state.domain, NONCE_TTL_SECS
    );

    (
        StatusCode::OK,
        AxumJson(RegisterPrepareResponse {
            id: request.id,
            message: "Nonce generated successfully".to_string(),
            nonce: Some(nonce_hex),
            error: None,
        }),
    )
}

/// Validate that a string is a well-formed DNS label (RFC 1035).
fn validate_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Verify a Schnorr signature over `message` using the spend public key
/// derived from `sp_address`.
///
/// The message is SHA-256 hashed before verification, as required by
/// the secp256k1 Schnorr signature scheme.
fn verify_schnorr_signature(
    signature_hex: &str,
    message: &str,
    sp_address: &SilentPaymentAddress,
) -> Result<(), String> {
    use secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
    use sha2::{Digest, Sha256};

    // Decode hex signature
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| format!("Invalid signature hex: {}", e))?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "Signature must be 64 bytes (got {})",
            sig_bytes.len()
        ));
    }

    // Parse Schnorr signature (secp256k1 0.28: schnorr::Signature, not SchnorrSig)
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("Invalid signature encoding: {}", e))?;

    // Get spend public key from SP address and convert to XOnlyPublicKey
    // (Schnorr signatures use X-only point compression)
    let spend_pubkey = sp_address.get_spend_key();
    let pk_bytes = spend_pubkey.serialize();
    let x_only_pubkey = XOnlyPublicKey::from_slice(&pk_bytes[1..])
        .map_err(|e| format!("Invalid X-only pubkey: {}", e))?;

    // SHA-256 hash the message
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let digest = hasher.finalize();

    // Create message from digest
    let msg = Message::from_digest_slice(&digest).map_err(|e| format!("Invalid digest: {}", e))?;

    // Verify
    let secp = Secp256k1::new();
    secp.verify_schnorr(&sig, &msg, &x_only_pubkey)
        .map_err(|e| format!("Signature verification failed: {}", e))
}

/// Atomically claim a registration nonce so two concurrent requests with the
/// same nonce cannot both proceed. Removes the nonce from the store under a
/// write lock; the nonce is single-use — on any later failure the client must
/// call `/register/prepare` again.
async fn claim_nonce(
    nonce_store: &Arc<RwLock<HashMap<String, NonceEntry>>>,
    nonce: &str,
    user_name: &str,
    sp_address: &str,
    domain: &str,
) -> Result<(), String> {
    let mut store = nonce_store.write().await;
    // Validate while holding the write lock; if claimable, remove it atomically.
    let claimable = match store.get(nonce) {
        None => false,
        Some(e) => {
            !e.is_expired()
                && e.user_name == user_name
                && e.sp_address == sp_address
                && e.domain == domain
        }
    };
    if !claimable {
        return match store.get(nonce) {
            None => Err(
                "Invalid or missing nonce. Please call /register/prepare first.".to_string(),
            ),
            Some(e) => {
                if e.is_expired() {
                    Err("Registration nonce expired. Please request a new one.".to_string())
                } else {
                    Err(
                        "Nonce does not match this registration request. Request a new one."
                            .to_string(),
                    )
                }
            }
        };
    }
    store.remove(nonce).expect("validated nonce is present");
    Ok(())
}

async fn handle_register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterRequest>,
) -> (StatusCode, AxumJson<RegisterResponse>) {
    // Bound the in-memory nonce store by evicting expired entries
    cleanup_expired_nonces(&state.nonce_store).await;
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
        match silentpayments::SilentPaymentAddress::try_from(request.sp_address.clone()) {
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

    if sp_address.get_network() != state.network {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(RegisterResponse {
                id: request.id,
                message: format!(
                    "Registered address has wrong network type: {:?}, expected: {:?}",
                    sp_address.get_network(),
                    state.network
                ),
                dana_address: None,
                sp_address: None,
                dns_record_id: None,
            }),
        );
    }

    // We modify the key depending on the network we're on (mainnet vs signet/testnet)
    let network_key = match sp_address.get_network() {
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

    // Extract user_name before validation (nonce may store None)
    let user_name = match request.user_name {
        Some(name) => name,
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

    // Atomically claim the nonce so concurrent requests with the same nonce
    // cannot both proceed. Claim consumes it; on any later failure the client
    // must call /register/prepare again.
    if let Err(msg) = claim_nonce(
        &state.nonce_store,
        &request.nonce,
        &user_name,
        &request.sp_address,
        &request.domain,
    )
    .await
    {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(RegisterResponse {
                id: request.id,
                message: msg,
                dana_address: None,
                sp_address: None,
                dns_record_id: None,
            }),
        );
    }

    // Verify signature over the nonce + user_name + domain
    let signed_message = format!(
        "dana-register:{}:{}:{}:{}",
        network_key, request.nonce, user_name, state.domain
    );

    if let Err(e) = verify_schnorr_signature(&request.signature, &signed_message, &sp_address) {
        warn!(
            "Signature verification failed for user '{}': {}",
            user_name, e
        );
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(RegisterResponse {
                id: request.id,
                message: format!("Invalid signature: {}", e),
                dana_address: None,
                sp_address: None,
                dns_record_id: None,
            }),
        );
    }
    debug!("Signature verified for user '{}'", user_name);

    // Validate DNS name before creating records
    if !validate_dns_name(&user_name) {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(RegisterResponse {
                id: request.id,
                message: "Invalid user name (alphanumeric and hyphens only, 1-63 chars)"
                    .to_string(),
                dana_address: None,
                sp_address: None,
                dns_record_id: None,
            }),
        );
    }

    let dana_address = format!("{}@{}", user_name, state.domain);
    let txt_name = format!("{}.user._bitcoin-payment.{}", user_name, state.domain);
    let txt_content = format!("bitcoin:?{}={}", network_key, sp_address.to_string());

    let _create_guard = state.register_create_lock.lock().await;

    // First check if the record already exists using DNS-over-HTTPS. The whole
    // proof-building round-trip carries a hard deadline: on expiry this one request
    // fails closed with 503, the `_create_guard` taken above drops on the return, and
    // other registrations keep flowing (no more indefinite head-of-line block).
    let existing_check = match tokio::time::timeout(
        Duration::from_secs(REGISTER_DNS_PROOF_TIMEOUT_SECS),
        fetch_sp_address_from_txt_record(&user_name, &state.domain, sp_address.get_network()),
    )
    .await
    {
        Err(_elapsed) => {
            warn!(
                "DNS TXT verification timed out after {}s for user {}; failing this request closed",
                REGISTER_DNS_PROOF_TIMEOUT_SECS,
                user_name
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: format!(
                        "DNS verification timed out after {} s, please retry",
                        REGISTER_DNS_PROOF_TIMEOUT_SECS
                    ),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                }),
            );
        }
        Ok(result) => result,
    };

    match existing_check
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
                    &dana_address, sp_address
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
            sp_address.get_network(),
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
    // Bounded so this call cannot pin the global register-create guard on a stalled
    // Cloudflare peer: on expiry the reqwest error trips the deadline arm below and
    // fails THIS request only (503), dropping the guard with the return.
    let client = match register_http_client() {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to build the bounded register HTTP client: {}", e);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: format!("Failed to prepare DNS record creation: {}", e),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                }),
            );
        }
    };

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
                    &dana_address, sp_address
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
            // Map our deadline trip to 503 for THAT one request; any other create
            // error keeps the pre-existing 500. Either early return drops _create_guard,
            // so a stalled upstream can no longer lock in every registration.
            let create_timed_out = e
                .downcast_ref::<reqwest::Error>()
                .map_or(false, |re| re.is_timeout());
            if create_timed_out {
                warn!(
                    "Timed out creating TXT record {} after {}s; failing this request only and releasing the register-create guard",
                    txt_name, REGISTER_CREATE_TIMEOUT_SECS
                );
            } else {
                error!("Error creating TXT record {}: {}", txt_name, e);
            }
            return (
                if create_timed_out {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                },
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
    let sp_address = match SilentPaymentAddress::try_from(query.sp_address.clone()) {
        Ok(sp_address) => {
            debug!(
                "Successfully parsed SP address: {} (network: {:?})",
                sp_address,
                sp_address.get_network()
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

    let sp_to_dana: Arc<RwLock<HashMap<SilentPaymentAddress, Vec<String>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let dana_to_sp: Arc<RwLock<HashMap<String, SilentPaymentAddress>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let nonce_store: Arc<RwLock<HashMap<String, NonceEntry>>> =
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
                                match SilentPaymentAddress::try_from(sp_addr_str.to_string()) {
                                    Ok(sp_address) => {
                                        let dana_addr = dana_address.clone();
                                        let existing =
                                            map.entry(sp_address).or_insert_with(Vec::new);
                                        existing.push(dana_addr.clone());
                                        reverse_map.insert(dana_addr.clone(), sp_address);
                                        info!(
                                            "Mapped SP address {} to Dana address {} (total mappings for this SP: {})",
                                            sp_addr_str,
                                            &dana_address,
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
                                match SilentPaymentAddress::try_from(sp_addr_str.to_string()) {
                                    Ok(sp_address) => {
                                        let dana_addr = dana_address.clone();
                                        let existing =
                                            map.entry(sp_address).or_insert_with(Vec::new);
                                        existing.push(dana_addr.clone());
                                        reverse_map.insert(dana_addr.clone(), sp_address);
                                        info!(
                                            "Mapped SP address {} to Dana address {} (total mappings for this SP: {})",
                                            sp_addr_str,
                                            &dana_address,
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
        nonce_store,
        register_create_lock: Arc::new(tokio::sync::Mutex::new(())),
    });

    let v1_router = Router::new()
        .route("/info", get(handle_get_info))
        .route("/register", post(handle_register))
        .route("/register/prepare", post(handle_register_prepare))
        .route("/lookup", get(handle_lookup_sp_address))
        .route("/search", get(handle_prefix_search));

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
    use silentpayments::SilentPaymentAddress;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path, header, query_param};

    #[tokio::test]
    async fn test_check_txt_record_exists_with_address() {
        let address_to_register = SilentPaymentAddress::try_from("sp1qq0cygnetgn3rz2kla5cp05nj5uetlsrzez0l4p8g7wehf7ldr93lcqadw65upymwzvp5ed38l8ur2rznd6934xh95msevwrdwtrpk372hyz4vr6g").unwrap();
        let result = fetch_sp_address_from_txt_record(
            "donate",
            "danawallet.app",
            address_to_register.get_network(),
        )
        .await;

        assert!(result.is_ok());

        assert_eq!(result.unwrap(), Some(address_to_register));
    }

    #[tokio::test]
    async fn test_check_txt_record_does_not_exist() {
        let result =
            fetch_sp_address_from_txt_record("invalid", "danawallet.app", SpNetwork::Mainnet).await;

        assert!(result.is_ok());

        assert_eq!(result.unwrap(), None);
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

        // No TXT record => HrnResolutionError, which the function maps to Ok(None).
        assert!(result.unwrap().is_none());
    }

    // ── Unit tests for signature verification, DNS name validation, nonce expiry ──

    #[test]
    fn test_verify_schnorr_signature_valid() {
        use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
        use sha2::{Digest, Sha256};

        let secp = Secp256k1::new();

        // Generate a random keypair
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let keypair = Keypair::from_seckey_slice(&secp, secret_key.as_ref()).unwrap();
        let (x_only_pubkey, _parity) = XOnlyPublicKey::from_keypair(&keypair);

        // Hash a test message with SHA-256
        let message = "dana-register:sp:testnonce:testuser:testdomain.com";
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let digest = hasher.finalize();
        let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();

        // Sign with an RNG and verify
        let sig = secp.sign_schnorr_with_rng(&msg, &keypair, &mut rand::thread_rng());
        assert!(secp.verify_schnorr(&sig, &msg, &x_only_pubkey).is_ok());
    }

    #[test]
    fn test_verify_schnorr_signature_invalid() {
        use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
        use sha2::{Digest, Sha256};

        let secp = Secp256k1::new();

        // Generate two different keypairs
        let sk_a = SecretKey::new(&mut rand::thread_rng());
        let keypair_a = Keypair::from_seckey_slice(&secp, sk_a.as_ref()).unwrap();
        let (pk_a, _) = XOnlyPublicKey::from_keypair(&keypair_a);

        let sk_b = SecretKey::new(&mut rand::thread_rng());
        let keypair_b = Keypair::from_seckey_slice(&secp, sk_b.as_ref()).unwrap();
        let (pk_b, _) = XOnlyPublicKey::from_keypair(&keypair_b);

        // Sign with keypair_a, verify with keypair_b — should fail
        let message = "dana-register:sp:testnonce:testuser:testdomain.com";
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let digest = hasher.finalize();
        let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();

        let sig = secp.sign_schnorr_with_rng(&msg, &keypair_a, &mut rand::thread_rng());
        assert!(secp.verify_schnorr(&sig, &msg, &pk_b).is_err());
    }

    #[test]
    fn test_validate_dns_name() {
        assert!(validate_dns_name("alice"));
        assert!(validate_dns_name("alice-123"));
        assert!(validate_dns_name("a")); // min 1 char
        assert!(!validate_dns_name("")); // empty
        assert!(!validate_dns_name("alice bob")); // space
        assert!(!validate_dns_name("alice@domain")); // @
        assert!(!validate_dns_name(&"a".repeat(64))); // max 63
        assert!(validate_dns_name(&"a".repeat(63))); // exactly 63
        // Reject non-ASCII (Unicode) labels — RFC 1035 names are ASCII
        assert!(!validate_dns_name("é"));
        assert!(!validate_dns_name("日本語"));
        assert!(!validate_dns_name("café"));
    }

    #[test]
    fn test_nonce_expiry() {
        let expired = NonceEntry {
            user_name: "test".into(),
            sp_address: "sp1test".into(),
            domain: "test.com".into(),
            expires_at: Instant::now() - Duration::from_secs(1),
        };
        assert!(expired.is_expired());

        let fresh = NonceEntry {
            user_name: "test".into(),
            sp_address: "sp1test".into(),
            domain: "test.com".into(),
            expires_at: Instant::now() + Duration::from_secs(300),
        };
        assert!(!fresh.is_expired());
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

#[tokio::test]
async fn test_nonce_claim_is_atomic() {
    let store = std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    store.write().await.insert(
        "n1".to_string(),
        super::NonceEntry {
            user_name: "alice".into(),
            sp_address: "sp1alice".into(),
            domain: "test.com".into(),
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        },
    );

    // Two concurrent claims for the same nonce: exactly one succeeds.
    let a = super::claim_nonce(&store, "n1", "alice", "sp1alice", "test.com");
    let b = super::claim_nonce(&store, "n1", "alice", "sp1alice", "test.com");
    let (ra, rb) = tokio::join!(a, b);
    assert!(matches!((ra.is_ok(), rb.is_ok()), (true, false) | (false, true)));
}

#[tokio::test]
async fn test_nonce_claim_is_single_use() {
    let store = std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    store.write().await.insert(
        "n1".to_string(),
        super::NonceEntry {
            user_name: "alice".into(),
            sp_address: "sp1alice".into(),
            domain: "test.com".into(),
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        },
    );

    assert!(
        super::claim_nonce(&store, "n1", "alice", "sp1alice", "test.com")
            .await
            .is_ok()
    );

    // Claim removes the nonce; a retry must go through /register/prepare again.
    let retry = super::claim_nonce(&store, "n1", "alice", "sp1alice", "test.com").await;
    assert!(retry.is_err());
}

#[tokio::test]
async fn test_nonce_claim_rejects_mismatch_and_expired() {
    let store = std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    store.write().await.insert(
        "n1".to_string(),
        super::NonceEntry {
            user_name: "alice".into(),
            sp_address: "sp1alice".into(),
            domain: "test.com".into(),
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        },
    );

    // Claim with mismatched data is rejected and the nonce stays available.
    let mismatch = super::claim_nonce(&store, "n1", "bob", "sp1bob", "test.com").await;
    assert!(mismatch.is_err());

    // The legitimate claim still works (the mismatched attempt did not consume it).
    let legit = super::claim_nonce(&store, "n1", "alice", "sp1alice", "test.com").await;
    assert!(legit.is_ok());

    // An expired nonce is rejected.
    store.write().await.insert(
        "n2".to_string(),
        super::NonceEntry {
            user_name: "alice".into(),
            sp_address: "sp1alice".into(),
            domain: "test.com".into(),
            expires_at: std::time::Instant::now() - std::time::Duration::from_secs(1),
        },
    );
    let expired = super::claim_nonce(&store, "n2", "alice", "sp1alice", "test.com").await;
    assert!(expired.is_err());
}

    // ───────────────────────────────────────────────────────────────────────
    // HIGH-availability regression for finding t_466ace42: the register-create
    // critical section must fail CLOSED on a stalled upstream instead of
    // pinning every registration until a process restart.
    //
    // RED at base a6147ff: no outbound deadline exists anywhere on the
    // register path, so the stalled stub request below hangs forever while
    // holding the global register-create mutex ⇒ the 60/90s bound asserts fire.
    // GREEN with the REGISTER_*_TIMEOUT_SECS deadlines + their fail-closed arms.
    //
    // API-neutral by design: the tests only touch items that exist at base
    // (handle_register, AppState, the CLOUDFLARE_API_BASE_URL stub hook), so
    // the same text compiles red at base and green on the fix commit.
    // ───────────────────────────────────────────────────────────────────────

    /// std::net stub of the Cloudflare TXT-create endpoint (deliberately avoids
    /// async/tokio features + wiremock so a stalled request cannot share any
    /// client/pool state with the answered one). A POST whose JSON body
    /// mentions the trigger word "stale-me" in its JSON body is read and then NEVER
    /// answered (connection held open)
    /// — the stalled round-trip from the finding. Any other POST gets an
    /// instant 200 with a record id.
    fn spawn_stalling_cloudflare_stub() -> std::net::SocketAddr {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("stub bind");
        let addr = listener.local_addr().expect("stub addr");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                buf.extend(chunk[..n].iter());
                                if buf.contains(&b'}') {
                                    break; // whole (small) JSON body arrived
                                }
                            }
                        }
                    }
                    let text = String::from_utf8_lossy(&buf);
                    if text.contains("stale-me") {
                        // Never answer: the client must hit its own deadline and
                        // fail that one request closed. Keep the socket open.
                        std::mem::forget(stream);
                        return;
                    }
                    let body = r#"{"success":true,"result":{"id":"rec-stub-ok"}}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                });
            }
        });
        addr
    }

    /// Mint a testnet SP address with a known key and sign the exact server
    /// challenge message, mirroring handle_register's scheme
    /// `dana-register:<network key>:<nonce>:<user name>:<server domain>` with
    /// network key `tsp` for Testnet. Returns (sp address string, sig hex).
    fn mint_signed_identity(nonce: &str, user_name: &str, domain: &str) -> (String, String) {
        use secp256k1::{Keypair, Message, Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
        use sha2::{Digest, Sha256};
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let kp = Keypair::from_seckey_slice(&secp, sk.as_ref()).expect("keypair");
        let (x_only, parity) = XOnlyPublicKey::from_keypair(&kp);
        // secp256k1 0.28 has no PublicKey::from_x_only; rebuild the compressed key
        // from x bytes + parity and parse it via the stable from_slice path.
        let mut compressed = [0u8; 33];
        compressed[0] = match parity { Parity::Even => 2u8, Parity::Odd => 3u8 };
        compressed[1..].copy_from_slice(&x_only.serialize());
        let pubkey = PublicKey::from_slice(&compressed).expect("compressed pubkey");
        // The server verifies the challenge signature against the SP spend key;
        // scan key == spend key keeps this a parseable BIP-352 shape.
        let addr = SilentPaymentAddress::new(pubkey, pubkey, SpNetwork::Testnet, 0).expect("sp address");
        let addr_str = addr.to_string();
        let message = format!("dana-register:tsp:{}:{}:{}", nonce, user_name, domain);
        let digest = Sha256::digest(message.as_bytes());
        let msg = Message::from_digest_slice(&digest).expect("32-byte digest");
        let sig = secp.sign_schnorr_with_rng(&msg, &kp, &mut rand::thread_rng());
        (addr_str, hex::encode(&sig.serialize()[..]))
    }

    fn stall_test_state() -> Arc<AppState> {
        // Same real domain the existing DNS-fetch tests use: an unknown user's
        // TXT lookup answers NXDOMAIN ⇒ Ok(None) fast, so the register path
        // always reaches the (stubbed) Cloudflare create leg.
        Arc::new(AppState {
            zone_id: "zone-1".to_string(),
            api_token: "tkn-1".to_string(),
            domain: "danawallet.app".to_string(),
            sp_to_dana: Arc::new(RwLock::new(HashMap::new())),
            dana_to_sp: Arc::new(RwLock::new(HashMap::new())),
            network: SpNetwork::Testnet,
            nonce_store: Arc::new(RwLock::new(HashMap::new())),
            register_create_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    async fn seed_nonce(state: &AppState, nonce: &str, user_name: &str, sp_str: &str, domain: &str) {
        state.nonce_store.write().await.insert(
            nonce.to_string(),
            NonceEntry {
                user_name: user_name.to_string(),
                sp_address: sp_str.to_string(),
                domain: domain.to_string(),
                expires_at: Instant::now() + Duration::from_secs(300),
            },
        );
    }

    /// One full signed /register drive; the user name must NOT contain the
    /// stub's stall trigger word unless the request is meant to stall.
    async fn drive_register(state: &Arc<AppState>, user_name: &str, nonce: &str) -> (StatusCode, RegisterResponse) {
        let domain = state.domain.clone();
        let (sp_str, sig_hex) = mint_signed_identity(nonce, user_name, &domain);
        seed_nonce(state, nonce, user_name, &sp_str, &domain).await;
        let request = RegisterRequest {
            id: format!("regression-{}", user_name),
            domain: domain.clone(),
            user_name: Some(user_name.to_string()),
            sp_address: sp_str,
            signature: sig_hex,
            nonce: nonce.to_string(),
        };
        let (status, AxumJson(body)) = handle_register(State(state.clone()), Json(request)).await;
        (status, body)
    }

    #[tokio::test]
    async fn test_register_stalled_create_fails_closed_and_releases_guard() {
        let _serial = CF_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let stub = spawn_stalling_cloudflare_stub();
        unsafe { std::env::set_var("CLOUDFLARE_API_BASE_URL", format!("http://{}", stub)) };
        let state = stall_test_state();

        // (a) The stalled Cloudflare create must fail THIS one request closed
        // (503 from the deadline arm) instead of hanging. RED at base: no client
        // deadline ⇒ the 60s bound trips (pre-fix panic below).
        let stalled_res = tokio::time::timeout(
            Duration::from_secs(60),
            drive_register(&state, "stale-me-a", "nonce-stale-a"),
        )
        .await;
        // (b) The guard did not leak: a later registration still succeeds.
        let later_res = tokio::time::timeout(
            Duration::from_secs(60),
            drive_register(&state, "later-b", "nonce-later-b"),
        )
        .await;

        unsafe { std::env::remove_var("CLOUDFLARE_API_BASE_URL") };
        std::mem::drop(_serial);

        let stalled = match stalled_res {
            Err(_elapsed) => panic!(
                "stalled /register hung past the 60s bound — the create round-trip must fail closed on its own deadline (pre-fix RED state)"
            ),
            Ok(res) => res,
        };
        let later = match later_res {
            Err(_elapsed) => panic!(
                "a registration stayed blocked after the stalled request — its guard/slot leaked when the deadline tripped (pre-fix RED state)"
            ),
            Ok(res) => res,
        };
        assert_eq!(stalled.0, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            stalled.1.message.to_lowercase().contains("timed out"),
            "expected a deadline-exceeded failure, got: {}",
            stalled.1.message
        );
        assert_eq!(stalled.1.dns_record_id, None);
        assert_eq!(later.0, StatusCode::OK);
        assert_eq!(later.1.dns_record_id.as_deref().map(|s| &s[..]), Some("rec-stub-ok"));
    }


    #[tokio::test]
    async fn test_register_concurrent_different_names_not_head_of_line_blocked() {
        let _serial = CF_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let stub = spawn_stalling_cloudflare_stub();
        unsafe { std::env::set_var("CLOUDFLARE_API_BASE_URL", format!("http://{}", stub)) };
        let state = stall_test_state();

        // While request A ("stale-me-b") is pinned on the stalled stub, a
        // concurrent /register for a DIFFERENT name ("quick-b") must still
        // complete. RED at base: A holds the global register-create mutex
        // forever (no deadline anywhere) ⇒ B waits forever ⇒ 90s bound trips.
        // With the fix, A fails closed at its deadline and B gets its 200.
        let pair_res = tokio::time::timeout(
            Duration::from_secs(90),
            async move {
                tokio::join!(
                    drive_register(&state, "stale-me-b", "nonce-hol-b"),
                    drive_register(&state, "quick-b", "nonce-hol-quick-b")
                )
            },
        )
        .await;

        unsafe { std::env::remove_var("CLOUDFLARE_API_BASE_URL") };
        std::mem::drop(_serial);

        let pair = match pair_res {
            Err(_elapsed) => panic!(
                "the /register for a different name was head-of-line-blocked behind the stalled one (pre-fix RED state)"
            ),
            Ok(pair) => pair,
        };
        let (a, b) = pair;
        assert_eq!(a.0, StatusCode::SERVICE_UNAVAILABLE);
        assert!(a.1.message.to_lowercase().contains("timed out"), "a: {}", a.1.message);
        assert_eq!(b.0, StatusCode::OK);
        assert_eq!(b.1.dns_record_id.as_deref().map(|s| &s[..]), Some("rec-stub-ok"));
    }


    #[tokio::test]
    async fn test_register_happy_path_through_bounded_client() {
        let _serial = CF_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let stub = spawn_stalling_cloudflare_stub();
        unsafe { std::env::set_var("CLOUDFLARE_API_BASE_URL", format!("http://{}", stub)) };
        let state = stall_test_state();

        // Acceptance anchor: with real connect+request deadlines on the create
        // client, a normal registration against a responsive upstream still
        // succeeds end-to-end and updates both maps. (GREEN at base too; it must
        // stay green under the fix.)
        let domain = state.domain.clone();
        let (sp_str, sig_hex) = mint_signed_identity("nonce-happy", "happy-c", &domain);
        seed_nonce(&state, "nonce-happy", "happy-c", &sp_str, &domain).await;
        let request = RegisterRequest {
            id: "regression-happy".to_string(),
            domain: domain.clone(),
            user_name: Some("happy-c".to_string()),
            sp_address: sp_str.clone(),
            signature: sig_hex,
            nonce: "nonce-happy".to_string(),
        };
        let drive = handle_register(State(state.clone()), Json(request)).await;
        unsafe { std::env::remove_var("CLOUDFLARE_API_BASE_URL") };
        std::mem::drop(_serial);

        let (status, body) = drive;
        assert_eq!(status, StatusCode::OK, "happy path body: {}", body.0.message);
        let body = body.0;
        assert_eq!(body.dns_record_id.as_deref().map(|s| &s[..]), Some("rec-stub-ok"));
        let dana_addr = format!("happy-c@{}", domain);
        assert_eq!(body.dana_address.as_deref().map(|s| &s[..]), Some(&dana_addr[..]));

        let sp = SilentPaymentAddress::try_from(sp_str.clone()).expect("parse minted sp address");
        let sp_map = state.sp_to_dana.read().await;
        assert!(
            sp_map.get(&sp).map_or(false, |names| names.iter().any(|n| n == &dana_addr)),
            "sp_to_dana not updated for {}",
            dana_addr
        );
        drop(sp_map);
        let dana_map = state.dana_to_sp.read().await;
        assert!(dana_map.contains_key(&dana_addr), "dana_to_sp not updated");
        drop(dana_map);
    }


}