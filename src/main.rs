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

const NONCE_TTL_SECS: u64 = 300; // 5 minutes

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
    // Per-username mutexes so check-and-create for the same name is serialized,
    // closing the TOCTOU window between the DNS exists-check and TXT creation.
    username_locks: Arc<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
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
/// write lock; the caller owns the entry and must call `restore_nonce` if the
/// registration attempt ultimately fails.
async fn claim_nonce(
    nonce_store: &Arc<RwLock<HashMap<String, NonceEntry>>>,
    nonce: &str,
    user_name: &str,
    sp_address: &str,
    domain: &str,
) -> Result<NonceEntry, String> {
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
    Ok(store.remove(nonce).expect("validated nonce is present"))
}

/// Restore a claimed nonce after a failed registration attempt so the client
/// can retry with the same nonce. It remains single-use only on success.
async fn restore_nonce(
    nonce_store: &Arc<RwLock<HashMap<String, NonceEntry>>>,
    nonce: &str,
    entry: NonceEntry,
) {
    nonce_store.write().await.insert(nonce.to_string(), entry);
}

/// Get (or create) the per-username lock for `user_name`. The caller holds it
/// across the DNS exists-check and TXT creation so concurrent registrations for
/// the same name cannot both see "absent" and both create the record (MODERATE-5).
fn get_username_lock(state: &AppState, user_name: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = state
        .username_locks
        .lock()
        .expect("username_locks mutex poisoned");
    locks
        .entry(user_name.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
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
    // cannot both proceed. On any failure after this point the nonce is
    // restored so the client can retry.
    let claimed_nonce = match claim_nonce(
        &state.nonce_store,
        &request.nonce,
        &user_name,
        &request.sp_address,
        &request.domain,
    )
    .await
    {
        Ok(entry) => entry,
        Err(msg) => {
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
    };

    // Verify signature over the nonce + user_name + domain
    let signed_message = format!(
        "dana-register:{}:{}:{}:{}",
        network_key, request.nonce, user_name, state.domain
    );

    if let Err(e) = verify_schnorr_signature(&request.signature, &signed_message, &sp_address) {
            restore_nonce(&state.nonce_store, &request.nonce, claimed_nonce).await;
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
            restore_nonce(&state.nonce_store, &request.nonce, claimed_nonce).await;
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

    // Serialize check-and-create for the same user name: without this, two
    // concurrent registrations can both see "no TXT exists" and both create one.
    let username_lock = get_username_lock(&state, &user_name);
    let _username_guard = username_lock.lock().await;

    // First check if the record already exists using DNS-over-HTTPS
    match fetch_sp_address_from_txt_record(&user_name, &state.domain, sp_address.get_network())
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
            restore_nonce(&state.nonce_store, &request.nonce, claimed_nonce).await;
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
            restore_nonce(&state.nonce_store, &request.nonce, claimed_nonce).await;
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
            restore_nonce(&state.nonce_store, &request.nonce, claimed_nonce).await;
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
            restore_nonce(&state.nonce_store, &request.nonce, claimed_nonce).await;
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
        username_locks: Arc::new(std::sync::Mutex::new(HashMap::new())),
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
async fn test_nonce_restore_allows_retry() {
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

    let claimed = super::claim_nonce(&store, "n1", "alice", "sp1alice", "test.com")
        .await
        .unwrap();

    // A failed registration attempt restores the nonce for a retry.
    super::restore_nonce(&store, "n1", claimed).await;

    let retry = super::claim_nonce(&store, "n1", "alice", "sp1alice", "test.com").await;
    assert!(retry.is_ok());
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

    #[tokio::test]
    async fn test_username_lock_serializes_same_name() {
        let state = AppState {
            zone_id: "zone".into(),
            api_token: "token".into(),
            domain: "test.com".into(),
            sp_to_dana: Arc::new(RwLock::new(HashMap::new())),
            dana_to_sp: Arc::new(RwLock::new(HashMap::new())),
            network: SpNetwork::Mainnet,
            nonce_store: Arc::new(RwLock::new(HashMap::new())),
            username_locks: Arc::new(std::sync::Mutex::new(HashMap::new())),
        };

        // Same user name => the same underlying lock, so check-and-create is serialized.
        let l1 = get_username_lock(&state, "alice");
        let l2 = get_username_lock(&state, "alice");
        assert!(Arc::ptr_eq(&l1, &l2));

        // Different user names => independent locks (no cross-user serialization).
        let lbob = get_username_lock(&state, "bob");
        assert!(!Arc::ptr_eq(&l1, &lbob));

        // The lock actually blocks a concurrent acquire for the same name (TOCTOU fix).
        let binding = l1.clone();
        let _g1 = binding.lock().await;
        assert!(l2.try_lock().is_err());
        drop(_g1);
        assert!(l2.try_lock().is_ok());
    }
}
