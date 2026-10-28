mod api_structs;

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{ConnectInfo, Query, State},
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
use std::{net::{IpAddr, SocketAddr}, str::FromStr, sync::Arc};
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
/// Idle-drain period for the nonce janitor (t_fc0840f5).
const NONCE_JANITOR_INTERVAL_SECS: u64 = 30;

/// Hard capacity of the challenge-response nonce store. /register/prepare is
/// unauthenticated, so without a ceiling the store size is bounded only by the
/// attacker's request rate x the nonce TTL: every admitted call buys a 32-byte
/// RNG draw, a hex encode, an SP-address parse and three heap Strings (parent
/// finding t_b8902a36, card t_fc0840f5). Under the release profile's
/// panic = abort, OOM pressure takes the whole process down with it — /lookup
/// and /search die too — so the store needs a hard ceiling plus per-peer
/// budgets. Env overrides exist for the tests, mirroring the
/// CLOUDFLARE_API_BASE_URL hook precedent.
const NONCE_STORE_MAX_ENTRIES: usize = 10_000;
/// Pending-nonce budget per peer IP (binds before the global ceiling).
const NONCES_PER_IP_MAX_PENDING: usize = 64;
/// Pending-nonce budget per SP address (binds before the global ceiling).
const NONCES_PER_SP_MAX_PENDING: usize = 16;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn nonce_store_max_entries() -> usize {
    env_usize("DANA_NONCE_STORE_MAX_ENTRIES", NONCE_STORE_MAX_ENTRIES)
}

fn nonces_per_ip_max_pending() -> usize {
    env_usize("DANA_NONCES_PER_IP_MAX_PENDING", NONCES_PER_IP_MAX_PENDING)
}

fn nonces_per_sp_max_pending() -> usize {
    env_usize("DANA_NONCES_PER_SP_MAX_PENDING", NONCES_PER_SP_MAX_PENDING)
}

fn nonce_ttl_secs() -> u64 {
    env_u64("DANA_NONCE_TTL_SECS", NONCE_TTL_SECS).max(1)
}

/// Effective issuance limits, read per request like the other test hooks.
struct NonceCaps {
    max_entries: usize,
    per_ip_max: usize,
    per_sp_max: usize,
}

impl NonceCaps {
    fn from_env() -> Self {
        Self {
            max_entries: nonce_store_max_entries().max(1),
            per_ip_max: nonces_per_ip_max_pending().max(1),
            per_sp_max: nonces_per_sp_max_pending().max(1),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum IssueError {
    /// Global ceiling reached.
    GlobalFull,
    /// Peer IP's pending-nonce budget exhausted.
    IpFull,
    /// SP address's pending-nonce budget exhausted.
    SpFull,
}

/// The nonce store with its per-peer bookkeeping behind ONE lock, so a capped
/// entry can never strand a peer counter: every mutation runs under the same
/// write guard and the counters are re-derived from `entries` on every reap
/// (the single source of truth is `entries`; the maps are a pure index).
#[derive(Default)]
struct NonceStore {
    entries: HashMap<String, NonceEntry>,
    per_ip: HashMap<IpAddr, usize>,
    per_sp: HashMap<String, usize>,
}

fn dec_counter<K: std::hash::Hash + std::cmp::Eq>(counters: &mut HashMap<K, usize>, key: &K) {
    if let Some(count) = counters.get_mut(key) {
        *count = count.saturating_sub(1);
    }
}

impl NonceStore {
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&self, nonce: &str) -> Option<&NonceEntry> {
        self.entries.get(nonce)
    }

    fn put(&mut self, nonce: String, entry: NonceEntry) {
        *self.per_ip.entry(entry.issued_to_ip).or_insert(0) += 1;
        *self.per_sp.entry(entry.sp_address.clone()).or_insert(0) += 1;
        self.entries.insert(nonce, entry);
    }

    fn remove(&mut self, nonce: &str) -> Option<NonceEntry> {
        let entry = self.entries.remove(nonce)?;
        dec_counter(&mut self.per_ip, &entry.issued_to_ip);
        dec_counter(&mut self.per_sp, &entry.sp_address);
        Some(entry)
    }

    /// Check all three budgets and insert inside the caller's single write
    /// guard: a racing prepare cannot interleave the two, so the store stops
    /// AT the cap and the counters cannot drift. The RNG draw and the entry's
    /// heap work happen only once the call is admitted, so a refused flood
    /// request pays no per-entry allocation cost either.
    fn issue(
        &mut self,
        peer_ip: IpAddr,
        user_name: &str,
        sp_address: &str,
        domain: &str,
        ttl_secs: u64,
        caps: &NonceCaps,
    ) -> Result<String, IssueError> {
        if self.entries.len() >= caps.max_entries {
            return Err(IssueError::GlobalFull);
        }
        if self.per_ip.get(&peer_ip).copied().unwrap_or(0) >= caps.per_ip_max {
            return Err(IssueError::IpFull);
        }
        if self.per_sp.get(sp_address).copied().unwrap_or(0) >= caps.per_sp_max {
            return Err(IssueError::SpFull);
        }
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce_hex = hex::encode(nonce_bytes);
        self.put(
            nonce_hex.clone(),
            NonceEntry {
                user_name: user_name.to_string(),
                sp_address: sp_address.to_string(),
                domain: domain.to_string(),
                issued_to_ip: peer_ip,
                expires_at: Instant::now() + Duration::from_secs(ttl_secs),
            },
        );
        Ok(nonce_hex)
    }

    fn reap_expired(&mut self) -> usize {
        let mut reaped = 0_usize;
        self.entries.retain(|_, entry| {
            if entry.is_expired() {
                reaped += 1;
                false
            } else {
                true
            }
        });
        if reaped > 0 {
            // Re-derive the index from the survivors: counters and store cannot
            // diverge even if a path is ever added that drops entries.
            self.per_ip.clear();
            self.per_sp.clear();
            for entry in self.entries.values() {
                *self.per_ip.entry(entry.issued_to_ip).or_insert(0) += 1;
                *self.per_sp.entry(entry.sp_address.clone()).or_insert(0) += 1;
            }
        }
        reaped
    }
}

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
    /// OS-reported TCP peer address the entry was issued to — the key of the
    /// per-IP budget (ConnectInfo, not a forgeable header; see
    /// handle_register_prepare).
    issued_to_ip: IpAddr,
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
    // Challenge-response nonce store for signature auth: entries plus their
    // per-IP/per-SP budget index behind ONE lock, capacity-bounded at issue and
    // reaped by the janitor on the clock (t_fc0840f5).
    nonce_store: Arc<RwLock<NonceStore>>,
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

/// Full route table, factored out of main() so the HTTP-level regressions
/// below drive the exact surface the server exposes (t_fc0840f5 flood suite).
fn build_router(state: Arc<AppState>) -> Router {
    let v1_router = Router::new()
        .route("/info", get(handle_get_info))
        .route("/register", post(handle_register))
        .route("/register/prepare", post(handle_register_prepare))
        .route("/lookup", get(handle_lookup_sp_address))
        .route("/search", get(handle_prefix_search));
    Router::new().nest("/v1", v1_router).with_state(state)
}

/// Idle-drain period for the nonce janitor; tests shorten it via
/// DANA_NONCE_JANITOR_INTERVAL_SECS. The prod default stays well inside
/// NONCE_TTL_SECS so an idle server cannot sit on a store full of dead nonces.
fn nonce_janitor_interval_secs() -> u64 {
    std::env::var("DANA_NONCE_JANITOR_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value >= 1)
        .unwrap_or(NONCE_JANITOR_INTERVAL_SECS)
}

/// Drive nonce expiry from the clock instead of only inline at request entry:
/// an idle process must drain its nonce store without any new request arriving
/// (t_fc0840f5, parent finding t_b8902a36 — cleanup_expired_nonces used to run
/// only at the top of prepare/register, so a quiet server never reclaimed).
/// main() and the HTTP-level tests share this one path so they cannot diverge.
fn spawn_nonce_janitor(
    nonce_store: Arc<RwLock<NonceStore>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval(Duration::from_secs(nonce_janitor_interval_secs().max(1)));
        loop {
            tick.tick().await;
            cleanup_expired_nonces(&nonce_store).await;
        }
    })
}

async fn cleanup_expired_nonces(nonce_store: &Arc<RwLock<NonceStore>>) {
    nonce_store.write().await.reap_expired();
}

/// Prepare a nonce for challenge-response registration authentication.
///
/// The route is unauthenticated, so issuance is capped by the store's global
/// ceiling plus per-IP and per-SP-address budgets; past a budget the call is
/// refused with 429 (a plain refusal — never a panic or 5xx). The peer key is
/// ConnectInfo's OS-reported TCP socket address: this service has no
/// tower-http/TrustedProxy layer and never trusts X-Forwarded-For, so a
/// header-derived key would be attacker-chosen (forgeable). The socket peer
/// can only be forged by whoever owns the real return path — the exact
/// identity the per-IP budget is meant to meter.
async fn handle_register_prepare(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
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

    // Single source of truth for the size/budget decision: the cap checks and
    // the insert share one write guard (NonceStore::issue), so concurrent
    // prepares cannot overshoot the cap and the peer counters cannot strand.
    let peer_ip = peer.ip();
    let caps = NonceCaps::from_env();
    let ttl_secs = nonce_ttl_secs();
    let issued = {
        let mut store = state.nonce_store.write().await;
        store.issue(
            peer_ip,
            &user_name,
            request.sp_address.as_str(),
            &state.domain,
            ttl_secs,
            &caps,
        )
    };
    let nonce_hex = match issued {
        Ok(nonce_hex) => nonce_hex,
        Err(kind) => {
            let reason = match kind {
                IssueError::GlobalFull => {
                    "nonce store is at capacity; retry once older nonces have expired"
                }
                IssueError::IpFull => "too many pending registration nonces from this address",
                IssueError::SpFull => "too many pending registration nonces for this SP address",
            };
            warn!(
                "Nonce issuance refused for {}@{} from {}: {}",
                user_name, state.domain, peer_ip, reason
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                AxumJson(RegisterPrepareResponse {
                    id: request.id,
                    message: format!("Registration rate limit reached: {}", reason),
                    nonce: None,
                    error: Some("nonce_budget_exhausted".to_string()),
                }),
            );
        }
    };

    info!(
        "Generated nonce for user {} on domain {} (expires in {}s)",
        user_name, state.domain, ttl_secs
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
    nonce_store: &Arc<RwLock<NonceStore>>,
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
    let nonce_store: Arc<RwLock<NonceStore>> = Arc::new(RwLock::new(NonceStore::default()));

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

    // Idle-drain guarantee (t_fc0840f5): expired nonces leave the store on the
    // clock instead of only when another request happens to arrive.
    let _nonce_janitor = spawn_nonce_janitor(state.nonce_store.clone());

    let app = build_router(state);

    let server_addr = format!("{server_host}:{server_port}");

    let listener = tokio::net::TcpListener::bind(&server_addr)
        .await
        .expect("Failed to bind to server address");

    info!("Server starting on {server_addr}");
    info!("API endpoint available at: http://{server_addr}/v1/info");
    info!("API endpoint available at: http://{server_addr}/v1/register");
    info!("API endpoint available at: http://{server_addr}/v1/lookup");
    info!("API endpoint available at: http://{server_addr}/v1/search");

    // ConnectInfo (used by the bounded prepare handler) is only populated
    // when the app is served through into_make_service_with_connect_info().
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
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
            issued_to_ip: "203.0.113.7".parse().unwrap(),
            expires_at: Instant::now() - Duration::from_secs(1),
        };
        assert!(expired.is_expired());

        let fresh = NonceEntry {
            user_name: "test".into(),
            sp_address: "sp1test".into(),
            domain: "test.com".into(),
            issued_to_ip: "203.0.113.7".parse().unwrap(),
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
        let _guard = CF_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
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
        let _guard = CF_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
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
        let _guard = CF_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
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
        let _guard = CF_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
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
    let store = std::sync::Arc::new(tokio::sync::RwLock::new(NonceStore::default()));
    store.write().await.put(
        "n1".to_string(),
        super::NonceEntry {
            user_name: "alice".into(),
            sp_address: "sp1alice".into(),
            domain: "test.com".into(),
            issued_to_ip: "203.0.113.7".parse().unwrap(),
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
    let store = std::sync::Arc::new(tokio::sync::RwLock::new(NonceStore::default()));
    store.write().await.put(
        "n1".to_string(),
        super::NonceEntry {
            user_name: "alice".into(),
            sp_address: "sp1alice".into(),
            domain: "test.com".into(),
            issued_to_ip: "203.0.113.7".parse().unwrap(),
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
    let store = std::sync::Arc::new(tokio::sync::RwLock::new(NonceStore::default()));
    store.write().await.put(
        "n1".to_string(),
        super::NonceEntry {
            user_name: "alice".into(),
            sp_address: "sp1alice".into(),
            domain: "test.com".into(),
            issued_to_ip: "203.0.113.7".parse().unwrap(),
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
    store.write().await.put(
        "n2".to_string(),
        super::NonceEntry {
            user_name: "alice".into(),
            sp_address: "sp1alice".into(),
            domain: "test.com".into(),
            issued_to_ip: "203.0.113.7".parse().unwrap(),
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
            nonce_store: Arc::new(RwLock::new(NonceStore::default())),
            register_create_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    async fn seed_nonce(state: &AppState, nonce: &str, user_name: &str, sp_str: &str, domain: &str) {
        state.nonce_store.write().await.put(
            nonce.to_string(),
            NonceEntry {
                user_name: user_name.to_string(),
                sp_address: sp_str.to_string(),
                domain: domain.to_string(),
                issued_to_ip: "127.0.0.1".parse().unwrap(),
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



    // ───────────────────────────────────────────────────────────────────────
    // Unauthenticated DoS-class regression for parent finding t_b8902a36
    // (dev-loop card t_fc0840f5). At base 910d968 /v1/register/prepare is
    // unauthenticated (router post(...) with no route_layer/middleware) and
    // every admitted call inserted one NonceEntry keyed by fresh server
    // randomness, so the store grew attacker_rate x NONCE_TTL_SECS with no
    // capacity, no per-IP budget, no per-SP budget — and expiry ran only
    // inline at the next prepare/register, never on an idle process. Under
    // the release profile's panic = abort, OOM pressure takes /lookup and
    // /search down with it.
    //
    // RED at base: no 429 arm exists and the size asserts blow past every
    // configured bound; the TTL knob the expiry test needs does not exist
    // either. GREEN on the capacity/budget commit. The suite runs against the
    // real router over loopback so the flood walks production HTTP behavior
    // (JSON bodies, ConnectInfo peer address, the shared janitor).
    // ───────────────────────────────────────────────────────────────────────

    struct TestServer {
        addr: SocketAddr,
        state: Arc<AppState>,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            for task in &self.tasks {
                task.abort();
            }
        }
    }

    /// Serve the exact main() surface (build_router + janitor) on loopback.
    async fn spawn_flood_server(state: Arc<AppState>) -> TestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("flood server bind");
        let addr = listener.local_addr().expect("flood server addr");
        let serve_state = state.clone();
        let serve = tokio::spawn(async move {
            axum::serve(listener, build_router(serve_state).into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("test server");
        });
        let janitor = spawn_nonce_janitor(state.nonce_store.clone());
        TestServer {
            addr,
            state,
            tasks: vec![serve, janitor],
        }
    }

    fn flood_state() -> Arc<AppState> {
        Arc::new(AppState {
            zone_id: "zone-flood".to_string(),
            api_token: "tkn-flood".to_string(),
            domain: "danawallet.app".to_string(),
            sp_to_dana: Arc::new(RwLock::new(HashMap::new())),
            dana_to_sp: Arc::new(RwLock::new(HashMap::new())),
            network: SpNetwork::Testnet,
            nonce_store: Arc::new(RwLock::new(NonceStore::default())),
            register_create_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    fn flood_prepare_body(
        id: &str,
        domain: &str,
        user_name: &str,
        sp_address: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "domain": domain,
            "user_name": user_name,
            "sp_address": sp_address,
        })
    }

    async fn post_prepare(addr: SocketAddr, body: &serde_json::Value) -> (u16, serde_json::Value) {
        let url = format!("http://{}/v1/register/prepare", addr);
        let resp = reqwest::Client::new()
            .post(&url)
            .json(body)
            .send()
            .await
            .expect("prepare round-trip");
        let code = resp.status().as_u16();
        let body = resp
            .json::<serde_json::Value>()
            .await
            .expect("prepare json body");
        (code, body)
    }

    async fn get_lookup(addr: SocketAddr, sp_address: &str) -> u16 {
        let url = format!(
            "http://{}/v1/lookup?sp_address={}&id=live-probe",
            addr, sp_address
        );
        reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .expect("lookup round-trip")
            .status()
            .as_u16()
    }

    /// (sp address string, signing key) — every call mints a fresh identity so
    /// a flood can target one key with distinct per-request SP addresses or
    /// saturate one SP address on purpose.
    fn fresh_testnet_identity() -> (String, secp256k1::SecretKey) {
        use secp256k1::{Keypair, PublicKey, Parity, Secp256k1, SecretKey, XOnlyPublicKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let kp = Keypair::from_seckey_slice(&secp, sk.as_ref()).expect("keypair");
        let (x_only, parity) = XOnlyPublicKey::from_keypair(&kp);
        let mut compressed = [0u8; 33];
        compressed[0] = match parity {
            Parity::Even => 2u8,
            Parity::Odd => 3u8,
        };
        compressed[1..].copy_from_slice(&x_only.serialize());
        let pubkey = PublicKey::from_slice(&compressed).expect("compressed pubkey");
        let addr = SilentPaymentAddress::new(pubkey, pubkey, SpNetwork::Testnet, 0)
            .expect("sp address");
        (addr.to_string(), sk)
    }

    fn sign_registration(
        sk: &secp256k1::SecretKey,
        nonce: &str,
        user_name: &str,
        domain: &str,
    ) -> String {
        use secp256k1::{Keypair, Message, Secp256k1};
        use sha2::{Digest, Sha256};
        let secp = Secp256k1::new();
        let kp = Keypair::from_seckey_slice(&secp, sk.as_ref()).expect("keypair");
        let message = format!("dana-register:tsp:{}:{}:{}", nonce, user_name, domain);
        let digest = Sha256::digest(message.as_bytes());
        let msg = Message::from_digest_slice(&digest).expect("32-byte digest");
        let sig = secp.sign_schnorr_with_rng(&msg, &kp, &mut rand::thread_rng());
        hex::encode(&sig.serialize()[..])
    }

    fn make_register_request(
        id: &str,
        domain: &str,
        user_name: &str,
        sp_address: &str,
        signature: &str,
        nonce: &str,
    ) -> RegisterRequest {
        RegisterRequest {
            id: id.to_string(),
            domain: domain.to_string(),
            user_name: Some(user_name.to_string()),
            sp_address: sp_address.to_string(),
            signature: signature.to_string(),
            nonce: nonce.to_string(),
        }
    }

    #[tokio::test]
    async fn test_flood_prepare_store_stops_at_global_cap_and_429s() {
        let _serial = CF_ENV_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            std::env::set_var("DANA_NONCE_STORE_MAX_ENTRIES", "16");
            // Neutralise the per-peer budgets so the GLOBAL cap is what binds.
            std::env::set_var("DANA_NONCES_PER_IP_MAX_PENDING", "10000");
            std::env::set_var("DANA_NONCES_PER_SP_MAX_PENDING", "10000");
        }
        let srv = spawn_flood_server(flood_state()).await;
        let domain = "danawallet.app".to_string();

        let mut codes = Vec::new();
        let mut admitted = 0_u16;
        let mut refused_429 = 0_u16;
        for i in 0..24 {
            let (sp_str, _sk) = fresh_testnet_identity();
            let body = flood_prepare_body(
                &format!("gcap-{}", i),
                &domain,
                &format!("gcap-u{}", i),
                &sp_str,
            );
            let (code, resp) = post_prepare(srv.addr, &body).await;
            codes.push(code);
            if code == 200 && resp["nonce"].as_str().is_some() {
                admitted += 1;
            } else if code == 429 {
                refused_429 += 1;
            }
            // The cap must reject, not fault: any 5xx (or a dead server, which
            // surfaces here as a connection-level panic) is the release-profile
            // abort scenario this finding is about.
            assert!(
                code < 500,
                "server faulted {} on prepare #{} — the cap must answer 429, never 5xx",
                code,
                i
            );
        }

        // Store size stops AT the cap and the cap is what refuses.
        let len = srv.state.nonce_store.read().await.len();
        assert_eq!(
            len, 16,
            "nonce store must stop at the configured cap (codes: {:?})",
            codes
        );
        assert_eq!(admitted, 16, "only cap prepares may be admitted");
        assert_eq!(refused_429, 8, "every call past the cap must get a 429");

        // /lookup stays up in the same process across the flood.
        let (probe_sp, _probe_sk) = fresh_testnet_identity();
        let probe = tokio::time::timeout(Duration::from_secs(10), get_lookup(srv.addr, &probe_sp)).await;
        assert!(
            matches!(probe, Ok(code) if code < 500),
            "/lookup must stay live across the prepare flood, got {:?}",
            probe
        );

        drop(srv);
        unsafe {
            std::env::remove_var("DANA_NONCE_STORE_MAX_ENTRIES");
            std::env::remove_var("DANA_NONCES_PER_IP_MAX_PENDING");
            std::env::remove_var("DANA_NONCES_PER_SP_MAX_PENDING");
        }
    }

    #[tokio::test]
    async fn test_flood_per_ip_budget_caps_one_source_first() {
        let _serial = CF_ENV_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            std::env::set_var("DANA_NONCE_STORE_MAX_ENTRIES", "10000");
            // The whole loop connects from 127.0.0.1 with distinct SP
            // addresses, so only the per-IP budget can bind here.
            std::env::set_var("DANA_NONCES_PER_IP_MAX_PENDING", "6");
            std::env::set_var("DANA_NONCES_PER_SP_MAX_PENDING", "10000");
        }
        let srv = spawn_flood_server(flood_state()).await;
        let domain = "danawallet.app".to_string();

        let mut refused_429 = 0_u16;
        for i in 0..9 {
            let (sp_str, _sk) = fresh_testnet_identity();
            let body =
                flood_prepare_body(&format!("ip-{}", i), &domain, &format!("ip-u{}", i), &sp_str);
            let (code, _resp) = post_prepare(srv.addr, &body).await;
            assert!(code < 500, "peer budget overrun must 429, not fault ({})", code);
            if code == 429 {
                refused_429 += 1;
            }
        }
        let len = srv.state.nonce_store.read().await.len();
        assert_eq!(len, 6, "one source must stop at its per-IP budget");
        assert_eq!(refused_429, 3, "calls past the per-IP budget must 429");
        drop(srv);
        unsafe {
            std::env::remove_var("DANA_NONCE_STORE_MAX_ENTRIES");
            std::env::remove_var("DANA_NONCES_PER_IP_MAX_PENDING");
            std::env::remove_var("DANA_NONCES_PER_SP_MAX_PENDING");
        }
    }

    #[tokio::test]
    async fn test_flood_per_sp_budget_caps_one_address_first() {
        let _serial = CF_ENV_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            std::env::set_var("DANA_NONCE_STORE_MAX_ENTRIES", "10000");
            std::env::set_var("DANA_NONCES_PER_IP_MAX_PENDING", "10000");
            std::env::set_var("DANA_NONCES_PER_SP_MAX_PENDING", "3");
        }
        let srv = spawn_flood_server(flood_state()).await;
        let domain = "danawallet.app".to_string();
        let (shared_sp, _sk) = fresh_testnet_identity();

        let mut refused_429 = 0_u16;
        for i in 0..6 {
            let body = flood_prepare_body(&format!("sp-{}", i), &domain, "sp-u", &shared_sp);
            let (code, _resp) = post_prepare(srv.addr, &body).await;
            assert!(code < 500, "SP budget overrun must 429, not fault ({})", code);
            if code == 429 {
                refused_429 += 1;
            }
        }
        let len = srv.state.nonce_store.read().await.len();
        assert_eq!(len, 3, "one SP address must stop at its budget");
        assert_eq!(refused_429, 3, "calls past the SP budget must 429");
        drop(srv);
        unsafe {
            std::env::remove_var("DANA_NONCE_STORE_MAX_ENTRIES");
            std::env::remove_var("DANA_NONCES_PER_IP_MAX_PENDING");
            std::env::remove_var("DANA_NONCES_PER_SP_MAX_PENDING");
        }
    }

    #[tokio::test]
    async fn test_flood_entries_expire_on_the_clock_without_followup_request() {
        let _serial = CF_ENV_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            std::env::set_var("DANA_NONCE_TTL_SECS", "1");
            std::env::set_var("DANA_NONCE_JANITOR_INTERVAL_SECS", "1");
        }
        let srv = spawn_flood_server(flood_state()).await;
        let domain = "danawallet.app".to_string();

        let mut issued = 0_u16;
        for i in 0..3 {
            let (sp_str, _sk) = fresh_testnet_identity();
            let body = flood_prepare_body(
                &format!("exp-{}", i),
                &domain,
                &format!("exp-u{}", i),
                &sp_str,
            );
            let (code, _resp) = post_prepare(srv.addr, &body).await;
            assert_eq!(code, 200, "normal prepares below every budget must pass");
            issued += 1;
        }
        assert_eq!(issued, 3);
        assert_eq!(srv.state.nonce_store.read().await.len(), 3);

        // NO further HTTP request is sent: only the janitor can now clear the
        // store. Base only reclaimed inline at the next prepare/register, so a
        // quiet server kept dead entries until traffic returned (pre-fix RED).
        let drained = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if srv.state.nonce_store.read().await.len() == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        assert!(
            drained.is_ok(),
            "idle nonce store never drained without a follow-up request — expiry must \
             run on the janitor timer, not only inline at request entry (pre-fix RED state)"
        );

        drop(srv);
        unsafe {
            std::env::remove_var("DANA_NONCE_TTL_SECS");
            std::env::remove_var("DANA_NONCE_JANITOR_INTERVAL_SECS");
        }
    }

    #[tokio::test]
    async fn test_flood_legit_nonce_survives_the_pressure_and_lookup_stays_up() {
        let _serial = CF_ENV_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let stub = spawn_stalling_cloudflare_stub();
        unsafe {
            std::env::set_var("CLOUDFLARE_API_BASE_URL", format!("http://{}", stub));
            std::env::set_var("DANA_NONCE_STORE_MAX_ENTRIES", "12");
            std::env::set_var("DANA_NONCES_PER_IP_MAX_PENDING", "10000");
            std::env::set_var("DANA_NONCES_PER_SP_MAX_PENDING", "10000");
        }
        let srv = spawn_flood_server(flood_state()).await;
        let domain = "danawallet.app".to_string();

        // (a) The client's legitimate prepare (first below every bound) issues a nonce.
        let (sp_str, sk) = fresh_testnet_identity();
        let user = "flood-live-u";
        let body = flood_prepare_body("live", &domain, user, &sp_str);
        let (code, resp) = post_prepare(srv.addr, &body).await;
        assert_eq!(code, 200, "legitimate prepare must be admitted");
        let nonce = resp["nonce"]
            .as_str()
            .expect("legitimate prepare must return a nonce")
            .to_string();

        // (b) Flood past the cap with unrelated identities from the same source.
        let mut junk_429 = 0_u16;
        for i in 0..20 {
            let (junk_sp, _junk_sk) = fresh_testnet_identity();
            let junk_body =
                flood_prepare_body(&format!("junk-{}", i), &domain, &format!("junk-u{}", i), &junk_sp);
            let (junk_code, _junk_resp) = post_prepare(srv.addr, &junk_body).await;
            assert!(junk_code < 500, "junk prepare faulted {}", junk_code);
            if junk_code == 429 {
                junk_429 += 1;
            }
        }
        assert!(junk_429 > 0, "the saturated store must start refusing with 429");
        assert_eq!(
            srv.state.nonce_store.read().await.len(),
            12,
            "live entry + junk must stop at the cap"
        );

        // (c) /lookup answers from the same process while the store is jammed.
        let (probe_sp, _probe_sk) = fresh_testnet_identity();
        let probe = tokio::time::timeout(Duration::from_secs(10), get_lookup(srv.addr, &probe_sp)).await;
        assert!(
            matches!(probe, Ok(code) if code < 500),
            "/lookup must stay live while the nonce store is at capacity, got {:?}",
            probe
        );

        // (d) The legitimately issued nonce still validates for its registration
        // despite the flood — junk never evicted it and the cap never blocks a
        // nonce already in the user's hand.
        let sig = sign_registration(&sk, &nonce, user, &domain);
        let req = make_register_request("live-reg", &domain, user, &sp_str, &sig, &nonce);
        let state = srv.state.clone();
        let drive = tokio::time::timeout(Duration::from_secs(60), handle_register(State(state), Json(req))).await;
        let (reg_status, reg_body) = match drive {
            Err(_elapsed) => panic!(
                "live /register hung under flood pressure (pre-fix RED state): {:?}",
                _elapsed
            ),
            Ok(pair) => pair,
        };
        assert_eq!(
            reg_status,
            StatusCode::OK,
            "flood pressure must not invalidate a legitimately issued nonce: {}",
            reg_body.0.message
        );
        assert_eq!(
            reg_body.0.dns_record_id.as_deref().map(|s| &s[..]),
            Some("rec-stub-ok"),
            "live registration must complete through the bounded stub"
        );

        // (e) Single-use still holds after the flood: replay is refused.
        let replay_sig = sign_registration(&sk, &nonce, user, &domain);
        let replay = make_register_request("live-reg-2", &domain, user, &sp_str, &replay_sig, &nonce);
        let (replay_status, _replay_body) = handle_register(State(srv.state.clone()), Json(replay)).await;
        assert_eq!(
            replay_status,
            StatusCode::BAD_REQUEST,
            "a flooded store must not revive a consumed nonce"
        );

        drop(srv);
        unsafe {
            std::env::remove_var("CLOUDFLARE_API_BASE_URL");
            std::env::remove_var("DANA_NONCE_STORE_MAX_ENTRIES");
            std::env::remove_var("DANA_NONCES_PER_IP_MAX_PENDING");
            std::env::remove_var("DANA_NONCES_PER_SP_MAX_PENDING");
        }
    }

}
