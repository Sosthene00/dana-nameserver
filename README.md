# Dana Name Server

A Rust-based name server for Bitcoin payment addresses that automatically creates DNS TXT records for Silent Payment (SP) addresses through Cloudflare's API.

## Overview

Dana Name Server provides a REST API that allows users to register Bitcoin Silent Payment addresses by creating DNS TXT records in the format `{username}.user._bitcoin-payment.{domain}`. This enables users to receive Bitcoin payments using human-readable identifiers instead of complex addresses.

## Features

- **DNS TXT Record Management**: Automatically creates and manages DNS TXT records via Cloudflare API
- **Silent Payment Support**: Validates and processes Bitcoin Silent Payment addresses
- **Input Validation**: Comprehensive validation for usernames and domains
- **Duplicate Prevention**: Checks for existing records before creating new ones
- **RESTful API**: Simple HTTP API for integration
- **Challenge-Response Authentication**: `/register` requires a single-use nonce from `/v1/challenge` plus a Schnorr signature proving SP address ownership. The handshake speaks spec v1: the challenge message carries a `dana-register:v1` prefix and binds every mutable field of the record (including the SP address), `/register` answers with machine-readable error codes, and `GET /v1/info` advertises the `challenge-auth:v1` capability
- **Comprehensive Testing**: Unit tests for all validation functions and DNS operations

## API Endpoints

### GET `/v1/info`

Returns the served domain, the SP network, and the machine-readable capability list (spec v1):

```json
{
    "domain": "example.com",
    "network": "mainnet",
    "capabilities": ["challenge-auth:v1"]
}
```

### POST `/v1/challenge`

Issues the single-use nonce used by the challenge-response handshake that authenticates `POST /v1/register`. This endpoint is public; it proves nothing and creates no records — it only returns the exact message to sign and the nonce bound to it.

**Request Body:**
```json
{
    "id": "req-1",
    "domain": "example.com",
    "user_name": "alice",
    "sp_address": "sp1qq0cygnetgn3rz2kla5cp05nj5uetlsrzez0l4p8g7wehf7ldr93lcqadw65upymwzvp5ed38l8ur2rznd6934xh95msevwrdwtrpk372hyz4vr6g"
}
```

**Response:**
```json
{
    "id": "req-1",
    "message": "dana-register:v1:…",
    "nonce": "9f2c…",
    "network_key": "…",
    "expires_at": 0
}
```

**Notes:**
- `message` is the exact string the wallet must sign. It is built by `challenge_message()` in `src/main.rs` — the single source of truth — as: `dana-register:v1:{network_key}:{nonce}:{user_name}:{domain}:{sp_address}` (spec v1: the signature binds every mutable field of the record, including the SP address being registered)
- `expires_at` is the Unix timestamp (seconds) at which the nonce expires: issuance time plus `NONCE_TTL_SECS` (300 s = 5 minutes).
- Nonces are single-use: they are consumed only after `/register` verifies the signature; a failed signature verification does not burn the nonce, so a corrected signature may be retried until `expires_at`.
- Rate limits: at most `MAX_NONCES_PER_PEER` outstanding nonces per peer, `MAX_PENDING_NONCES` server-wide, and `MAX_TRACKED_PEERS` tracked peers — over-cap requests receive `429 Too Many Requests`.

### POST `/v1/register`

Registers a Bitcoin payment address by creating a DNS TXT record. Registration requires challenge-response authentication: the client must first call `POST /v1/challenge` and then present the returned `nonce` together with a Schnorr `signature` over the exact `message` string:

`dana-register:v1:{network_key}:{nonce}:{user_name}:{domain}:{sp_address}`

signed with the spend private key that derives `sp_address` (the message is SHA-256 hashed before verification; the signature is 64 bytes, hex-encoded).

**Request Body:**
```json
{
    "id": "req-2",
    "domain": "example.com",
    "user_name": "alice",
    "sp_address": "sp1qq0cygnetgn3rz2kla5cp05nj5uetlsrzez0l4p8g7wehf7ldr93lcqadw65upymwzvp5ed38l8ur2rznd6934xh95msevwrdwtrpk372hyz4vr6g",
    "nonce": "9f2c…",
    "signature": "e5c1…"
}
```

`nonce` and `signature` are required: a request without them is rejected with `401 Unauthorized` (`message`: `nonce_unknown` or `signature_invalid`). A `401` is also returned when the nonce is unknown (`nonce_unknown`), expired (`nonce_expired`), or bound to different `user_name`/`sp_address`/`domain` values (`nonce_mismatch`). Re-request `/v1/challenge` to obtain a fresh nonce.

**Machine-readable error codes (spec v1, section 6):** every error answer from `/register` carries exactly one code in `message`: `nonce_expired`, `nonce_mismatch`, `nonce_unknown`, `signature_invalid` (all `401`), `username_invalid` (`400`, non-canonical label), `username_taken` (`409`, name already registered by a different owner), `rate_limited` (`429`, per-peer register-attempt cap), and `unknown` (`500`, internal/DNS/Cloudflare failures). Expiry is checked before the nonce is burned, and a pure signature-verification failure keeps the nonce valid, so a corrected signature may be retried until `expires_at`.

**Response:**
```json
{
    "id": "req-2",
    "message": "Payment instructions processed successfully",
    "dana_address": "alice.user._bitcoin-payment.example.com",
    "sp_address": "sp1qq0cygnetgn3rz2kla5cp05nj5uetlsrzez0l4p8g7wehf7ldr93lcqadw65upymwzvp5ed38l8ur2rznd6934xh95msevwrdwtrpk372hyz4vr6g",
    "dns_record_id": "abc123def456"
}
```

## Prerequisites

- Rust 1.70+ (2024 edition)
- Cloudflare account with API access
- Domain managed by Cloudflare

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd dana_nameserver
```

2. Create a `.env` file with your Cloudflare credentials:
```bash
CLOUDFLARE_ZONE_ID=your_zone_id_here
CLOUDFLARE_API_TOKEN=your_api_token_here
```

3. Build and run:
```bash
cargo run
```

The server will start on `http://127.0.0.1:8080`.

## Configuration

### Environment Variables

- `CLOUDFLARE_ZONE_ID`: Your Cloudflare zone ID for the domain
- `CLOUDFLARE_API_TOKEN`: Your Cloudflare API token with DNS edit permissions

### Cloudflare Setup

1. Get your Zone ID from the Cloudflare dashboard
2. Create an API token with the following permissions:
   - Zone:Zone:Read
   - Zone:DNS:Edit
3. Set the zone scope to the specific domain you want to manage

## Usage Examples

### Register a Payment Address

```bash
# 1) Obtain a challenge nonce and the exact message to sign
curl -X POST http://127.0.0.1:8080/v1/challenge \
  -H "Content-Type: application/json" \
  -d '{
    "id": "req-1",
    "user_name": "alice",
    "domain": "example.com",
    "sp_address": "sp1qq0cygnetgn3rz2kla5cp05nj5uetlsrzez0l4p8g7wehf7ldr93lcqadw65upymwzvp5ed38l8ur2rznd6934xh95msevwrdwtrpk372hyz4vr6g"
  }'

# 2) Sign the returned `message` (dana-register:v1:{network_key}:{nonce}:{user_name}:{domain}:{sp_address}) with the spend private key,
#    then register — nonce and signature are both required (401 without them).
curl -X POST http://127.0.0.1:8080/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "id": "req-2",
    "user_name": "alice",
    "domain": "example.com",
    "sp_address": "sp1qq0cygnetgn3rz2kla5cp05nj5uetlsrzez0l4p8g7wehf7ldr93lcqadw65upymwzvp5ed38l8ur2rznd6934xh95msevwrdwtrpk372hyz4vr6g",
    "nonce": "<nonce from /v1/challenge>",
    "signature": "<64-byte Schnorr signature over message, hex-encoded>"
  }'
```

### DNS Record Format

The service creates TXT records with the following format:
- **Record Name**: `{username}.user._bitcoin-payment.{domain}`
- **Record Type**: TXT
- **TTL**: 3600 seconds (1 hour)
- **Content**: `bitcoin:?sp={sp_address}` (uses the provided Silent Payment address)

## Validation Rules

### Username Validation
The `user_name` must be a **canonical** RFC 1035 DNS label (validated by `validate_dns_name`):
- Lowercase ASCII alphanumeric characters and hyphens only (`[a-z0-9-]`)
- 1 to 63 characters long
- Cannot start or end with a hyphen
- No consecutive hyphens
- Uppercase is **rejected**, not silently lowercased — submit the canonical lowercase form (DNS is case-insensitive, but the server keys nonces, registration maps and per-name locks by label, so one rejected case variant can never fork a second label)
### Domain Validation
- ASCII characters only
- Must include a valid TLD (at least 2 characters)
- Each part can contain letters, numbers, and hyphens
- Cannot start or end with hyphen
- No consecutive hyphens
- Converted to lowercase

## Testing

Run the test suite:

```bash
cargo test
```

The tests include:
- DNS record existence checking
- Username validation
- Domain validation
- Error handling scenarios

## Error Handling

The API returns appropriate HTTP status codes:
- `200 OK`: Successful registration
- `400 Bad Request`: Invalid input (username, domain, or SP address)
- `409 Conflict`: TXT record already exists
- `500 Internal Server Error`: Server or Cloudflare API errors

## Dependencies

- **axum**: Web framework
- **tokio**: Async runtime
- **hickory-client**: DNS client for record checking
- **reqwest**: HTTP client for Cloudflare API
- **serde**: Serialization/deserialization
- **silentpayments**: Bitcoin Silent Payment address validation
- **dotenv**: Environment variable loading
- **log/env_logger**: Logging

## Security Considerations

- API tokens should be kept secure and not committed to version control
- Consider implementing rate limiting for production use
- Validate all inputs thoroughly (already implemented)
- Monitor Cloudflare API usage and costs

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]
