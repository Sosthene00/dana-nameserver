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
- **Comprehensive Testing**: Unit tests for all validation functions and DNS operations

## API Endpoints

### POST `/api/register`

Registers a new Bitcoin payment address by creating a DNS TXT record.

**Request Body:**
```json
{
    "user_name": "alice",
    "domain": "example.com",
    "sp_address": "sp1qq0cygnetgn3rz2kla5cp05nj5uetlsrzez0l4p8g7wehf7ldr93lcqadw65upymwzvp5ed38l8ur2rznd6934xh95msevwrdwtrpk372hyz4vr6g"
}
```

**Response:**
```json
{
    "message": "Payment instructions processed successfully",
    "received": {
        "user_name": "alice",
        "domain": "example.com",
        "sp_address": "sp1qq0cygnetgn3rz2kla5cp05nj5uetlsrzez0l4p8g7wehf7ldr93lcqadw65upymwzvp5ed38l8ur2rznd6934xh95msevwrdwtrpk372hyz4vr6g"
    },
    "dns_record_id": "abc123def456",
    "record_name": "alice.user._bitcoin-payment.example.com"
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
curl -X POST http://127.0.0.1:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "user_name": "alice",
    "domain": "example.com",
    "sp_address": "sp1qq0cygnetgn3rz2kla5cp05nj5uetlsrzez0l4p8g7wehf7ldr93lcqadw65upymwzvp5ed38l8ur2rznd6934xh95msevwrdwtrpk372hyz4vr6g"
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
- ASCII characters only
- Letters, numbers, and hyphens allowed
- Cannot start or end with hyphen
- No consecutive hyphens
- Converted to lowercase

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
