# AGENTS.md — Dana Name Server

## 1. Project Overview

- **Name:** Dana Name Server
- **Type:** Rust service (HTTP API) for Bitcoin Silent Payment address name resolution
- **Primary users:** Dana Wallet (and any service that needs to register/lookup Dana addresses)
- **Core functions:**
  - Accept Silent Payment (SP) address registrations via REST API
  - Create corresponding DNS TXT records on Cloudflare (`{user}.user._bitcoin-payment.{domain}`)
  - Lookup Dana addresses from SP addresses (in-memory cache + DNS)
  - Prefix search across registered Dana addresses
- **Current stage:** Actively maintained

Agent: Optimize for correctness (crypto/biitcoin code must be exact), small binary size, and reliability. The service has no persistence — maps are rebuilt from Cloudflare on every restart.

## 2. Tech Stack and Environment

- **Language:** Rust 2024 edition
- **Framework:** axum 0.8.5 (HTTP/1, JSON, query params)
- **Runtime:** tokio (macros + rt-multi-thread)
- **HTTP client:** reqwest 0.11 (native-tls-vendored)
- **DNS:** hickory-client (via `bitcoin-payment-instructions`)
- **Bitcoin:** `silentpayments` 0.4.1, `bitcoin-payment-instructions` (forked at `add_silent_payments` branch from `https://github.com/Sosthene00/bitcoin-payment-instructions.git`)
- **Error handling:** anyhow
- **Serialization:** serde + serde_json
- **Config:** dotenv (`.env` file)
- **Logging:** env_logger 0.10 (default level: `info`)
- **Release profile:** `opt-level = "z"`, LTO fat, single codegen unit, panic=abort, strip=true

Agent: No `justfile` or Makefile — use `cargo` directly. No project-level test framework beyond `cargo test`.

## 3. Repository Structure

```text
dana-nameserver/
├── src/
│   ├── main.rs            # All logic: handlers, DNS, Cloudflare, maps, main()
│   └── api_structs.rs     # Request/response structs (Register, Lookup, PrefixSearch)
├── Cargo.toml             # Dependencies and release profile
├── Cargo.lock             # Locked dependencies
├── .env.example           # (add if exists — template env vars)
└── AGENTS.md              # This file
```

Agent: `main.rs` is a ~930-line monolith. It contains route handlers, DNS functions, Cloudflare API calls, map management, and `main()`. Do not refactor into separate files without explicit approval.

## 4. Commands That Actually Work


### Toolchain (audit gate — non-negotiable)

This workspace requires Rust >= 1.84 (`resolver = "3"`). The host carries two
toolchains: the rustup-managed `stable` (current, pinned by `rust-toolchain.toml`
at the repo root) and the distro `rustc` 1.75 in `/usr/bin`, which is TOO OLD.
Non-interactive `ssh` shells do NOT source `~/.cargo/env`, so bare `cargo`/`rustc`
resolve to 1.75 and the verification gate fails. ALWAYS invoke via the rustup shim:

```bash
~/.cargo/bin/cargo check --workspace
~/.cargo/bin/cargo test --workspace
~/.cargo/bin/cargo clippy --workspace
```

`rust-toolchain.toml` forces the pinned stable toolchain for these invocations.
Never rely on bare `cargo` in remote/cron shells.
### Build & Run
```bash
cargo build --release          # Release build (strip, LTO, opt-size)
cargo run                      # Dev build, reads .env
RUST_LOG=debug cargo run       # Debug-level logging
```

### Testing
```bash
cargo test                     # All tests (DNS lookup tests against real records)
```

### Environment Setup
```bash
cp .env.example .env           # (create manually if no example exists)
# Set CLOUDFLARE_ZONE_ID, CLOUDFLARE_API_TOKEN, DOMAIN_NAME, SERVER_HOST, SERVER_PORT, NETWORK
```

Agent: **Run `cargo test`** after non-trivial changes and include the result.

## 5. Coding Standards

- **File organization:** Everything lives in `main.rs` and `api_structs.rs`. Do not split into more modules unless explicitly requested.
- **Naming:** Rust conventions — `snake_case` for functions/vars, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- **Error handling:** Use `anyhow::Result` for internal errors. Return `(StatusCode, AxumJson<...>)` for API responses. Always log errors at `error!` level.
- **Concurrency:** `tokio::sync::RwLock` protects the SP↔Dana maps. Use `read().await` for lookups, `write().await` for mutations. Always `drop()` write locks before returning.
- **Logging:** Use `log::{debug, info, warn, error}`. Log at the appropriate level — `debug` for trace-level details, `info` for lifecycle/events, `warn` for recoverable issues, `error` for failures.
- **API structure:** All endpoints are under `/v1/` prefix. Each request/response includes an `id` field (correlation ID).

### Route Handlers
- `GET /v1/info` — Server info (domain, network)
- `POST /v1/register/prepare` — Initiate registration, returns a challenge nonce
- `POST /v1/register` — Register with signature proof (requires /register/prepare first)
- `GET /v1/lookup?sp_address=...` — Lookup Dana address(es) for an SP address
- `GET /v1/search?prefix=...` — Prefix search across Dana addresses (min 3 chars, max 25 results)

### Authentication Flow

Registration uses challenge-response authentication to prove ownership of the SP address:

1. **Prepare** — `POST /v1/register/prepare` with `{id, domain, user_name, sp_address}`
   → Server validates inputs and returns `{nonce}` (valid for 5 minutes)
2. **Sign** — Client signs `"dana-register:{network_key}:{nonce}:{user_name}:{domain}"` (network_key = `sp`/`tsp` per the SP address network) with the spend private key
   corresponding to the SP address (Schnorr signature, 64 bytes hex)
3. **Register** — `POST /v1/register` with `{id, domain, user_name, sp_address, signature, nonce}`
   → Server verifies nonce (exists, matches, not expired), then verifies signature, then creates DNS record
4. **Single-use** — The nonce is consumed as soon as `/register` claims it. On any failure the client must call `/register/prepare` again for a new nonce.

**DNS name constraints**: alphanumeric + hyphens only, 1-63 characters.

## 6. Testing Conventions

- **Location:** Inline tests in `main.rs` (`#[cfg(test)] mod tests`)
- **Tests:** 4 integration tests that hit real DNS/Cloudflare records
  - `test_check_txt_record_exists_with_address` — verify known record returns SP address
  - `test_check_txt_record_does_not_exist` — verify missing record returns `None`
  - `test_check_txt_record_exists_with_no_address` — verify record with no SP param
  - `test_check_no_txt_record` — verify completely unknown record returns error
- **Principles:** Tests use real DNS lookups (not mocks). They depend on `danawallet.app` and `mattcorallo.com` being live.
- **Adding tests:** Co-locate new tests in the same `#[cfg(test)]` module. Keep them self-contained.

Agent: Add or update tests whenever you change behavior. Tests must pass before proposing a change.

## 7. Workflows and Agent Behavior

### 7.1 Default Workflow
1. Restate task → 2. Locate patterns in `main.rs`/`api_structs.rs` → 3. Plan (5-10 bullets) → 4. Implement iteratively → 5. Validate (`cargo test`) → 6. Summarize

### 7.2 Decision-Making Thresholds

**Autonomous (no confirmation needed):**
- Bug fixes in existing functions
- Adding input validation or error handling
- Adding logging/debug statements
- Updating variable names for clarity
- Fixing typos in docs or comments
- Adding tests for existing behavior
- Updating dependency versions (patch-level)

**Needs confirmation (ask first):**
- Changing function signatures or public API
- Adding/removing route handlers or endpoints
- Modifying the Cloudflare API interaction
- Changing DNS record format or validation rules
- Introducing new third-party dependencies
- Adding persistent storage (DB, file-based cache)
- Restructuring `main.rs` into separate modules
- Adding authentication or rate limiting
- Changes to `bitcoin-payment-instructions` fork
- Modifying the release profile or build config

### 7.3 Output Format
In every response with code changes: summary, file list, commands + results, tests.

## 8. Universal Baseline Rules

### Must-Do

1. **Write and run tests for all new code** — Include unit, integration, or functional tests as appropriate
2. **Run linters and formatters before committing** — Ensure code meets project style standards
3. **Make atomic, descriptive commits for human review** — One logical change per commit with clear commit messages
4. **Handle errors gracefully** — Use proper exception handling, logging, and user-friendly error messages
5. **Pin dependency versions** — Specify exact versions in lock files to ensure reproducible builds
6. **Validate all external inputs** — Sanitize user input, API responses, and file contents
7. **Update documentation when changing APIs or complex logic** — Keep README, API docs, and comments in sync with code

### Never-Do

1. **Never commit secrets, credentials, or hardcoded configuration** — Use environment variables, config files, or secret management
2. **Never ignore test failures** — Fix broken tests immediately or remove obsolete ones
3. **Never merge without code review** — All changes should be reviewed by another developer
4. **Never use deprecated APIs without migration plan** — Address deprecation warnings promptly
5. **Never commit commented-out code** — Remove dead code instead of commenting it out

## 9. Project-Specific Rules

### Always Do
- Run `cargo test` after changes to `main.rs` and include the output
- Respect the monolithic `main.rs` structure — do not split without approval
- Keep all API responses consistent: include `id`, `message`, and typed result fields
- Use `anyhow::Result` for internal errors; return proper HTTP status codes for user-facing errors
- Log DNS and Cloudflare API calls at `debug` level for troubleshooting
- Use `env_logger::Env` for log level control via `RUST_LOG`

### Never Do
- Never hardcode Cloudflare credentials or API tokens
- Never change the DNS record format (`.user._bitcoin-payment.{domain}`) without explicit approval — Dana Wallet depends on it
- Never modify the `bitcoin-payment-instructions` fork's API without understanding the impact
- Never add network calls to untrusted external services without confirming endpoint, auth, and timeouts
- Never panic in route handlers — use proper error responses
- Never change the release profile (size optimization is intentional)
- Never introduce new dependencies without checking the `silentpayments` and `bitcoin-payment-instructions` crates first — they are the core crypto

## 10. Known Tech Debt and Gotchas

- **Monolithic main.rs** — ~930 lines, all route handlers and business logic in one file. Refactoring is wanted but should not happen without explicit direction.
- **No persistent storage** — The SP↔Dana maps are rebuilt from Cloudflare on every startup via `list_bitcoin_records()`. Server restarts don't lose data (DNS records persist), but the in-memory cache is cold.
- **Custom fork dependency** — `bitcoin-payment-instructions` is from a forked branch (`add_silent_payments`). Breaking changes upstream could affect this.
- **DNS lookup is the only duplicate check** — Registration checks DNS for existing records, not the in-memory map. Race conditions between two concurrent registrations are possible.
- **Read endpoints are unauthenticated** — `/lookup`, `/search` and `/info` are public by design. `/register` requires challenge-response signature proof of SP address ownership (see Authentication Flow in section 5).
- **Prefix search is O(n)** — Iterates all keys in `dana_to_sp` map. Fine for small registries, but should be flagged if scale becomes an issue.

## 11. Additional Context Files

- `README.md` — project intro, API docs, setup instructions
- `Cargo.toml` — full dependency list and release profile
- `src/api_structs.rs` — all request/response type definitions
- `src/main.rs` — complete source (all logic in one file)
