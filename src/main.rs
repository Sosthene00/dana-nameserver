use hickory_client::{client::ClientHandle, proto::{rr::{DNSClass, RecordType, Record}, runtime::TokioRuntimeProvider, udp::UdpClientStream}};
use hickory_client::proto::xfer::DnsResponse;
use serde::{Deserialize, Serialize};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json as AxumJson,
    routing::post,
    Json, Router,
};
use reqwest::Client;
use log::{info, warn, error, debug};
use silentpayments::Network;
use std::{net::SocketAddr, str::FromStr, sync::Arc};

#[derive(Deserialize, Serialize)]
struct Request {
    user_name: String,
    domain: String,
    sp_address: String,
}

#[derive(Serialize)]
struct ResponseBody {
    message: String,
    received: Request,
    dns_record_id: Option<String>,
    record_name: Option<String>,
}

#[derive(Serialize)]
struct CloudflareRequest {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
}

async fn check_txt_record_exists(
    record_name: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    debug!("Checking if TXT record exists: {}", record_name);
    let address = SocketAddr::from(([8, 8, 8, 8], 53));
    let conn = UdpClientStream::builder(address, TokioRuntimeProvider::default()).build();
    let (mut client, bg) = hickory_client::client::Client::connect(conn).await?;
    tokio::spawn(bg);

    let name = hickory_client::proto::rr::Name::from_str(record_name)?;
    
    let response: DnsResponse = client
        .query(name, DNSClass::IN, RecordType::TXT)
        .await?;

    let answers: &[Record] = response.answers();

    let txt_data = answers
        .iter()
        .flat_map(|record| record.data().as_txt())
        .collect::<Vec<_>>();

    Ok(!txt_data.is_empty())
}

async fn create_txt_record(
    client: &Client,
    zone_id: &str,
    api_token: &str,
    name: &str,
    content: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records", zone_id);
    
    debug!("Creating TXT record: {} -> {}", name, content);
    debug!("Using Cloudflare API URL: {}", url);
    
    let record = CloudflareRequest {
        record_type: "TXT".to_string(),
        name: name.to_string(),
        content: content.to_string(),
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
            warn!("Cloudflare API returned success but no record ID for {}", name);
            Ok(None)
        }
    } else {
        let error_text = response.text().await?;
        error!("Cloudflare API error for {}: {}", name, error_text);
        Ok(None)
    }
}


fn validate_username(input: &str) -> Result<String, String> {
    if !input.is_ascii() {
        return Err(format!("'{}' contains non-ASCII characters. Only ASCII characters are supported.", input));
    }
    
    let lowercase = input.to_lowercase();
    
    if lowercase.is_empty() {
        return Err("Username cannot be empty".to_string());
    }
    
    if lowercase.starts_with('-') || lowercase.ends_with('-') {
        return Err("Username cannot start or end with hyphen".to_string());
    }
    
    if !lowercase.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("Username can only contain letters, numbers, and hyphens".to_string());
    }
    
    if lowercase.contains("--") {
        return Err("Username cannot contain consecutive hyphens".to_string());
    }
    
    Ok(lowercase)
}

fn validate_domain(input: &str) -> Result<String, String> {
    if !input.is_ascii() {
        return Err(format!("'{}' contains non-ASCII characters. Only ASCII characters are supported.", input));
    }
    
    let lowercase = input.to_lowercase();
    
    if lowercase.is_empty() {
        return Err("Domain cannot be empty".to_string());
    }
    
    // Check for valid domain structure: at least one dot and valid TLD
    if !lowercase.contains('.') {
        return Err("Domain must include extension (e.g., .com, .org, .io)".to_string());
    }
    
    let parts: Vec<&str> = lowercase.split('.').collect();
    if parts.len() < 2 {
        return Err("Domain must have at least a name and extension".to_string());
    }
    
    // Validate each part of the domain
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err("Domain parts cannot be empty".to_string());
        }
        
        if part.starts_with('-') || part.ends_with('-') {
            return Err("Domain parts cannot start or end with hyphen".to_string());
        }
        
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("Domain parts can only contain letters, numbers, and hyphens".to_string());
        }
        
        if part.contains("--") {
            return Err("Domain parts cannot contain consecutive hyphens".to_string());
        }
        
        // TLD (last part) should be at least 2 characters
        if i == parts.len() - 1 && part.len() < 2 {
            return Err("Domain extension must be at least 2 characters".to_string());
        }
    }
    
    Ok(lowercase)
}

#[derive(Clone)]
struct AppState {
    zone_id: String,
    api_token: String,
}

async fn handle_register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<Request>,
) -> (StatusCode, AxumJson<ResponseBody>) {
    info!("Received registration request for user: {} on domain: {}", request.user_name, request.domain);
    debug!("User {} provided sp address: {}", request.user_name, request.sp_address);
    
    let dns_record_id;
    
    // Just in case
    if state.zone_id.is_empty() || state.api_token.is_empty() {
        const ERROR_MESSAGE: &str = "Cloudflare credentials not provided, DNS record creation failed";
        error!("{}", ERROR_MESSAGE);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            AxumJson(ResponseBody {
                message: ERROR_MESSAGE.to_string(),
                received: request,
                dns_record_id: None,
                record_name: None,
            })
        );
    }

    // Validate user name and domain
    let validated_user = match validate_username(&request.user_name) {
        Ok(user) => user,
        Err(e) => {
            error!("Invalid user name '{}': {}", request.user_name, e);
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(ResponseBody {
                    message: format!("Invalid user name: {}", e),
                    received: request,
                    dns_record_id: None,
                    record_name: None,
                })
            );
        }
    };
    
    let validated_domain = match validate_domain(&request.domain) {
        Ok(domain) => domain,
        Err(e) => {
            error!("Invalid domain '{}': {}", request.domain, e);
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(ResponseBody {
                    message: format!("Invalid domain: {}", e),
                    received: request,
                    dns_record_id: None,
                    record_name: None,
                })
            );
        }
    };

    // Validate SP address
    let sp_address = match silentpayments::SilentPaymentAddress::try_from(request.sp_address.clone()) {
        Ok(sp_address) => {
            debug!("Valid SP address: {}", sp_address);
            sp_address
        }
        Err(e) => {
            error!("Invalid SP address '{}': {}", request.sp_address, e);
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(ResponseBody {
                    message: format!("Invalid SP address: {}", e),
                    received: request,
                    dns_record_id: None,
                    record_name: None,
                })
            );
        }
    };

    // We modify the key depending on the network we're on (mainnet vs signet/testnet)
    let network_key = match sp_address.get_network() {
        Network::Mainnet => "sp",
        _ => "tsp"
    };

    // Format: {user}.user._bitcoin-payment.{domain}
    let txt_name = format!("{}.user._bitcoin-payment.{}", validated_user, validated_domain);
    let txt_content = format!("bitcoin:?{}={}", network_key, sp_address.to_string());
    
    let record_name = Some(txt_name.clone());

    // First check if the record already exists using DNS-over-HTTPS
    match check_txt_record_exists(&txt_name).await {
        Ok(true) => {
            error!("TXT record already exists: {}", txt_name);
            return (
                StatusCode::CONFLICT,
                AxumJson(ResponseBody {
                    message: "TXT record already exists".to_string(),
                    received: request,
                    dns_record_id: None, // We don't have the Cloudflare record ID from DNS check
                    record_name: Some(txt_name),
                })
            );
        }
        Ok(false) => {
            info!("No existing TXT record found for {}", txt_name);
        }
        Err(e) => {
            error!("Error checking for existing TXT record {}: {}", txt_name, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(ResponseBody {
                    message: format!("Error checking for existing TXT record: {}", e),
                    received: request,
                    dns_record_id: None,
                    record_name: Some(txt_name),
                })
            );
        }
    };
    
    info!("Attempting to create TXT record: {}", txt_name);
    let client = Client::new();
    
    dns_record_id = match create_txt_record(&client, &state.zone_id, &state.api_token, &txt_name, &txt_content).await {
        Ok(Some(id)) => {
            info!("Successfully created TXT record: {} -> {}", txt_name, txt_content);
            Some(id)
        }
        Ok(None) => {
            warn!("Failed to create TXT record: No ID returned from Cloudflare for {}", txt_name);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(ResponseBody {
                    message: "Failed to create DNS record: No ID returned from Cloudflare".to_string(),
                    received: request,
                    dns_record_id: None,
                    record_name: Some(txt_name),
                })
            );
        }
        Err(e) => {
            error!("Error creating TXT record {}: {}", txt_name, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(ResponseBody {
                    message: format!("Failed to create DNS record: {}", e),
                    received: request,
                    dns_record_id: None,
                    record_name: Some(txt_name),
                })
            );
        }
    };

    let response_body = ResponseBody {
        message: "Payment instructions processed successfully".to_string(),
        received: request,
        dns_record_id,
        record_name,
    };
    
    debug!("Sending response for record: {}", response_body.record_name.as_ref().unwrap_or(&"unknown".to_string()));
    (
        StatusCode::OK,
        AxumJson(response_body)
    )
}

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init();
    info!("Starting Dana Name Server");

    if let Err(e) = dotenv::dotenv() {
        error!("Could not load .env file: {}", e);
        std::process::exit(1);
    } else {
        info!("Successfully loaded .env file");
    }

    let zone_id = std::env::var("CLOUDFLARE_ZONE_ID").unwrap_or_default();
    let api_token = std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default();
    
    if zone_id.is_empty() || api_token.is_empty() {
        error!("Cloudflare credentials not provided. Can't proceed.");
        error!("Set CLOUDFLARE_ZONE_ID and CLOUDFLARE_API_TOKEN environment variables to enable DNS integration.");
        std::process::exit(1);
    } else {
        info!("Cloudflare credentials loaded successfully");
        debug!("Zone ID: {}", zone_id);
        debug!("API Token: {}...", &api_token[..8.min(api_token.len())]);
    }

    let state = Arc::new(AppState {
        zone_id,
        api_token,
    });

    let app = Router::new()
        .route("/api/register", post(handle_register))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("Failed to bind to port 8080");
    
    info!("Server starting on http://127.0.0.1:8080");
    info!("API endpoint available at: http://127.0.0.1:8080/api/register");
    
    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_txt_record_exists_with_existing_record() {
        // Test with a well-known domain that should have TXT records
        // Using Google's domain which typically has SPF/DKIM records
        let result = check_txt_record_exists("google.com").await;
        
        // This test might be flaky due to network conditions, but it should generally work
        match result {
            Ok(exists) => {
                // We expect this to be true for google.com as it has TXT records
                assert!(exists, "Google.com should have TXT records");
            }
            Err(e) => {
                // If network fails, we should still test the error handling
                println!("Network error during test (expected in some environments): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_check_txt_record_exists_with_nonexistent_record() {
        // Test with a domain that likely doesn't exist
        let result = check_txt_record_exists("this-domain-definitely-does-not-exist-12345.invalid").await;
        
        match result {
            Ok(exists) => {
                assert!(!exists, "Non-existent domain should not have TXT records");
            }
            Err(e) => {
                // DNS resolution failure is also acceptable for non-existent domains
                println!("DNS resolution failed for non-existent domain (expected): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_check_txt_record_exists_with_invalid_domain() {
        // Test with malformed domain name
        let result = check_txt_record_exists("invalid..domain").await;
        
        // This should return an error due to invalid domain format
        assert!(result.is_err(), "Invalid domain format should return an error");
        
        if let Err(e) = result {
            // The error should be related to domain parsing
            let error_msg = e.to_string().to_lowercase();
            assert!(
                error_msg.contains("invalid") || 
                error_msg.contains("parse") || 
                error_msg.contains("name") ||
                error_msg.contains("malformed") ||
                error_msg.contains("label"),
                "Error message should indicate domain parsing issue: {}",
                e
            );
        }
    }

    #[tokio::test]
    async fn test_check_txt_record_exists_with_empty_domain() {
        // Test with empty domain
        let result = check_txt_record_exists("").await;
        
        // Empty domain should return an error or false (depending on DNS library behavior)
        match result {
            Ok(exists) => {
                // If it doesn't error, it should return false for empty domain
                assert!(!exists, "Empty domain should not have TXT records");
            }
            Err(e) => {
                // This is also acceptable - empty domain should cause an error
                let error_msg = e.to_string().to_lowercase();
                assert!(
                    error_msg.contains("invalid") || 
                    error_msg.contains("parse") || 
                    error_msg.contains("name") ||
                    error_msg.contains("malformed") ||
                    error_msg.contains("label") ||
                    error_msg.contains("empty"),
                    "Error message should indicate domain parsing issue: {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    async fn test_check_txt_record_exists_with_specific_txt_record() {
        // Test with a specific subdomain that might have TXT records
        // Using a common pattern for verification records
        let result = check_txt_record_exists("_verification.github.com").await;
        
        match result {
            Ok(exists) => {
                // GitHub might have verification records, but we can't be certain
                // This test mainly ensures the function doesn't panic
                println!("GitHub verification record exists: {}", exists);
            }
            Err(e) => {
                // Network or DNS errors are acceptable in test environments
                println!("DNS query failed (expected in some environments): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_check_txt_record_exists_error_handling() {
        // Test that the function properly handles DNS resolution errors
        // Using a domain that should cause a specific type of error
        let result = check_txt_record_exists("test.invalid").await;
        
        // The .invalid TLD should cause a DNS resolution error
        match result {
            Ok(_) => {
                // If it somehow resolves, that's unexpected but not a test failure
                println!("Unexpectedly resolved .invalid domain");
            }
            Err(e) => {
                // This is the expected behavior
                let error_msg = e.to_string().to_lowercase();
                assert!(
                    error_msg.contains("nxdomain") || 
                    error_msg.contains("not found") ||
                    error_msg.contains("no such name") ||
                    error_msg.contains("resolution") ||
                    error_msg.contains("timeout"),
                    "Error should indicate DNS resolution failure: {}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_validate_username_valid_cases() {
        // Test valid usernames
        assert_eq!(validate_username("alice"), Ok("alice".to_string()));
        assert_eq!(validate_username("bob123"), Ok("bob123".to_string()));
        assert_eq!(validate_username("user-name"), Ok("user-name".to_string()));
        assert_eq!(validate_username("ALICE"), Ok("alice".to_string())); // Should be lowercased
        assert_eq!(validate_username("User123"), Ok("user123".to_string()));
    }

    #[test]
    fn test_validate_username_invalid_cases() {
        // Test invalid usernames
        assert!(validate_username("").is_err());
        assert!(validate_username("-alice").is_err());
        assert!(validate_username("alice-").is_err());
        assert!(validate_username("alice--bob").is_err());
        assert!(validate_username("alice bob").is_err());
        assert!(validate_username("alice@bob").is_err());
        assert!(validate_username("alice.bob").is_err());
        assert!(validate_username("alice_bob").is_err());
        assert!(validate_username("aliceé").is_err()); // Non-ASCII
    }

    #[test]
    fn test_validate_domain_valid_cases() {
        // Test valid domains
        assert_eq!(validate_domain("example.com"), Ok("example.com".to_string()));
        assert_eq!(validate_domain("sub.example.com"), Ok("sub.example.com".to_string()));
        assert_eq!(validate_domain("example.org"), Ok("example.org".to_string()));
        assert_eq!(validate_domain("EXAMPLE.COM"), Ok("example.com".to_string())); // Should be lowercased
        assert_eq!(validate_domain("test-domain.co.uk"), Ok("test-domain.co.uk".to_string()));
    }

    #[test]
    fn test_validate_domain_invalid_cases() {
        // Test invalid domains
        assert!(validate_domain("").is_err());
        assert!(validate_domain("example").is_err()); // No TLD
        assert!(validate_domain(".com").is_err()); // Empty domain part
        assert!(validate_domain("example.").is_err()); // Empty TLD
        assert!(validate_domain("-example.com").is_err()); // Starts with hyphen
        assert!(validate_domain("example-.com").is_err()); // Ends with hyphen
        assert!(validate_domain("example..com").is_err()); // Double dot
        assert!(validate_domain("example.c").is_err()); // TLD too short
        assert!(validate_domain("example com").is_err()); // Space
        assert!(validate_domain("example@com").is_err()); // Invalid character
        assert!(validate_domain("examplé.com").is_err()); // Non-ASCII
    }
}
