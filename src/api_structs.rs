use serde::{Deserialize, Serialize};

// Register endpoint types
#[derive(Deserialize, Serialize)]
pub struct RegisterRequest {
    pub id: String,
    pub domain: String,
    pub user_name: Option<String>,
    pub sp_address: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: String,
    pub message: String,
    pub dana_address: Option<String>,
    pub sp_address: Option<String>,
    pub dns_record_id: Option<String>,
}

// Lookup endpoint types
#[derive(Deserialize)]
pub struct LookupRequest {
    pub sp_address: String,
    pub id: String,
}

#[derive(Serialize)]
pub struct LookupResponse {
    pub id: String,
    pub message: String,
    pub dana_address: Vec<String>,
    pub sp_address: Option<String>,
}

// Prefix search endpoint types
#[derive(Deserialize)]
pub struct PrefixSearchRequest {
    pub prefix: String,
    pub id: String,
}

#[derive(Serialize)]
pub struct PrefixSearchResponse {
    pub id: String,
    pub message: String,
    pub dana_address: Vec<String>,
    pub count: usize,
    pub total_count: usize,
}

#[derive(Serialize)]
pub struct CloudflareRequest {
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub ttl: u32,
}

#[derive(Debug, Deserialize)]
pub struct Record {
    #[allow(unused)]
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    // skip other fields
}

#[derive(Debug, Deserialize)]
pub struct ApiResponse {
    #[allow(unused)]
    pub success: bool,
    pub result: Vec<Record>,
    // skip result_info, errors, messages, ...
}

#[derive(Serialize)]
pub struct GetInfoResponse {
    pub domain: String,
    pub mainnet_only: bool,
}
