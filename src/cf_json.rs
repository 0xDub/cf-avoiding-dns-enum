use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct CloudFlareError {
    pub code: u16,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CloudFlareMessage {
    pub code: u16,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CloudFlareIPsResult {
    pub etag: String,
    pub ipv4_cidrs: Vec<String>,
    pub ipv6_cidrs: Vec<String>,
    pub jdcloud_cidrs: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CloudFlareIPs {
    pub errors: Vec<CloudFlareError>,
    pub messages: Vec<CloudFlareMessage>,
    pub success: bool,
    pub result: CloudFlareIPsResult,
}