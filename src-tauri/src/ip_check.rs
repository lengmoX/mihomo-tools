use std::io::Read;
use std::time::Duration;
use crate::models::{CommandResult, IpCheckResult, IpInfoResponse, ListenerRule};
use crate::utils::{build_proxy_url, normalize_country_code, unix_timestamp_secs};

pub const MAX_IPINFO_RESPONSE_BYTES: u64 = 16 * 1024;

pub fn fetch_ip_info(rule: &ListenerRule) -> CommandResult<IpCheckResult> {
    let proxy = reqwest::Proxy::all(build_proxy_url(&rule.listen, rule.port, &rule.inbound_type))
        .map_err(|error| format!("Failed to configure rule proxy: {error}"))?;
    let client = reqwest::blocking::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| format!("Failed to build IP check client: {error}"))?;
    let response = client
        .get("https://ipinfo.io/json")
        .send()
        .map_err(|error| format!("Failed to check rule IP: {error}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "IP check request failed with status {}",
            response.status()
        ));
    }

    let mut response_body = Vec::new();
    response
        .take(MAX_IPINFO_RESPONSE_BYTES + 1)
        .read_to_end(&mut response_body)
        .map_err(|error| format!("Failed to read IP check response: {error}"))?;
    if response_body.len() as u64 > MAX_IPINFO_RESPONSE_BYTES {
        return Err("IP check response was too large".to_string());
    }

    let info = serde_json::from_slice::<IpInfoResponse>(&response_body)
        .map_err(|error| format!("Failed to parse IP check response: {error}"))?;
    let ip = info
        .ip
        .trim()
        .parse::<std::net::IpAddr>()
        .map_err(|_| "IP check response did not include a valid IP address".to_string())?
        .to_string();

    Ok(IpCheckResult {
        ip,
        country: normalize_country_code(info.country),
        checked_at: unix_timestamp_secs(),
    })
}
