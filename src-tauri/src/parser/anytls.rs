use crate::models::{AnytlsOutboundConfig, CommandResult, ImportSource, OutboundConfig, ParseOutboundUrlResult};
use crate::utils::{percent_decode, unix_timestamp_secs};
use super::{parse_fragment, optional_query_value, unsupported_query_warnings};

pub fn parse_anytls_url(input: &str) -> CommandResult<ParseOutboundUrlResult> {
    let url = url::Url::parse(input)
        .map_err(|error| format!("Failed to parse AnyTLS URL: {error}"))?;
    if url.scheme() != "anytls" {
        return Err("Only anytls:// URLs are supported".to_string());
    }
    let password = percent_decode(url.username())?;
    if password.trim().is_empty() {
        return Err("AnyTLS URL must include password before @".to_string());
    }
    let address = url
        .host_str()
        .ok_or_else(|| "AnyTLS URL must include a host".to_string())?
        .to_string();
    let port = url
        .port()
        .ok_or_else(|| "AnyTLS URL must include a port".to_string())?;

    let query = url.query_pairs().collect::<Vec<_>>();
    let client_fingerprint = optional_query_value(&query, "client-fingerprint")
        .or_else(|| optional_query_value(&query, "fp"))
        .filter(|value| !value.is_empty());
    let udp = optional_query_value(&query, "udp")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    let interval = optional_query_value(&query, "idle-session-check-interval")
        .and_then(|v| v.parse::<u32>().ok());
    let timeout = optional_query_value(&query, "idle-session-timeout")
        .and_then(|v| v.parse::<u32>().ok());
    let min_idle = optional_query_value(&query, "min-idle-session")
        .and_then(|v| v.parse::<u32>().ok());
    let sni = optional_query_value(&query, "sni")
        .or_else(|| optional_query_value(&query, "peer"))
        .filter(|value| !value.is_empty());
    let alpn = optional_query_value(&query, "alpn")
        .map(|value| value.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>());
    let skip_cert_verify = optional_query_value(&query, "skip-cert-verify")
        .or_else(|| optional_query_value(&query, "allowInsecure"))
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"));

    let warnings = unsupported_query_warnings(
        &query,
        &[
            "client-fingerprint",
            "fp",
            "udp",
            "idle-session-check-interval",
            "idle-session-timeout",
            "min-idle-session",
            "sni",
            "peer",
            "alpn",
            "skip-cert-verify",
            "allowInsecure",
        ],
    );

    let outbound = OutboundConfig::Anytls(AnytlsOutboundConfig {
        address,
        port,
        password,
        client_fingerprint,
        udp,
        idle_session_check_interval: interval,
        idle_session_timeout: timeout,
        min_idle_session: min_idle,
        sni,
        alpn,
        skip_cert_verify,
        import_source: Some(ImportSource {
            raw_url: input.trim().to_string(),
            imported_at: unix_timestamp_secs(),
            warnings: warnings.clone(),
        }),
    });
    crate::models::validate_outbound_config("imported", &outbound)?;

    Ok(ParseOutboundUrlResult {
        outbound,
        display_name: parse_fragment(url.fragment())?,
        warnings,
    })
}
