use crate::models::{CommandResult, ImportSource, OutboundConfig, ParseOutboundUrlResult, Hysteria2OutboundConfig, Hysteria2ObfsConfig};
use crate::utils::{percent_decode, unix_timestamp_secs};
use super::{parse_fragment, optional_query_value, unsupported_query_warnings};

pub fn parse_hysteria2_url(input: &str) -> CommandResult<ParseOutboundUrlResult> {
    let url = url::Url::parse(input)
        .map_err(|error| format!("Failed to parse Hysteria2 URL: {error}"))?;
    let scheme = url.scheme();
    if scheme != "hy2" && scheme != "hysteria2" {
        return Err("Only hy2:// and hysteria2:// URLs are supported".to_string());
    }

    let password = percent_decode(url.username())?;
    let password_opt = if password.is_empty() { None } else { Some(password) };

    let server = url
        .host_str()
        .ok_or_else(|| "Hysteria2 URL must include a host".to_string())?
        .to_string();
    let port = url
        .port()
        .ok_or_else(|| "Hysteria2 URL must include a port".to_string())?;

    let query = url.query_pairs().collect::<Vec<_>>();
    let sni = optional_query_value(&query, "sni").filter(|value| !value.is_empty());
    let skip_cert_verify = optional_query_value(&query, "skip-cert-verify")
        .or_else(|| optional_query_value(&query, "allowInsecure"))
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    let tfo = optional_query_value(&query, "tfo")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    let up = optional_query_value(&query, "up").filter(|value| !value.is_empty());
    let down = optional_query_value(&query, "down").filter(|value| !value.is_empty());

    let obfs_type = optional_query_value(&query, "obfs").filter(|value| !value.is_empty());
    let obfs_password = optional_query_value(&query, "obfs-password").filter(|value| !value.is_empty());
    
    let obfs = if let (Some(t), Some(p)) = (obfs_type, obfs_password) {
        Some(Hysteria2ObfsConfig { r#type: t, password: p })
    } else {
        None
    };

    let warnings = unsupported_query_warnings(
        &query,
        &[
            "sni",
            "skip-cert-verify",
            "allowInsecure",
            "tfo",
            "up",
            "down",
            "obfs",
            "obfs-password",
        ],
    );

    let outbound = OutboundConfig::Hysteria2(Hysteria2OutboundConfig {
        server,
        port,
        password: password_opt,
        auth_str: None,
        sni,
        skip_cert_verify,
        tfo,
        up,
        down,
        obfs,
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
