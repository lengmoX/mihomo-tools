use crate::models::{
    CommandResult, ImportSource, OutboundConfig, ParseOutboundUrlResult,
    TrojanOutboundConfig, TrojanRealityConfig, TrojanTlsConfig, TrojanTransportConfig, TrojanTransportKind,
};
use crate::utils::{percent_decode, unix_timestamp_secs};
use super::{parse_fragment, optional_query_value, unsupported_query_warnings};

pub fn parse_trojan_url(input: &str) -> CommandResult<ParseOutboundUrlResult> {
    let url =
        url::Url::parse(input).map_err(|error| format!("Failed to parse Trojan URL: {error}"))?;
    if url.scheme() != "trojan" {
        return Err("Only trojan:// URLs are supported".to_string());
    }
    let password = percent_decode(url.username())?;
    if password.trim().is_empty() {
        return Err("Trojan URL must include password before @".to_string());
    }
    let address = url
        .host_str()
        .ok_or_else(|| "Trojan URL must include a host".to_string())?
        .to_string();
    let port = url
        .port()
        .ok_or_else(|| "Trojan URL must include a port".to_string())?;

    let query = url.query_pairs().collect::<Vec<_>>();
    let transport_kind_str = optional_query_value(&query, "type").unwrap_or_else(|| "tcp".to_string());
    let transport_kind = match transport_kind_str.as_str() {
        "tcp" => TrojanTransportKind::Tcp,
        "ws" => TrojanTransportKind::Ws,
        other => return Err(format!("Trojan transport '{other}' is not supported yet; only tcp and ws are supported")),
    };
    let path = if transport_kind == TrojanTransportKind::Ws {
        optional_query_value(&query, "path").map(|p| percent_decode(&p).unwrap_or(p))
    } else {
        None
    };
    let host = if transport_kind == TrojanTransportKind::Ws {
        optional_query_value(&query, "host")
    } else {
        None
    };

    let security = optional_query_value(&query, "security").unwrap_or_else(|| "tls".to_string());
    let sni = optional_query_value(&query, "sni").filter(|value| !value.is_empty());
    let fp = optional_query_value(&query, "fp").filter(|value| !value.is_empty());
    let email = optional_query_value(&query, "email").filter(|value| !value.is_empty());
    let allow_insecure = optional_query_value(&query, "allowInsecure")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"));

    let (tls, reality) = match security.as_str() {
        "none" | "" => (None, None),
        "tls" => (
            Some(TrojanTlsConfig {
                server_name: sni,
                fingerprint: fp,
                allow_insecure,
            }),
            None,
        ),
        "reality" => {
            let public_key = optional_query_value(&query, "pbk")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "Trojan REALITY links must include pbk".to_string())?;
            (
                None,
                Some(TrojanRealityConfig {
                    server_name: sni,
                    fingerprint: fp,
                    public_key,
                    short_id: optional_query_value(&query, "sid").filter(|value| !value.is_empty()),
                    spider_x: optional_query_value(&query, "spx").filter(|value| !value.is_empty()),
                }),
            )
        }
        other => return Err(format!("Unsupported Trojan security '{other}'")),
    };

    let warnings = unsupported_query_warnings(
        &query,
        &[
            "type",
            "security",
            "sni",
            "pbk",
            "sid",
            "spx",
            "fp",
            "email",
            "allowInsecure",
            "path",
            "host",
        ],
    );

    let outbound = OutboundConfig::Trojan(TrojanOutboundConfig {
        address,
        port,
        password,
        email,
        level: None,
        transport: TrojanTransportConfig {
            kind: transport_kind,
            path,
            host,
        },
        tls,
        reality,
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
