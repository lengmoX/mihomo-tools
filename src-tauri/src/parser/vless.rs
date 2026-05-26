use crate::models::{
    CommandResult, ImportSource, OutboundConfig, ParseOutboundUrlResult,
    VlessOutboundConfig, VlessRealityConfig, VlessTlsConfig, VlessTransportConfig, VlessTransportKind,
    SUPPORTED_VLESS_FLOWS,
};
use crate::utils::{percent_decode, unix_timestamp_secs};
use super::{parse_fragment, optional_query_value, unsupported_query_warnings};

pub fn parse_vless_url(input: &str) -> CommandResult<ParseOutboundUrlResult> {
    let url =
        url::Url::parse(input).map_err(|error| format!("Failed to parse VLESS URL: {error}"))?;
    if url.scheme() != "vless" {
        return Err("Only vless:// URLs are supported".to_string());
    }
    let id = percent_decode(url.username())?;
    if id.trim().is_empty() {
        return Err("VLESS URL must include an id before @".to_string());
    }
    let address = url
        .host_str()
        .ok_or_else(|| "VLESS URL must include a host".to_string())?
        .to_string();
    let port = url
        .port()
        .ok_or_else(|| "VLESS URL must include a port".to_string())?;
    let query = url.query_pairs().collect::<Vec<_>>();
    let transport_kind_str = optional_query_value(&query, "type").unwrap_or_else(|| "tcp".to_string());
    let transport_kind = match transport_kind_str.as_str() {
        "tcp" => VlessTransportKind::Tcp,
        "ws" => VlessTransportKind::Ws,
        other => return Err(format!("VLESS transport '{other}' is not supported yet; only tcp and ws are supported")),
    };
    let path = if transport_kind == VlessTransportKind::Ws {
        optional_query_value(&query, "path").map(|p| percent_decode(&p).unwrap_or(p))
    } else {
        None
    };
    let host = if transport_kind == VlessTransportKind::Ws {
        optional_query_value(&query, "host")
    } else {
        None
    };
    let encryption =
        optional_query_value(&query, "encryption").unwrap_or_else(|| "none".to_string());
    let flow = optional_query_value(&query, "flow").filter(|value| !value.is_empty());
    if let Some(flow) = flow.as_deref() {
        if !SUPPORTED_VLESS_FLOWS.contains(&flow) {
            return Err(format!("Unsupported VLESS flow '{flow}'"));
        }
    }

    let security = optional_query_value(&query, "security").unwrap_or_else(|| "none".to_string());
    let sni = optional_query_value(&query, "sni").filter(|value| !value.is_empty());
    let fp = optional_query_value(&query, "fp").filter(|value| !value.is_empty());
    let allow_insecure = optional_query_value(&query, "allowInsecure")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"));

    let (tls, reality) = match security.as_str() {
        "none" | "" => (None, None),
        "tls" => (
            Some(VlessTlsConfig {
                server_name: sni,
                fingerprint: fp,
                allow_insecure,
            }),
            None,
        ),
        "reality" => {
            let public_key = optional_query_value(&query, "pbk")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "VLESS REALITY links must include pbk".to_string())?;
            (
                None,
                Some(VlessRealityConfig {
                    server_name: sni,
                    fingerprint: fp,
                    public_key,
                    short_id: optional_query_value(&query, "sid").filter(|value| !value.is_empty()),
                    spider_x: optional_query_value(&query, "spx").filter(|value| !value.is_empty()),
                }),
            )
        }
        other => return Err(format!("Unsupported VLESS security '{other}'")),
    };

    let warnings = unsupported_query_warnings(
        &query,
        &[
            "type",
            "security",
            "flow",
            "encryption",
            "sni",
            "pbk",
            "sid",
            "spx",
            "fp",
            "packetEncoding",
            "allowInsecure",
            "path",
            "host",
        ],
    );

    let outbound = OutboundConfig::Vless(VlessOutboundConfig {
        address,
        port,
        id,
        encryption,
        flow,
        level: None,
        transport: VlessTransportConfig {
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
