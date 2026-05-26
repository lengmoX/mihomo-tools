use crate::models::{CommandResult, ImportSource, OutboundConfig, ParseOutboundUrlResult, ShadowsocksOutboundConfig};
use crate::utils::{percent_decode, decode_base64_optional, decode_base64_required, unix_timestamp_secs};
use super::{parse_fragment, optional_query_value, unsupported_query_warnings};

pub fn parse_shadowsocks_url(input: &str) -> CommandResult<ParseOutboundUrlResult> {
    let url = url::Url::parse(input)
        .map_err(|error| format!("Failed to parse Shadowsocks URL: {error}"))?;
    if url.scheme() != "ss" {
        return Err("Only ss:// URLs are supported".to_string());
    }

    let query = url.query_pairs().collect::<Vec<_>>();
    reject_unsupported_shadowsocks_plugin_params(&query)?;
    let (method, password, address, port) = if url.username().is_empty() {
        parse_full_base64_shadowsocks(url.host_str(), url.port())?
    } else {
        let user_info = if let Some(password) = url.password() {
            format!(
                "{}:{}",
                percent_decode(url.username())?,
                percent_decode(password)?
            )
        } else {
            percent_decode(url.username())?
        };
        let decoded_user_info = decode_base64_optional(&user_info).unwrap_or(user_info);
        let (method, password) = parse_shadowsocks_user_info(&decoded_user_info)?;
        let address = url
            .host_str()
            .ok_or_else(|| "Shadowsocks URL must include a host".to_string())?
            .to_string();
        let port = url
            .port()
            .ok_or_else(|| "Shadowsocks URL must include a port".to_string())?;
        (method, password, address, port)
    };

    let uot = optional_query_value(&query, "uot")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let uot_version = optional_query_value(&query, "uotVersion")
        .or_else(|| optional_query_value(&query, "UoTVersion"))
        .map(|value| {
            value
                .parse::<u8>()
                .map_err(|_| "Shadowsocks UoT version must be 1 or 2".to_string())
        })
        .transpose()?;

    let warnings = unsupported_query_warnings(&query, &["uot", "uotVersion", "UoTVersion"]);

    let outbound = OutboundConfig::Shadowsocks(ShadowsocksOutboundConfig {
        address,
        port,
        method,
        password,
        uot,
        uot_version,
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

pub fn reject_unsupported_shadowsocks_plugin_params(
    query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
) -> CommandResult<()> {
    let critical_params = ["plugin", "plugin_opts", "obfs", "obfs-host", "obfsHost"];
    if let Some((name, _)) = query
        .iter()
        .find(|(name, _)| critical_params.iter().any(|param| name.eq_ignore_ascii_case(param)))
    {
        return Err(format!(
            "Shadowsocks plugin/obfs parameter '{name}' is not supported yet"
        ));
    }
    Ok(())
}

pub fn parse_full_base64_shadowsocks(
    encoded: Option<&str>,
    parsed_port: Option<u16>,
) -> CommandResult<(String, String, String, u16)> {
    if parsed_port.is_some() {
        return Err("Shadowsocks URL is missing method and password".to_string());
    }
    let decoded = decode_base64_required(
        encoded.ok_or_else(|| "Shadowsocks URL must include server information".to_string())?,
    )?;
    let (user_info, host_port) = decoded
        .rsplit_once('@')
        .ok_or_else(|| "Shadowsocks URL must include method:password@host:port".to_string())?;
    let (method, password) = parse_shadowsocks_user_info(user_info)?;
    let (address, port_text) = host_port
        .rsplit_once(':')
        .ok_or_else(|| "Shadowsocks URL must include host and port".to_string())?;
    if address.trim().is_empty() {
        return Err("Shadowsocks host cannot be empty".to_string());
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|_| "Shadowsocks port must be between 1 and 65535".to_string())?;
    Ok((method, password, address.to_string(), port))
}

pub fn parse_shadowsocks_user_info(user_info: &str) -> CommandResult<(String, String)> {
    let (method, password) = user_info.split_once(':').ok_or_else(|| {
        "Shadowsocks credentials must be formatted as method:password".to_string()
    })?;
    if method.trim().is_empty() || password.is_empty() {
        return Err("Shadowsocks method and password cannot be empty".to_string());
    }
    Ok((method.to_string(), password.to_string()))
}
