use crate::models::{
    AuthConfig, CommandResult, ImportSource, OutboundConfig, ParseOutboundUrlResult,
    ShadowsocksOutboundConfig, SocksOutboundConfig, VlessOutboundConfig, VlessRealityConfig,
    VlessTlsConfig, VlessTransportConfig, VlessTransportKind,
    SUPPORTED_VLESS_FLOWS,
    TrojanOutboundConfig, TrojanTlsConfig, TrojanRealityConfig, TrojanTransportConfig, TrojanTransportKind,
    AnytlsOutboundConfig,
};
use crate::utils::{
    decode_base64_optional, decode_base64_required, percent_decode, unix_timestamp_secs,
};

pub fn parse_outbound_url_value(input: &str) -> CommandResult<ParseOutboundUrlResult> {
    let normalized = normalize_proxy_url(input);
    let (scheme, _) = normalized
        .split_once("://")
        .ok_or_else(|| "Proxy URL must include a supported scheme".to_string())?;

    match scheme.to_ascii_lowercase().as_str() {
        "socks" | "socks5" => parse_socks_url(&normalized),
        "vless" => parse_vless_url(&normalized),
        "ss" => parse_shadowsocks_url(&normalized),
        "trojan" => parse_trojan_url(&normalized),
        "anytls" => parse_anytls_url(&normalized),
        _ => Err("Only socks://, socks5://, vless://, ss://, trojan://, and anytls:// URLs are supported".to_string()),
    }
}

pub fn parse_socks_url(input: &str) -> CommandResult<ParseOutboundUrlResult> {
    let url =
        url::Url::parse(input).map_err(|error| format!("Failed to parse SOCKS URL: {error}"))?;
    let scheme = url.scheme();
    if scheme != "socks" && scheme != "socks5" {
        return Err("Only socks:// and socks5:// URLs are supported".to_string());
    }
    if !(url.path().is_empty() || url.path() == "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "SOCKS proxy URL must only contain host, port, and optional credentials".to_string(),
        );
    }

    let host = url
        .host_str()
        .ok_or_else(|| "SOCKS proxy host cannot be empty".to_string())?;
    let port = url
        .port()
        .ok_or_else(|| "SOCKS proxy URL must include host and port".to_string())?;
    let username = url.username();
    let auth = if username.is_empty() {
        None
    } else {
        let password = url
            .password()
            .ok_or_else(|| "SOCKS proxy credentials must be formatted as user:pass".to_string())?;
        if password.is_empty() {
            return Err("SOCKS proxy username and password cannot be empty".to_string());
        }
        Some(AuthConfig {
            username: percent_decode(username)?,
            password: percent_decode(password)?,
        })
    };

    Ok(ParseOutboundUrlResult {
        outbound: OutboundConfig::Socks(SocksOutboundConfig {
            host: host.to_string(),
            port,
            auth,
        }),
        display_name: None,
        warnings: Vec::new(),
    })
}

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

pub fn optional_query_value(
    query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    key: &str,
) -> Option<String> {
    query
        .iter()
        .find(|(name, _)| name.as_ref() == key)
        .map(|(_, value)| value.to_string())
}

pub fn unsupported_query_warnings(
    query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    supported: &[&str],
) -> Vec<String> {
    query
        .iter()
        .filter(|(name, _)| !supported.contains(&name.as_ref()))
        .map(|(name, _)| format!("Ignored unsupported query parameter '{name}'"))
        .collect()
}

pub fn parse_fragment(fragment: Option<&str>) -> CommandResult<Option<String>> {
    fragment
        .map(percent_decode)
        .transpose()
        .map(|fragment| fragment.filter(|value| !value.is_empty()))
}

pub fn normalize_proxy_url(input: &str) -> String {
    let trimmed = input.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return trimmed.to_string();
    };

    if let Some(at_idx) = find_credentials_separator(rest) {
        let credentials = &rest[..at_idx];
        let host_and_more = &rest[at_idx..];

        // Define the ASCII set of characters to encode in the credentials part.
        // These are characters that would interfere with standard URL parsing if left unencoded.
        // We include controls, space, double quote, angle brackets, backtick, hash, question mark,
        // curly braces, square brackets, slash, backslash, and '@' itself.
        // Note: we do NOT encode ':' to preserve SOCKS username:password separation.
        const SAFE_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
            .add(b' ')
            .add(b'"')
            .add(b'<')
            .add(b'>')
            .add(b'`')
            .add(b'#')
            .add(b'?')
            .add(b'{')
            .add(b'}')
            .add(b'[')
            .add(b']')
            .add(b'/')
            .add(b'\\')
            .add(b'@');

        let encoded_credentials = percent_encoding::utf8_percent_encode(credentials, SAFE_ENCODE_SET).to_string();
        format!("{}://{}{}", scheme, encoded_credentials, host_and_more)
    } else {
        trimmed.to_string()
    }
}

fn find_credentials_separator(rest: &str) -> Option<usize> {
    let mut at_indices = Vec::new();
    for (i, c) in rest.char_indices() {
        if c == '@' {
            at_indices.push(i);
        }
    }

    for &idx in at_indices.iter() {
        let after = &rest[idx + 1..];
        let end_idx = after.find(['/', '?', '#']).unwrap_or(after.len());
        let host_port_part = &after[..end_idx];

        if host_port_part.is_empty() {
            continue;
        }

        let is_valid = host_port_part.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == ':' || c == '[' || c == ']'
        });

        if is_valid {
            return Some(idx);
        }
    }
    None
}

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
