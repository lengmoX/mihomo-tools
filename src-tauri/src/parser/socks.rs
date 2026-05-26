use crate::models::{AuthConfig, CommandResult, OutboundConfig, ParseOutboundUrlResult, SocksOutboundConfig};
use crate::utils::percent_decode;

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

pub fn try_parse_raw_socks(input: &str) -> Option<ParseOutboundUrlResult> {
    let mut cleaned = input.trim();
    if let Some(rest) = cleaned.strip_prefix("socks5://") {
        cleaned = rest.trim();
    } else if let Some(rest) = cleaned.strip_prefix("socks://") {
        cleaned = rest.trim();
    }

    // Support formats:
    // 1. username:password@hostname:port
    // 2. hostname:port@username:password
    // 3. hostname:port:username:password
    // 4. username:password:hostname:port
    // 5. hostname:port

    if cleaned.contains('@') {
        let parts: Vec<&str> = cleaned.split('@').collect();
        if parts.len() == 2 {
            let p0 = parts[0].trim();
            let p1 = parts[1].trim();

            if let Some((host, port_str)) = p1.rsplit_once(':') {
                if let Ok(port) = port_str.trim().parse::<u16>() {
                    let (user, pass) = if let Some((u, p)) = p0.split_once(':') {
                        (u.to_string(), p.to_string())
                    } else {
                        (p0.to_string(), "".to_string())
                    };
                    return Some(ParseOutboundUrlResult {
                        outbound: OutboundConfig::Socks(SocksOutboundConfig {
                            host: host.trim().to_string(),
                            port,
                            auth: if user.is_empty() && pass.is_empty() {
                                None
                            } else {
                                Some(AuthConfig { username: user, password: pass })
                            },
                        }),
                        display_name: None,
                        warnings: Vec::new(),
                    });
                }
            }

            if let Some((host, port_str)) = p0.rsplit_once(':') {
                if let Ok(port) = port_str.trim().parse::<u16>() {
                    let (user, pass) = if let Some((u, p)) = p1.split_once(':') {
                        (u.to_string(), p.to_string())
                    } else {
                        (p1.to_string(), "".to_string())
                    };
                    return Some(ParseOutboundUrlResult {
                        outbound: OutboundConfig::Socks(SocksOutboundConfig {
                            host: host.trim().to_string(),
                            port,
                            auth: if user.is_empty() && pass.is_empty() {
                                None
                            } else {
                                Some(AuthConfig { username: user, password: pass })
                            },
                        }),
                        display_name: None,
                        warnings: Vec::new(),
                    });
                }
            }
        }
    }

    let parts: Vec<&str> = cleaned.split(':').map(|s| s.trim()).collect();
    if parts.len() == 4 {
        let port_1_opt = parts[1].parse::<u16>().ok();
        let port_3_opt = parts[3].parse::<u16>().ok();

        match (port_1_opt, port_3_opt) {
            (Some(port1), Some(port3)) => {
                let host_in_0 = parts[0].contains('.') || parts[0] == "localhost" || !parts[2].contains('.');
                if host_in_0 {
                    return Some(ParseOutboundUrlResult {
                        outbound: OutboundConfig::Socks(SocksOutboundConfig {
                            host: parts[0].to_string(),
                            port: port1,
                            auth: Some(AuthConfig {
                                username: parts[2].to_string(),
                                password: parts[3].to_string(),
                            }),
                        }),
                        display_name: None,
                        warnings: Vec::new(),
                    });
                } else {
                    return Some(ParseOutboundUrlResult {
                        outbound: OutboundConfig::Socks(SocksOutboundConfig {
                            host: parts[2].to_string(),
                            port: port3,
                            auth: Some(AuthConfig {
                                username: parts[0].to_string(),
                                password: parts[1].to_string(),
                            }),
                        }),
                        display_name: None,
                        warnings: Vec::new(),
                    });
                }
            }
            (Some(port1), None) => {
                return Some(ParseOutboundUrlResult {
                    outbound: OutboundConfig::Socks(SocksOutboundConfig {
                        host: parts[0].to_string(),
                        port: port1,
                        auth: Some(AuthConfig {
                            username: parts[2].to_string(),
                            password: parts[3].to_string(),
                        }),
                    }),
                    display_name: None,
                    warnings: Vec::new(),
                });
            }
            (None, Some(port3)) => {
                return Some(ParseOutboundUrlResult {
                    outbound: OutboundConfig::Socks(SocksOutboundConfig {
                        host: parts[2].to_string(),
                        port: port3,
                        auth: Some(AuthConfig {
                            username: parts[0].to_string(),
                            password: parts[1].to_string(),
                        }),
                    }),
                    display_name: None,
                    warnings: Vec::new(),
                });
            }
            (None, None) => {}
        }
    } else if parts.len() == 2 {
        if let Ok(port) = parts[1].parse::<u16>() {
            return Some(ParseOutboundUrlResult {
                outbound: OutboundConfig::Socks(SocksOutboundConfig {
                    host: parts[0].to_string(),
                    port,
                    auth: None,
                }),
                display_name: None,
                warnings: Vec::new(),
            });
        }
    }

    None
}
