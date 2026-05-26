use crate::models::{
    AuthConfig, CommandResult, ImportSource, OutboundConfig, ParseOutboundUrlResult,
    SocksOutboundConfig, ShadowsocksOutboundConfig, VlessOutboundConfig, VlessRealityConfig,
    VlessTlsConfig, VlessTransportConfig, VlessTransportKind,
    TrojanOutboundConfig, TrojanRealityConfig, TrojanTlsConfig, TrojanTransportConfig, TrojanTransportKind,
    AnytlsOutboundConfig, Hysteria2OutboundConfig, Hysteria2ObfsConfig,
};
use crate::utils::unix_timestamp_secs;

fn strip_common_indentation(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut min_indent = usize::MAX;
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent < min_indent {
            min_indent = indent;
        }
    }
    
    if min_indent == usize::MAX || min_indent == 0 {
        return input.to_string();
    }
    
    let mut result = String::new();
    for line in lines {
        if line.trim().is_empty() {
            result.push('\n');
        } else if line.len() >= min_indent {
            result.push_str(&line[min_indent..]);
            result.push('\n');
        } else {
            result.push_str(line.trim_start());
            result.push('\n');
        }
    }
    result
}

pub fn parse_mihomo_yaml(input: &str) -> CommandResult<ParseOutboundUrlResult> {
    let normalized = strip_common_indentation(input);
    let mut trimmed = normalized.trim();
    if trimmed.starts_with("-{") {
        trimmed = trimmed[1..].trim();
    } else if trimmed.starts_with("- {") {
        trimmed = trimmed[2..].trim();
    }

    let val: serde_yaml::Value = serde_yaml::from_str(trimmed)
        .map_err(|e| format!("Failed to parse YAML/JSON: {e}"))?;

    let map = match val {
        serde_yaml::Value::Mapping(m) => m,
        serde_yaml::Value::Sequence(seq) => {
            if let Some(serde_yaml::Value::Mapping(m)) = seq.first() {
                m.clone()
            } else {
                return Err("Pasted YAML sequence does not contain a proxy node mapping".to_string());
            }
        }
        _ => return Err("Pasted text is not a valid YAML mapping or sequence".to_string()),
    };

    let type_val = map.get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "YAML proxy config missing 'type' field".to_string())?;

    let name = map.get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let server = map.get("server")
        .or_else(|| map.get("host"))
        .and_then(|v| v.as_str().map(|s| s.to_string())
            .or_else(|| v.as_i64().map(|n| n.to_string())))
        .ok_or_else(|| "YAML proxy config missing 'server' field".to_string())?;

    let port = map.get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "YAML proxy config missing 'port' field".to_string())? as u16;

    let outbound = match type_val {
        "socks" | "socks5" => {
            let username = map.get("username").and_then(|v| v.as_str());
            let password = map.get("password").and_then(|v| v.as_str());
            let auth = if let (Some(u), Some(p)) = (username, password) {
                Some(AuthConfig {
                    username: u.to_string(),
                    password: p.to_string(),
                })
            } else {
                None
            };
            OutboundConfig::Socks(SocksOutboundConfig {
                host: server,
                port,
                auth,
            })
        }
        "ss" => {
            let cipher = map.get("cipher")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Shadowsocks config missing 'cipher' field".to_string())?
                .to_string();
            let password = map.get("password")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Shadowsocks config missing 'password' field".to_string())?
                .to_string();
            let uot = map.get("uot").and_then(|v| v.as_bool()).unwrap_or(false);
            let uot_version = map.get("uot-version").or_else(|| map.get("uotVersion"))
                .and_then(|v| v.as_u64().map(|n| n as u8));
            OutboundConfig::Shadowsocks(ShadowsocksOutboundConfig {
                address: server,
                port,
                method: cipher,
                password,
                uot,
                uot_version,
                import_source: Some(ImportSource {
                    raw_url: input.trim().to_string(),
                    imported_at: unix_timestamp_secs(),
                    warnings: Vec::new(),
                }),
            })
        }
        "vless" => {
            let uuid = map.get("uuid")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "VLESS config missing 'uuid' field".to_string())?
                .to_string();
            let flow = map.get("flow").and_then(|v| v.as_str()).map(|s| s.to_string());
            let network = map.get("network").and_then(|v| v.as_str()).unwrap_or("tcp");

            let transport_kind = match network {
                "tcp" => VlessTransportKind::Tcp,
                "ws" => VlessTransportKind::Ws,
                other => return Err(format!("Unsupported VLESS network '{other}'")),
            };

            let mut path = None;
            let mut ws_host = None;
            if transport_kind == VlessTransportKind::Ws {
                if let Some(ws_opts) = map.get("ws-opts") {
                    path = ws_opts.get("path").and_then(|v| v.as_str()).map(|s| s.to_string());
                    ws_host = ws_opts.get("headers")
                        .and_then(|h| h.get("Host").or_else(|| h.get("host")))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }

            let tls = map.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
            let mut tls_config = None;
            let mut reality_config = None;

            if tls {
                if let Some(reality_opts) = map.get("reality-opts") {
                    let pbk = reality_opts.get("public-key").or_else(|| reality_opts.get("publicKey"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "VLESS reality-opts missing public-key".to_string())?
                        .to_string();
                    let sid = reality_opts.get("short-id").or_else(|| reality_opts.get("shortId"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    let sni = map.get("servername").or_else(|| map.get("server-name"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    let fp = map.get("client-fingerprint").or_else(|| map.get("clientFingerprint"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    reality_config = Some(VlessRealityConfig {
                        server_name: sni,
                        fingerprint: fp,
                        public_key: pbk,
                        short_id: sid,
                        spider_x: None,
                    });
                } else {
                    let sni = map.get("servername").or_else(|| map.get("server-name"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    let fp = map.get("client-fingerprint").or_else(|| map.get("clientFingerprint"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    let skip_cert = map.get("skip-cert-verify").or_else(|| map.get("skipCertVerify"))
                        .and_then(|v| v.as_bool());
                    tls_config = Some(VlessTlsConfig {
                        server_name: sni,
                        fingerprint: fp,
                        allow_insecure: skip_cert,
                    });
                }
            }

            OutboundConfig::Vless(VlessOutboundConfig {
                address: server,
                port,
                id: uuid,
                encryption: map.get("cipher").or_else(|| map.get("encryption")).and_then(|v| v.as_str()).unwrap_or("none").to_string(),
                flow,
                level: None,
                transport: VlessTransportConfig {
                    kind: transport_kind,
                    path,
                    host: ws_host,
                },
                tls: tls_config,
                reality: reality_config,
                import_source: Some(ImportSource {
                    raw_url: input.trim().to_string(),
                    imported_at: unix_timestamp_secs(),
                    warnings: Vec::new(),
                }),
            })
        }
        "trojan" => {
            let password = map.get("password")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Trojan config missing 'password' field".to_string())?
                .to_string();
            let network = map.get("network").and_then(|v| v.as_str()).unwrap_or("tcp");

            let transport_kind = match network {
                "tcp" => TrojanTransportKind::Tcp,
                "ws" => TrojanTransportKind::Ws,
                other => return Err(format!("Unsupported Trojan network '{other}'")),
            };

            let mut path = None;
            let mut ws_host = None;
            if transport_kind == TrojanTransportKind::Ws {
                if let Some(ws_opts) = map.get("ws-opts") {
                    path = ws_opts.get("path").and_then(|v| v.as_str()).map(|s| s.to_string());
                    ws_host = ws_opts.get("headers")
                        .and_then(|h| h.get("Host").or_else(|| h.get("host")))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }

            let tls = map.get("tls").and_then(|v| v.as_bool()).unwrap_or(true);
            let mut tls_config = None;
            let mut reality_config = None;

            if tls {
                if let Some(reality_opts) = map.get("reality-opts") {
                    let pbk = reality_opts.get("public-key").or_else(|| reality_opts.get("publicKey"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "Trojan reality-opts missing public-key".to_string())?
                        .to_string();
                    let sid = reality_opts.get("short-id").or_else(|| reality_opts.get("shortId"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    let sni = map.get("servername").or_else(|| map.get("server-name"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    let fp = map.get("client-fingerprint").or_else(|| map.get("clientFingerprint"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    reality_config = Some(TrojanRealityConfig {
                        server_name: sni,
                        fingerprint: fp,
                        public_key: pbk,
                        short_id: sid,
                        spider_x: None,
                    });
                } else {
                    let sni = map.get("servername").or_else(|| map.get("server-name"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    let fp = map.get("client-fingerprint").or_else(|| map.get("clientFingerprint"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    let skip_cert = map.get("skip-cert-verify").or_else(|| map.get("skipCertVerify"))
                        .and_then(|v| v.as_bool());
                    tls_config = Some(TrojanTlsConfig {
                        server_name: sni,
                        fingerprint: fp,
                        allow_insecure: skip_cert,
                    });
                }
            }

            OutboundConfig::Trojan(TrojanOutboundConfig {
                address: server,
                port,
                password,
                email: None,
                level: None,
                transport: TrojanTransportConfig {
                    kind: transport_kind,
                    path,
                    host: ws_host,
                },
                tls: tls_config,
                reality: reality_config,
                import_source: Some(ImportSource {
                    raw_url: input.trim().to_string(),
                    imported_at: unix_timestamp_secs(),
                    warnings: Vec::new(),
                }),
            })
        }
        "anytls" => {
            let password = map.get("password")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "AnyTLS config missing 'password' field".to_string())?
                .to_string();
            let sni = map.get("sni").or_else(|| map.get("peer")).and_then(|v| v.as_str().map(|s| s.to_string()));
            let skip_cert = map.get("skip-cert-verify").or_else(|| map.get("skipCertVerify")).and_then(|v| v.as_bool());
            let fp = map.get("client-fingerprint").or_else(|| map.get("clientFingerprint")).and_then(|v| v.as_str().map(|s| s.to_string()));
            let udp = map.get("udp").and_then(|v| v.as_bool());
            let alpn = map.get("alpn").and_then(|v| {
                if let Some(arr) = v.as_sequence() {
                    Some(arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                } else if let Some(s) = v.as_str() {
                    Some(s.split(',').map(|x| x.trim().to_string()).collect())
                } else {
                    None
                }
            });
            let interval = map.get("idle-session-check-interval").and_then(|v| v.as_u64().map(|n| n as u32));
            let timeout = map.get("idle-session-timeout").and_then(|v| v.as_u64().map(|n| n as u32));
            let min_idle = map.get("min-idle-session").and_then(|v| v.as_u64().map(|n| n as u32));

            OutboundConfig::Anytls(AnytlsOutboundConfig {
                address: server,
                port,
                password,
                client_fingerprint: fp,
                udp,
                idle_session_check_interval: interval,
                idle_session_timeout: timeout,
                min_idle_session: min_idle,
                sni,
                alpn,
                skip_cert_verify: skip_cert,
                import_source: Some(ImportSource {
                    raw_url: input.trim().to_string(),
                    imported_at: unix_timestamp_secs(),
                    warnings: Vec::new(),
                }),
            })
        }
        "hysteria2" | "hysteria" => {
            let password = map.get("password").or_else(|| map.get("auth_str")).or_else(|| map.get("auth-str"))
                .and_then(|v| v.as_str().map(|s| s.to_string()));
            let sni = map.get("sni").and_then(|v| v.as_str().map(|s| s.to_string()));
            let skip_cert = map.get("skip-cert-verify").or_else(|| map.get("skipCertVerify")).and_then(|v| v.as_bool());
            let tfo = map.get("tfo").and_then(|v| v.as_bool());
            let up = map.get("up").and_then(|v| v.as_str().map(|s| s.to_string())
                .or_else(|| v.as_i64().map(|n| n.to_string())));
            let down = map.get("down").and_then(|v| v.as_str().map(|s| s.to_string())
                .or_else(|| v.as_i64().map(|n| n.to_string())));

            let obfs = map.get("obfs").and_then(|v| {
                let r#type = v.get("type").and_then(|t| t.as_str())?.to_string();
                let pwd = v.get("password").and_then(|p| p.as_str())?.to_string();
                Some(Hysteria2ObfsConfig { r#type, password: pwd })
            });

            OutboundConfig::Hysteria2(Hysteria2OutboundConfig {
                server,
                port,
                password,
                auth_str: None,
                sni,
                skip_cert_verify: skip_cert,
                tfo,
                up,
                down,
                obfs,
                import_source: Some(ImportSource {
                    raw_url: input.trim().to_string(),
                    imported_at: unix_timestamp_secs(),
                    warnings: Vec::new(),
                }),
            })
        }
        other => return Err(format!("Unsupported proxy type '{other}' in YAML")),
    };

    crate::models::validate_outbound_config("imported", &outbound)?;

    Ok(ParseOutboundUrlResult {
        outbound,
        display_name: name,
        warnings: Vec::new(),
    })
}
