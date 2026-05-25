use serde_json::{json, Value};
use crate::models::{
    AppState, CommandResult, OutboundConfig, InboundProtocol
};

pub fn generate_config_value(state: &AppState) -> CommandResult<Value> {
    crate::models::validate_state(state)?;

    let mut listeners = Vec::new();
    let mut proxies = Vec::new();
    let mut proxy_groups = Vec::new();

    for rule in state.rules.iter().filter(|r| r.enabled) {
        let node_name = format!("node-{}", rule.id);
        let group_name = format!("group-{}", rule.id);

        // 1. 生成 listener
        let inbound_type = match rule.inbound.protocol {
            InboundProtocol::Mixed => "mixed",
            InboundProtocol::Socks => "socks",
            InboundProtocol::Http => "http",
        };

        let mut listener = json!({
            "name": format!("listener-{}", rule.id),
            "type": inbound_type,
            "listen": rule.inbound.listen,
            "port": rule.inbound.port,
            "proxy": group_name,
        });

        if let Some(auth) = &rule.inbound.auth {
            if let Some(obj) = listener.as_object_mut() {
                obj.insert("username".to_string(), json!(auth.username));
                obj.insert("password".to_string(), json!(auth.password));
            }
        }

        listeners.push(listener);

        // 2. 生成 proxy
        let proxy_val = generate_mihomo_proxy_val(&node_name, &rule.outbound)?;
        proxies.push(proxy_val);

        // 3. 生成 proxy-group
        let pg = json!({
            "name": group_name,
            "type": "select",
            "proxies": vec![node_name, "DIRECT".to_string(), "REJECT".to_string()],
        });
        proxy_groups.push(pg);
    }

    Ok(json!({
        "mixed-port": 37890,
        "allow-lan": false,
        "mode": "rule",
        "log-level": "warning",
        "dns": {
            "enable": true,
            "ipv6": false,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": [
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/dns-query"
            ],
            "proxy-server-nameserver": [
                "https://223.5.5.5/dns-query",
                "https://223.6.6.6/dns-query"
            ],
            "direct-nameserver": [
                "https://223.5.5.5/dns-query",
                "https://223.6.6.6/dns-query"
            ],
            "respect-rules": true,
            "use-hosts": false,
            "use-system-hosts": false
        },
        "listeners": listeners,
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": [
            "MATCH,DIRECT"
        ]
    }))
}

fn generate_mihomo_proxy_val(name: &str, config: &OutboundConfig) -> CommandResult<Value> {
    let mut val = serde_json::Map::new();
    val.insert("name".to_string(), json!(name));

    match config {
        OutboundConfig::Socks(cfg) => {
            val.insert("type".to_string(), json!("socks5"));
            val.insert("server".to_string(), json!(cfg.host));
            val.insert("port".to_string(), json!(cfg.port));
            if let Some(auth) = &cfg.auth {
                val.insert("username".to_string(), json!(auth.username));
                val.insert("password".to_string(), json!(auth.password));
            }
        }
        OutboundConfig::Shadowsocks(cfg) => {
            val.insert("type".to_string(), json!("ss"));
            val.insert("server".to_string(), json!(cfg.address));
            val.insert("port".to_string(), json!(cfg.port));
            val.insert("cipher".to_string(), json!(cfg.method));
            val.insert("password".to_string(), json!(cfg.password));
            val.insert("udp".to_string(), json!(true));
        }
        OutboundConfig::Vless(cfg) => {
            val.insert("type".to_string(), json!("vless"));
            val.insert("server".to_string(), json!(cfg.address));
            val.insert("port".to_string(), json!(cfg.port));
            val.insert("uuid".to_string(), json!(cfg.id));
            val.insert("cipher".to_string(), json!("auto"));
            val.insert("udp".to_string(), json!(true));

            if let Some(flow) = &cfg.flow {
                if !flow.trim().is_empty() {
                    val.insert("flow".to_string(), json!(flow));
                }
            }

            let network = match cfg.transport.kind {
                crate::models::VlessTransportKind::Tcp => "tcp",
                crate::models::VlessTransportKind::Ws => "ws",
            };
            val.insert("network".to_string(), json!(network));

            if cfg.transport.kind == crate::models::VlessTransportKind::Ws {
                let mut ws_opts = serde_json::Map::new();
                if let Some(path) = &cfg.transport.path {
                    ws_opts.insert("path".to_string(), json!(path));
                }
                if let Some(host) = &cfg.transport.host {
                    let mut headers = serde_json::Map::new();
                    headers.insert("Host".to_string(), json!(host));
                    ws_opts.insert("headers".to_string(), json!(headers));
                }
                val.insert("ws-opts".to_string(), Value::Object(ws_opts));
            }

            if let Some(tls) = &cfg.tls {
                val.insert("tls".to_string(), json!(true));
                if let Some(server_name) = &tls.server_name {
                    if !server_name.trim().is_empty() {
                        val.insert("servername".to_string(), json!(server_name));
                    }
                }
                if let Some(allow_insecure) = tls.allow_insecure {
                    val.insert("skip-cert-verify".to_string(), json!(allow_insecure));
                }
                if let Some(fp) = &tls.fingerprint {
                    if !fp.trim().is_empty() {
                        val.insert("client-fingerprint".to_string(), json!(fp));
                    }
                }
            } else if let Some(reality) = &cfg.reality {
                val.insert("tls".to_string(), json!(true));
                if let Some(server_name) = &reality.server_name {
                    if !server_name.trim().is_empty() {
                        val.insert("servername".to_string(), json!(server_name));
                    }
                }
                if let Some(fp) = &reality.fingerprint {
                    if !fp.trim().is_empty() {
                        val.insert("client-fingerprint".to_string(), json!(fp));
                    }
                }
                let mut reality_opts = serde_json::Map::new();
                reality_opts.insert("public-key".to_string(), json!(reality.public_key));
                if let Some(short_id) = &reality.short_id {
                    reality_opts.insert("short-id".to_string(), json!(short_id));
                }
                val.insert("reality-opts".to_string(), Value::Object(reality_opts));
            }
        }
        OutboundConfig::Trojan(cfg) => {
            val.insert("type".to_string(), json!("trojan"));
            val.insert("server".to_string(), json!(cfg.address));
            val.insert("port".to_string(), json!(cfg.port));
            val.insert("password".to_string(), json!(cfg.password));
            val.insert("udp".to_string(), json!(true));

            let network = match cfg.transport.kind {
                crate::models::TrojanTransportKind::Tcp => "tcp",
                crate::models::TrojanTransportKind::Ws => "ws",
            };
            val.insert("network".to_string(), json!(network));

            if cfg.transport.kind == crate::models::TrojanTransportKind::Ws {
                let mut ws_opts = serde_json::Map::new();
                if let Some(path) = &cfg.transport.path {
                    ws_opts.insert("path".to_string(), json!(path));
                }
                if let Some(host) = &cfg.transport.host {
                    let mut headers = serde_json::Map::new();
                    headers.insert("Host".to_string(), json!(host));
                    ws_opts.insert("headers".to_string(), json!(headers));
                }
                val.insert("ws-opts".to_string(), Value::Object(ws_opts));
            }

            if let Some(tls) = &cfg.tls {
                val.insert("tls".to_string(), json!(true));
                if let Some(server_name) = &tls.server_name {
                    if !server_name.trim().is_empty() {
                        val.insert("servername".to_string(), json!(server_name));
                    }
                }
                if let Some(allow_insecure) = tls.allow_insecure {
                    val.insert("skip-cert-verify".to_string(), json!(allow_insecure));
                }
                if let Some(fp) = &tls.fingerprint {
                    if !fp.trim().is_empty() {
                        val.insert("client-fingerprint".to_string(), json!(fp));
                    }
                }
            } else if let Some(reality) = &cfg.reality {
                val.insert("tls".to_string(), json!(true));
                if let Some(server_name) = &reality.server_name {
                    if !server_name.trim().is_empty() {
                        val.insert("servername".to_string(), json!(server_name));
                    }
                }
                if let Some(fp) = &reality.fingerprint {
                    if !fp.trim().is_empty() {
                        val.insert("client-fingerprint".to_string(), json!(fp));
                    }
                }
                let mut reality_opts = serde_json::Map::new();
                reality_opts.insert("public-key".to_string(), json!(reality.public_key));
                if let Some(short_id) = &reality.short_id {
                    reality_opts.insert("short-id".to_string(), json!(short_id));
                }
                val.insert("reality-opts".to_string(), Value::Object(reality_opts));
            }
        }
    }

    Ok(Value::Object(val))
}
