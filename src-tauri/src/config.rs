use serde_json::{json, Value};
use crate::models::{
    AppState, CommandResult, OutboundConfig
};

pub fn generate_config_value(state: &AppState) -> CommandResult<Value> {
    crate::models::validate_state(state)?;

    let mut listeners = Vec::new();
    let mut proxies = Vec::new();
    let mut proxy_groups = Vec::new();

    // 1. 生成 listeners
    for rule in state.rules.iter().filter(|r| r.enabled) {
        // 查找对应的代理组名称
        let group = state.groups.iter().find(|g| g.id == rule.group_id)
            .ok_or_else(|| format!("Rule '{}' refers to non-existent group '{}'", rule.name, rule.group_id))?;
        
        let listener = json!({
            "name": format!("listener-{}", rule.id),
            "type": rule.inbound_type,
            "listen": rule.listen,
            "port": rule.port,
            "proxy": group.name,
        });

        listeners.push(listener);
    }

    // 2. 生成 proxies
    for node in &state.proxies {
        let proxy = generate_mihomo_proxy(node)?;
        proxies.push(proxy);
    }

    // 3. 生成 proxy-groups
    for group in &state.groups {
        let pg = json!({
            "name": group.name,
            "type": group.group_type, // "select"
            "proxies": group.proxies,
        });
        proxy_groups.push(pg);
    }

    // 4. 组装全局配置
    Ok(json!({
        "mixed-port": 37890,
        "allow-lan": false,
        "mode": "rule",
        "log-level": "warning",
        "listeners": listeners,
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": [
            "MATCH,DIRECT"
        ]
    }))
}

fn generate_mihomo_proxy(node: &crate::models::ProxyNode) -> CommandResult<Value> {
    let mut val = serde_json::Map::new();
    val.insert("name".to_string(), json!(node.name));

    match &node.config {
        OutboundConfig::Socks(config) => {
            val.insert("type".to_string(), json!("socks"));
            val.insert("server".to_string(), json!(config.host));
            val.insert("port".to_string(), json!(config.port));
            if let Some(auth) = &config.auth {
                val.insert("username".to_string(), json!(auth.username));
                val.insert("password".to_string(), json!(auth.password));
            }
        }
        OutboundConfig::Shadowsocks(config) => {
            val.insert("type".to_string(), json!("ss"));
            val.insert("server".to_string(), json!(config.address));
            val.insert("port".to_string(), json!(config.port));
            val.insert("cipher".to_string(), json!(config.method));
            val.insert("password".to_string(), json!(config.password));
            val.insert("udp".to_string(), json!(true));
        }
        OutboundConfig::Vless(config) => {
            val.insert("type".to_string(), json!("vless"));
            val.insert("server".to_string(), json!(config.address));
            val.insert("port".to_string(), json!(config.port));
            val.insert("uuid".to_string(), json!(config.id));
            val.insert("cipher".to_string(), json!("auto"));
            val.insert("udp".to_string(), json!(true));

            if let Some(flow) = &config.flow {
                if !flow.trim().is_empty() {
                    val.insert("flow".to_string(), json!(flow));
                }
            }

            let network = match config.transport.kind {
                crate::models::VlessTransportKind::Tcp => "tcp",
                crate::models::VlessTransportKind::Ws => "ws",
            };
            val.insert("network".to_string(), json!(network));

            if config.transport.kind == crate::models::VlessTransportKind::Ws {
                let mut ws_opts = serde_json::Map::new();
                if let Some(path) = &config.transport.path {
                    ws_opts.insert("path".to_string(), json!(path));
                }
                if let Some(host) = &config.transport.host {
                    let mut headers = serde_json::Map::new();
                    headers.insert("Host".to_string(), json!(host));
                    ws_opts.insert("headers".to_string(), json!(headers));
                }
                val.insert("ws-opts".to_string(), Value::Object(ws_opts));
            }

            if let Some(tls) = &config.tls {
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
            } else if let Some(reality) = &config.reality {
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
        OutboundConfig::Trojan(config) => {
            val.insert("type".to_string(), json!("trojan"));
            val.insert("server".to_string(), json!(config.address));
            val.insert("port".to_string(), json!(config.port));
            val.insert("password".to_string(), json!(config.password));
            val.insert("udp".to_string(), json!(true));

            let network = match config.transport.kind {
                crate::models::TrojanTransportKind::Tcp => "tcp",
                crate::models::TrojanTransportKind::Ws => "ws",
            };
            val.insert("network".to_string(), json!(network));

            if config.transport.kind == crate::models::TrojanTransportKind::Ws {
                let mut ws_opts = serde_json::Map::new();
                if let Some(path) = &config.transport.path {
                    ws_opts.insert("path".to_string(), json!(path));
                }
                if let Some(host) = &config.transport.host {
                    let mut headers = serde_json::Map::new();
                    headers.insert("Host".to_string(), json!(host));
                    ws_opts.insert("headers".to_string(), json!(headers));
                }
                val.insert("ws-opts".to_string(), Value::Object(ws_opts));
            }

            if let Some(tls) = &config.tls {
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
            } else if let Some(reality) = &config.reality {
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
