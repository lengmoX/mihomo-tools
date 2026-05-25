use serde_json::{json, Value};
use crate::models::{
    AppState, CommandResult, InboundProtocol, OutboundConfig, SocksOutboundConfig,
    VlessOutboundConfig, VlessTransportKind, ShadowsocksOutboundConfig, ProxyRule,
    TrojanOutboundConfig, TrojanTransportKind
};
use crate::utils::XRAY_API_PORT;

pub fn generate_config_value(state: &AppState) -> CommandResult<Value> {
    crate::models::validate_state(state)?;

    let enabled_rules = state.rules.iter().filter(|rule| rule.enabled);
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut routing_rules = Vec::new();

    // Add Xray API loopback inbound
    inbounds.push(json!({
        "listen": "127.0.0.1",
        "port": XRAY_API_PORT,
        "protocol": "dokodemo-door",
        "settings": {
            "address": "127.0.0.1"
        },
        "tag": "api-inbound"
    }));

    // Add API virtual outbound
    outbounds.push(json!({
        "protocol": "freedom",
        "tag": "api"
    }));

    // Add API routing rule at the very top of rules list
    routing_rules.push(json!({
        "type": "field",
        "inboundTag": ["api-inbound"],
        "outboundTag": "api"
    }));

    for rule in enabled_rules {
        let inbound_tag = inbound_tag(&rule.id);
        let outbound_tag = outbound_tag(&rule.id);
        inbounds.push(generate_inbound(rule, &inbound_tag));
        outbounds.push(generate_outbound(rule, &outbound_tag));
        routing_rules.push(json!({
            "type": "field",
            "inboundTag": [inbound_tag],
            "outboundTag": outbound_tag,
        }));
    }

    Ok(json!({
        "log": {
            "loglevel": "warning"
        },
        "api": {
            "tag": "api",
            "services": ["StatsService"]
        },
        "stats": {},
        "policy": {
            "system": {
                "statsInboundUplink": true,
                "statsInboundDownlink": true
            }
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "rules": routing_rules
        }
    }))
}

pub fn generate_inbound(rule: &ProxyRule, tag: &str) -> Value {
    match rule.inbound.protocol {
        InboundProtocol::Socks => {
            let mut settings = json!({
                "auth": "noauth",
                "udp": false
            });

            if let Some(auth) = &rule.inbound.auth {
                settings = json!({
                    "auth": "password",
                    "udp": false,
                    "users": [{
                        "user": auth.username,
                        "pass": auth.password,
                    }]
                });
            }

            json!({
                "tag": tag,
                "protocol": "socks",
                "listen": rule.inbound.listen,
                "port": rule.inbound.port,
                "settings": settings,
            })
        }
        InboundProtocol::Http => {
            let users = rule
                .inbound
                .auth
                .as_ref()
                .map(|auth| {
                    json!([{
                        "user": auth.username,
                        "pass": auth.password,
                    }])
                })
                .unwrap_or_else(|| json!([]));

            json!({
                "tag": tag,
                "protocol": "http",
                "listen": rule.inbound.listen,
                "port": rule.inbound.port,
                "settings": {
                    "users": users
                },
            })
        }
    }
}

pub fn generate_outbound(rule: &ProxyRule, tag: &str) -> Value {
    match &rule.outbound {
        OutboundConfig::Socks(config) => generate_socks_outbound(config, tag),
        OutboundConfig::Vless(config) => generate_vless_outbound(config, tag),
        OutboundConfig::Shadowsocks(config) => generate_shadowsocks_outbound(config, tag),
        OutboundConfig::Trojan(config) => generate_trojan_outbound(config, tag),
    }
}

pub fn generate_trojan_outbound(config: &TrojanOutboundConfig, tag: &str) -> Value {
    let mut server = json!({
        "address": config.address,
        "port": config.port,
        "password": config.password,
    });
    if let Some(email) = &config.email {
        server["email"] = json!(email);
    }
    if let Some(level) = config.level {
        server["level"] = json!(level);
    }

    let mut outbound = json!({
        "tag": tag,
        "protocol": "trojan",
        "settings": {
            "servers": [server]
        },
    });

    let network = match config.transport.kind {
        TrojanTransportKind::Tcp => "tcp",
        TrojanTransportKind::Ws => "ws",
    };

    let mut stream_settings = json!({
        "network": network,
    });

    if config.transport.kind == TrojanTransportKind::Ws {
        let mut ws_settings = json!({});
        if let Some(path) = &config.transport.path {
            ws_settings["path"] = json!(path);
        }
        if let Some(host) = &config.transport.host {
            ws_settings["headers"] = json!({
                "Host": host
            });
        }
        stream_settings["wsSettings"] = ws_settings;
    }

    if let Some(tls) = &config.tls {
        stream_settings["security"] = json!("tls");
        let mut tls_settings = json!({});
        if let Some(server_name) = tls.server_name.as_deref().filter(|value| !value.is_empty()) {
            tls_settings["serverName"] = json!(server_name);
        }
        if let Some(fingerprint) = tls.fingerprint.as_deref().filter(|value| !value.is_empty()) {
            tls_settings["fingerprint"] = json!(fingerprint);
        }
        if let Some(allow_insecure) = tls.allow_insecure {
            tls_settings["allowInsecure"] = json!(allow_insecure);
        }
        stream_settings["tlsSettings"] = tls_settings;
        outbound["streamSettings"] = stream_settings;
    } else if let Some(reality) = &config.reality {
        stream_settings["security"] = json!("reality");
        let mut reality_settings = json!({
            "publicKey": reality.public_key,
        });
        if let Some(server_name) = reality.server_name.as_deref().filter(|value| !value.is_empty()) {
            reality_settings["serverName"] = json!(server_name);
        }
        if let Some(fingerprint) = reality.fingerprint.as_deref().filter(|value| !value.is_empty()) {
            reality_settings["fingerprint"] = json!(fingerprint);
        }
        if let Some(short_id) = reality.short_id.as_deref().filter(|value| !value.is_empty()) {
            reality_settings["shortId"] = json!(short_id);
        }
        if let Some(spider_x) = reality.spider_x.as_deref().filter(|value| !value.is_empty()) {
            reality_settings["spiderX"] = json!(spider_x);
        }
        stream_settings["realitySettings"] = reality_settings;
        outbound["streamSettings"] = stream_settings;
    } else {
        if config.transport.kind == TrojanTransportKind::Ws {
            outbound["streamSettings"] = stream_settings;
        }
    }

    outbound
}

pub fn generate_socks_outbound(config: &SocksOutboundConfig, tag: &str) -> Value {
    let mut server = json!({
        "address": config.host,
        "port": config.port,
    });

    if let Some(auth) = &config.auth {
        if let Some(object) = server.as_object_mut() {
            object.insert(
                "users".to_string(),
                json!([{ "user": auth.username, "pass": auth.password }]),
            );
        }
    }

    json!({
        "tag": tag,
        "protocol": "socks",
        "settings": {
            "servers": [server]
        },
    })
}

pub fn generate_vless_outbound(config: &VlessOutboundConfig, tag: &str) -> Value {
    let mut settings = json!({
        "address": config.address,
        "port": config.port,
        "id": config.id,
        "encryption": config.encryption,
    });
    if let Some(flow) = config.flow.as_deref().filter(|flow| !flow.is_empty()) {
        settings["flow"] = json!(flow);
    }
    if let Some(level) = config.level {
        settings["level"] = json!(level);
    }

    let mut outbound = json!({
        "tag": tag,
        "protocol": "vless",
        "settings": settings,
    });

    let network = match config.transport.kind {
        VlessTransportKind::Tcp => "tcp",
        VlessTransportKind::Ws => "ws",
    };

    let mut stream_settings = json!({
        "network": network,
    });

    if config.transport.kind == VlessTransportKind::Ws {
        let mut ws_settings = json!({});
        if let Some(path) = &config.transport.path {
            ws_settings["path"] = json!(path);
        }
        if let Some(host) = &config.transport.host {
            ws_settings["headers"] = json!({
                "Host": host
            });
        }
        stream_settings["wsSettings"] = ws_settings;
    }

    if let Some(tls) = &config.tls {
        stream_settings["security"] = json!("tls");
        let mut tls_settings = json!({});
        if let Some(server_name) = tls.server_name.as_deref().filter(|value| !value.is_empty()) {
            tls_settings["serverName"] = json!(server_name);
        }
        if let Some(fingerprint) = tls.fingerprint.as_deref().filter(|value| !value.is_empty()) {
            tls_settings["fingerprint"] = json!(fingerprint);
        }
        if let Some(allow_insecure) = tls.allow_insecure {
            tls_settings["allowInsecure"] = json!(allow_insecure);
        }
        stream_settings["tlsSettings"] = tls_settings;
        outbound["streamSettings"] = stream_settings;
    } else if let Some(reality) = &config.reality {
        stream_settings["security"] = json!("reality");
        let mut reality_settings = json!({
            "publicKey": reality.public_key,
        });
        if let Some(server_name) = reality.server_name.as_deref().filter(|value| !value.is_empty()) {
            reality_settings["serverName"] = json!(server_name);
        }
        if let Some(fingerprint) = reality.fingerprint.as_deref().filter(|value| !value.is_empty()) {
            reality_settings["fingerprint"] = json!(fingerprint);
        }
        if let Some(short_id) = reality.short_id.as_deref().filter(|value| !value.is_empty()) {
            reality_settings["shortId"] = json!(short_id);
        }
        if let Some(spider_x) = reality.spider_x.as_deref().filter(|value| !value.is_empty()) {
            reality_settings["spiderX"] = json!(spider_x);
        }
        stream_settings["realitySettings"] = reality_settings;
        outbound["streamSettings"] = stream_settings;
    } else {
        if config.transport.kind == VlessTransportKind::Ws {
            outbound["streamSettings"] = stream_settings;
        }
    }

    outbound
}

pub fn generate_shadowsocks_outbound(config: &ShadowsocksOutboundConfig, tag: &str) -> Value {
    let mut settings = json!({
        "address": config.address,
        "port": config.port,
        "method": config.method,
        "password": config.password,
    });
    if config.uot {
        settings["uot"] = json!(true);
        if let Some(version) = config.uot_version {
            settings["UoTVersion"] = json!(version);
        }
    }

    json!({
        "tag": tag,
        "protocol": "shadowsocks",
        "settings": settings,
    })
}

pub fn inbound_tag(rule_id: &str) -> String {
    format!("inbound-{rule_id}")
}

pub fn outbound_tag(rule_id: &str) -> String {
    format!("outbound-{rule_id}")
}
