pub mod models;
pub mod utils;
pub mod process;
pub mod config;
pub mod parser;
pub mod ip_check;
pub mod commands;

pub use models::{
    AppState, AuthConfig, IpCheckResult, OutboundConfig,
    ShadowsocksOutboundConfig, SocksOutboundConfig, VlessOutboundConfig,
    VlessRealityConfig, VlessTlsConfig, VlessTransportConfig, VlessTransportKind,
    TrojanOutboundConfig, TrojanTlsConfig, TrojanRealityConfig, TrojanTransportConfig, TrojanTransportKind,
    ListenerRule, ProxyNode, ProxyGroup, SCHEMA_VERSION,
};
pub use parser::{parse_socks_url, parse_outbound_url_value};
pub use utils::{duplicate_port_validation, DEFAULT_LISTEN_ADDRESS};
pub use config::generate_config_value;

use crate::process::AppRuntimeState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppRuntimeState::default())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::load_app_state,
            commands::save_app_state,
            commands::save_and_apply_app_state,
            commands::add_rule,
            commands::duplicate_rule,
            commands::update_rule,
            commands::set_rule_enabled,
            commands::remove_rule,
            commands::check_rule_ip,
            commands::check_rules_ip_batch,
            commands::delete_rule,
            commands::add_proxy_node,
            commands::update_proxy_node,
            commands::analyze_proxy_deletion,
            commands::delete_proxy_node_safe,
            commands::add_proxy_group,
            commands::update_proxy_group,
            commands::analyze_proxy_group_deletion,
            commands::delete_proxy_group_safe,
            commands::parse_outbound_url,
            commands::parse_socks_outbound_url,
            commands::parse_socks_proxy_url,
            commands::generate_mihomo_config,
            commands::write_mihomo_config,
            commands::validate_mihomo_binary,
            commands::get_mihomo_version,
            commands::check_port_available,
            commands::validate_rule_ports,
            commands::get_runtime_paths,
            commands::get_runtime_status,
            commands::get_mihomo_status,
            commands::start_mihomo,
            commands::stop_mihomo,
            commands::restart_mihomo,
            commands::query_mihomo_stats
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                use tauri::Manager;
                if let Some(runtime_state) = app_handle.try_state::<AppRuntimeState>() {
                    if let Ok(mut manager) = runtime_state.process.lock() {
                        let _ = manager.stop();
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_state_with_socks(id: &str, rule_port: u16) -> AppState {
        let proxy_id = format!("proxy-{}", id);
        let group_id = format!("group-{}", id);
        let proxy_name = format!("Proxy-{}", id);
        let group_name = format!("Group-{}", id);

        let proxy = ProxyNode {
            id: proxy_id,
            name: proxy_name.clone(),
            config: OutboundConfig::Socks(SocksOutboundConfig {
                host: "proxy.example".to_string(),
                port: 1080,
                auth: None,
            }),
        };

        let group = ProxyGroup {
            id: group_id.clone(),
            name: group_name,
            group_type: "select".to_string(),
            proxies: vec![proxy_name],
        };

        let rule = ListenerRule {
            id: id.to_string(),
            name: "Test rule".to_string(),
            listen: DEFAULT_LISTEN_ADDRESS.to_string(),
            port: rule_port,
            inbound_type: "mixed".to_string(),
            group_id,
            enabled: true,
            ip_check: None,
        };

        AppState {
            schema_version: SCHEMA_VERSION,
            proxies: vec![proxy],
            groups: vec![group],
            rules: vec![rule],
        }
    }

    #[test]
    fn parses_socks_url_without_auth() {
        let result = parse_socks_url("socks5://proxy.example:1080").expect("valid SOCKS URL");

        let OutboundConfig::Socks(outbound) = result.outbound else {
            panic!("expected SOCKS outbound");
        };
        assert_eq!(outbound.host, "proxy.example");
        assert_eq!(outbound.port, 1080);
        assert_eq!(outbound.auth, None);
    }

    #[test]
    fn parses_socks_url_with_auth() {
        let result = parse_socks_url("socks://alice:secret@proxy.example:1080")
            .expect("valid SOCKS URL with auth");

        let OutboundConfig::Socks(outbound) = result.outbound else {
            panic!("expected SOCKS outbound");
        };
        assert_eq!(outbound.host, "proxy.example");
        assert_eq!(outbound.port, 1080);
        assert_eq!(
            outbound.auth,
            Some(AuthConfig {
                username: "alice".to_string(),
                password: "secret".to_string(),
            })
        );
    }

    #[test]
    fn rejects_unsupported_proxy_url_scheme() {
        let error = parse_socks_url("http://proxy.example:8080").expect_err("unsupported scheme");
        assert!(error.contains("Only socks:// and socks5://"));
    }

    #[test]
    fn parses_vless_tcp_tls_url() {
        let result = parse_outbound_url_value("vless://5783a3e7-e373-51cd-8642-c83782b807c5@example.com:443?encryption=none&type=tcp&security=tls&sni=example.com&fp=chrome#Example")
            .expect("valid VLESS URL");

        assert_eq!(result.display_name, Some("Example".to_string()));
        let OutboundConfig::Vless(outbound) = result.outbound else {
            panic!("expected VLESS outbound");
        };
        assert_eq!(outbound.address, "example.com");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.encryption, "none");
        assert_eq!(
            outbound.tls.expect("tls").server_name,
            Some("example.com".to_string())
        );
    }

    #[test]
    fn parses_vless_reality_url() {
        let result = parse_outbound_url_value("vless://5783a3e7-e373-51cd-8642-c83782b807c5@example.com:443?encryption=none&type=tcp&security=reality&pbk=key&sid=short&fp=chrome#Reality")
            .expect("valid VLESS REALITY URL");

        assert_eq!(result.display_name, Some("Reality".to_string()));
        let OutboundConfig::Vless(outbound) = result.outbound else {
            panic!("expected VLESS outbound");
        };
        let reality = outbound.reality.expect("reality");
        assert_eq!(reality.public_key, "key");
        assert_eq!(reality.short_id, Some("short".to_string()));
        assert_eq!(reality.fingerprint, Some("chrome".to_string()));
    }

    #[test]
    fn parses_vless_reality_url_with_packet_encoding() {
        let result = parse_outbound_url_value("vless://f96a3fb2-d2da-4ea3-958e-6c9bb15495bb@19b2d-8dc30k.bz.s1-h2a89c.gov-oss.cn:48778?security=reality&type=tcp&packetEncoding=none&sni=itunes.apple.com&fp=chrome&flow=xtls-rprx-vision&sid=2f787a31&pbk=AOV9rSWpGdrZXUpQyCtrETc2PXLsngTo3owYMysZRkw#Vless.Hong%20Kong%2001")
            .expect("valid VLESS REALITY URL with packetEncoding");

        assert_eq!(result.display_name, Some("Vless.Hong Kong 01".to_string()));
        assert!(result.warnings.is_empty());
        let OutboundConfig::Vless(outbound) = result.outbound else {
            panic!("expected VLESS outbound");
        };
        assert_eq!(outbound.address, "19b2d-8dc30k.bz.s1-h2a89c.gov-oss.cn");
        assert_eq!(outbound.port, 48778);
        assert_eq!(outbound.flow, Some("xtls-rprx-vision".to_string()));
        let reality = outbound.reality.expect("reality");
        assert_eq!(reality.server_name, Some("itunes.apple.com".to_string()));
        assert_eq!(reality.short_id, Some("2f787a31".to_string()));
        assert_eq!(
            reality.public_key,
            "AOV9rSWpGdrZXUpQyCtrETc2PXLsngTo3owYMysZRkw"
        );
    }

    #[test]
    fn parses_vless_ws_url() {
        let result = parse_outbound_url_value(
            "vless://5783a3e7-e373-51cd-8642-c83782b807c5@example.com:443?type=ws&path=%2Fwebsocket&host=ws.example.com",
        )
        .expect("valid VLESS ws URL");

        let OutboundConfig::Vless(outbound) = result.outbound else {
            panic!("expected VLESS outbound");
        };
        assert_eq!(outbound.address, "example.com");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.transport.kind, VlessTransportKind::Ws);
        assert_eq!(outbound.transport.path, Some("/websocket".to_string()));
        assert_eq!(outbound.transport.host, Some("ws.example.com".to_string()));
    }

    #[test]
    fn parses_shadowsocks_plain_url() {
        let result = parse_outbound_url_value(
            "ss://aes-256-gcm:secret@example.com:8388?uot=1&uotVersion=2#SS",
        )
        .expect("valid Shadowsocks URL");

        assert_eq!(result.display_name, Some("SS".to_string()));
        let OutboundConfig::Shadowsocks(outbound) = result.outbound else {
            panic!("expected Shadowsocks outbound");
        };
        assert_eq!(outbound.address, "example.com");
        assert_eq!(outbound.port, 8388);
        assert_eq!(outbound.method, "aes-256-gcm");
        assert_eq!(outbound.password, "secret");
        assert!(outbound.uot);
        assert_eq!(outbound.uot_version, Some(2));
    }

    #[test]
    fn parses_shadowsocks_base64_url() {
        let result = parse_outbound_url_value(
            "ss://YWVzLTI1Ni1nY206c2VjcmV0QGV4YW1wbGUuY29tOjgzODg#Example",
        )
        .expect("valid base64 Shadowsocks URL");

        let OutboundConfig::Shadowsocks(outbound) = result.outbound else {
            panic!("expected Shadowsocks outbound");
        };
        assert_eq!(outbound.address, "example.com");
        assert_eq!(outbound.port, 8388);
        assert_eq!(outbound.method, "aes-256-gcm");
        assert_eq!(outbound.password, "secret");
    }

    #[test]
    fn rejects_unsafe_shadowsocks_method() {
        let error = parse_outbound_url_value("ss://none:secret@example.com:8388")
            .expect_err("unsafe Shadowsocks method");
        assert!(error.contains("unsafe Shadowsocks method"));
    }

    #[test]
    fn detects_duplicate_local_ports() {
        let state1 = sample_state_with_socks("one", 50001);
        let state2 = sample_state_with_socks("two", 50001);
        let rules = vec![state1.rules[0].clone(), state2.rules[0].clone()];
        let validation = duplicate_port_validation(&rules);

        assert!(validation.has_duplicate_ports);
        assert_eq!(validation.duplicate_ports, vec![50001]);
    }

    #[test]
    fn generated_config_omits_disabled_rules() {
        let mut state = sample_state_with_socks("rule", 50001);
        let mut disabled_rule = state.rules[0].clone();
        disabled_rule.id = "disabled-rule".to_string();
        disabled_rule.port = 50002;
        disabled_rule.enabled = false;
        state.rules.push(disabled_rule);

        let config = generate_config_value(&state).expect("config generation");

        assert_eq!(config["listeners"].as_array().expect("listeners").len(), 1);
        assert_eq!(config["listeners"][0]["name"], "listener-rule");
    }

    #[test]
    fn generated_config_uses_stable_tags_and_expected_shape() {
        let mut state = sample_state_with_socks("socks-rule", 50001);

        let proxy_id = "proxy-http".to_string();
        let group_id = "group-http".to_string();
        let proxy_name = "Proxy-Http".to_string();
        let group_name = "Group-Http".to_string();

        let proxy = ProxyNode {
            id: proxy_id,
            name: proxy_name.clone(),
            config: OutboundConfig::Socks(SocksOutboundConfig {
                host: "proxy.example".to_string(),
                port: 1080,
                auth: Some(AuthConfig {
                    username: "upstream".to_string(),
                    password: "secret".to_string(),
                }),
            }),
        };

        let group = ProxyGroup {
            id: group_id.clone(),
            name: group_name,
            group_type: "select".to_string(),
            proxies: vec![proxy_name],
        };

        let rule = ListenerRule {
            id: "http-rule".to_string(),
            name: "HTTP Rule".to_string(),
            listen: DEFAULT_LISTEN_ADDRESS.to_string(),
            port: 50002,
            inbound_type: "http".to_string(),
            group_id,
            enabled: true,
            ip_check: None,
        };

        state.proxies.push(proxy);
        state.groups.push(group);
        state.rules.push(rule);

        let config = generate_config_value(&state).expect("config generation");

        assert_eq!(config["listeners"].as_array().expect("listeners").len(), 2);
        assert_eq!(config["proxies"].as_array().expect("proxies").len(), 2);
        assert_eq!(config["proxy-groups"].as_array().expect("groups").len(), 2);

        assert_eq!(config["listeners"][0]["name"], "listener-socks-rule");
        assert_eq!(config["listeners"][1]["name"], "listener-http-rule");
        assert_eq!(config["listeners"][1]["type"], "http");

        assert_eq!(config["proxies"][1]["name"], "Proxy-Http");
        assert_eq!(config["proxies"][1]["type"], "socks");
        assert_eq!(config["proxies"][1]["username"], "upstream");
        assert_eq!(config["proxies"][1]["password"], "secret");
    }

    #[test]
    fn migrates_legacy_state_to_v3() {
        let state = crate::models::deserialize_app_state_value(json!({
            "schemaVersion": 1,
            "rules": [{
                "id": "old-rule",
                "remark": "Old",
                "enabled": true,
                "inbound": {
                    "protocol": "socks",
                    "listen": "127.0.0.1",
                    "port": 50001,
                    "auth": null
                },
                "outbound": {
                    "protocol": "socks",
                    "host": "proxy.example",
                    "port": 1080,
                    "auth": null
                },
                "ipCheck": null
            }]
        }))
        .expect("v1 migration");

        assert_eq!(state.schema_version, SCHEMA_VERSION);
        assert_eq!(state.rules.len(), 1);
        assert_eq!(state.groups.len(), 1);
        assert_eq!(state.proxies.len(), 1);

        assert_eq!(state.proxies[0].name, "Old-Node");
        assert_eq!(state.groups[0].name, "Old-Group");
        assert_eq!(state.rules[0].name, "Old");
        assert_eq!(state.rules[0].inbound_type, "mixed");

        let OutboundConfig::Socks(outbound) = &state.proxies[0].config else {
            panic!("expected migrated SOCKS outbound");
        };
        assert_eq!(outbound.host, "proxy.example");
    }

    #[test]
    fn generates_vless_tls_outbound() {
        let mut state = sample_state_with_socks("vless-rule", 50001);
        state.proxies[0].config = OutboundConfig::Vless(VlessOutboundConfig {
            address: "vless.example".to_string(),
            port: 443,
            id: "5783a3e7-e373-51cd-8642-c83782b807c5".to_string(),
            encryption: "none".to_string(),
            flow: Some("xtls-rprx-vision".to_string()),
            level: Some(1),
            transport: VlessTransportConfig {
                kind: VlessTransportKind::Tcp,
                path: None,
                host: None,
            },
            tls: Some(VlessTlsConfig {
                server_name: Some("vless.example".to_string()),
                fingerprint: Some("chrome".to_string()),
                allow_insecure: None,
            }),
            reality: None,
            import_source: None,
        });

        let config = generate_config_value(&state).expect("config generation");

        assert_eq!(config["proxies"][0]["type"], "vless");
        assert_eq!(config["proxies"][0]["server"], "vless.example");
        assert_eq!(config["proxies"][0]["uuid"], "5783a3e7-e373-51cd-8642-c83782b807c5");
        assert_eq!(config["proxies"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(config["proxies"][0]["network"], "tcp");
        assert_eq!(config["proxies"][0]["tls"], true);
        assert_eq!(config["proxies"][0]["servername"], "vless.example");
        assert_eq!(config["proxies"][0]["client-fingerprint"], "chrome");
    }

    #[test]
    fn generates_shadowsocks_outbound() {
        let mut state = sample_state_with_socks("ss-rule", 50001);
        state.proxies[0].config = OutboundConfig::Shadowsocks(ShadowsocksOutboundConfig {
            address: "ss.example".to_string(),
            port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "secret".to_string(),
            uot: true,
            uot_version: Some(2),
            import_source: None,
        });

        let config = generate_config_value(&state).expect("config generation");

        assert_eq!(config["proxies"][0]["type"], "ss");
        assert_eq!(config["proxies"][0]["server"], "ss.example");
        assert_eq!(config["proxies"][0]["cipher"], "aes-256-gcm");
        assert_eq!(config["proxies"][0]["password"], "secret");
        assert_eq!(config["proxies"][0]["udp"], true);
    }

    #[test]
    fn rejects_shadowsocks_plugin_links() {
        let error = parse_outbound_url_value(
            "ss://aes-256-gcm:secret@example.com:8388?plugin=v2ray-plugin",
        )
        .expect_err("unsupported plugin");

        assert!(error.contains("plugin/obfs"));
    }

    #[test]
    fn parses_trojan_tls_url() {
        let result = parse_outbound_url_value(
            "trojan://password123@trojan.example:443?security=tls&sni=trojan.example&fp=chrome&email=love@xray.com#TrojanExample"
        )
        .expect("valid Trojan URL");

        assert_eq!(result.display_name, Some("TrojanExample".to_string()));
        let OutboundConfig::Trojan(outbound) = result.outbound else {
            panic!("expected Trojan outbound");
        };
        assert_eq!(outbound.address, "trojan.example");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.password, "password123");
        assert_eq!(outbound.email, Some("love@xray.com".to_string()));
        let tls = outbound.tls.expect("tls");
        assert_eq!(tls.server_name, Some("trojan.example".to_string()));
        assert_eq!(tls.fingerprint, Some("chrome".to_string()));
    }

    #[test]
    fn parses_trojan_reality_url() {
        let result = parse_outbound_url_value(
            "trojan://password123@trojan.example:443?security=reality&pbk=pubkey&sid=shortid&fp=chrome#RealityTrojan"
        )
        .expect("valid Trojan Reality URL");

        assert_eq!(result.display_name, Some("RealityTrojan".to_string()));
        let OutboundConfig::Trojan(outbound) = result.outbound else {
            panic!("expected Trojan outbound");
        };
        let reality = outbound.reality.expect("reality");
        assert_eq!(reality.public_key, "pubkey");
        assert_eq!(reality.short_id, Some("shortid".to_string()));
        assert_eq!(reality.fingerprint, Some("chrome".to_string()));
    }

    #[test]
    fn parses_trojan_with_special_characters_in_password() {
        let result = parse_outbound_url_value(
            "trojan://8r<[9'l6hAO#8ZQi@161.35.22.108:2087?sni=Koma-YT.PAGeS.Dev&type=ws&path=%2FtrTelegram%F0%9F%87%A8%F0%9F%87%B3%20%40WangCai2&fp=chrome#%F0%9F%8F%B4%E2%80%8D%E2%98%A0_289"
        )
        .expect("valid Trojan URL with special characters in password");

        let OutboundConfig::Trojan(outbound) = result.outbound else {
            panic!("expected Trojan outbound");
        };
        assert_eq!(outbound.address, "161.35.22.108");
        assert_eq!(outbound.port, 2087);
        assert_eq!(outbound.password, "8r<[9'l6hAO#8ZQi");
        assert_eq!(outbound.transport.kind, TrojanTransportKind::Ws);
    }

    #[test]
    fn generates_trojan_tls_outbound() {
        let mut state = sample_state_with_socks("trojan-rule", 50001);
        state.proxies[0].config = OutboundConfig::Trojan(TrojanOutboundConfig {
            address: "trojan.example".to_string(),
            port: 443,
            password: "password123".to_string(),
            email: Some("love@xray.com".to_string()),
            level: Some(2),
            transport: TrojanTransportConfig {
                kind: TrojanTransportKind::Tcp,
                path: None,
                host: None,
            },
            tls: Some(TrojanTlsConfig {
                server_name: Some("trojan.example".to_string()),
                fingerprint: Some("chrome".to_string()),
                allow_insecure: None,
            }),
            reality: None,
            import_source: None,
        });

        let config = generate_config_value(&state).expect("config generation");

        assert_eq!(config["proxies"][0]["type"], "trojan");
        assert_eq!(config["proxies"][0]["server"], "trojan.example");
        assert_eq!(config["proxies"][0]["password"], "password123");
        assert_eq!(config["proxies"][0]["network"], "tcp");
        assert_eq!(config["proxies"][0]["tls"], true);
        assert_eq!(config["proxies"][0]["servername"], "trojan.example");
    }
}
