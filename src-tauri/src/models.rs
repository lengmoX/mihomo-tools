use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashSet;

pub const SCHEMA_VERSION: u32 = 4;
pub const SUPPORTED_VLESS_FLOWS: &[&str] = &["xtls-rprx-vision", "xtls-rprx-vision-udp443"];
pub const SUPPORTED_SHADOWSOCKS_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-256-gcm",
    "aes-128-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
];

pub type CommandResult<T> = Result<T, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimePaths {
    pub runtime_root: std::path::PathBuf,
    pub data_dir: std::path::PathBuf,
    pub app_state_path: std::path::PathBuf,
    pub generated_config_path: std::path::PathBuf,
    pub mihomo_binary_path: std::path::PathBuf,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppState {
    pub schema_version: u32,
    pub rules: Vec<ProxyRule>,
}

impl<'de> Deserialize<'de> for AppState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        deserialize_app_state_value(value).map_err(serde::de::Error::custom)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            rules: Vec::new(),
        }
    }
}

pub fn deserialize_app_state_value(value: Value) -> CommandResult<AppState> {
    let schema_version = value
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| "App state schemaVersion is required".to_string())?;

    match schema_version {
        1 => {
            let v1 = migrate_v1_app_state(value)?;
            migrate_v2_to_v4(v1)
        }
        2 => {
            let v2 = serde_json::from_value::<AppStateV2>(value)
                .map_err(|error| format!("Failed to parse v2 app state JSON: {error}"))?;
            migrate_v2_to_v4(v2)
        }
        3 => {
            let v3 = serde_json::from_value::<AppStateV3>(value)
                .map_err(|error| format!("Failed to parse v3 app state JSON: {error}"))?;
            migrate_v3_to_v4(v3)
        }
        4 => serde_json::from_value::<AppStateV4>(value)
            .map(|state| state.into_app_state())
            .map_err(|error| format!("Failed to parse v4 app state JSON: {error}")),
        version => Err(format!("Unsupported app state schema version {version}")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppStateV4 {
    schema_version: u32,
    rules: Vec<ProxyRule>,
}

impl AppStateV4 {
    fn into_app_state(self) -> AppState {
        AppState {
            schema_version: self.schema_version,
            rules: self.rules,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppStateV3 {
    rules: Vec<ListenerRuleV3>,
    groups: Vec<ProxyGroupV3>,
    proxies: Vec<ProxyNodeV3>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListenerRuleV3 {
    id: String,
    name: String,
    listen: String,
    port: u16,
    inbound_type: String,
    group_id: String,
    enabled: bool,
    #[serde(default)]
    ip_check: Option<IpCheckResult>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct ProxyGroupV3 {
    id: String,
    name: String,
    proxies: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyNodeV3 {
    name: String,
    config: OutboundConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppStateV2 {
    rules: Vec<ProxyRuleV2>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyRuleV2 {
    id: String,
    remark: String,
    enabled: bool,
    inbound: InboundConfigV2,
    outbound: OutboundConfig,
    #[serde(default)]
    ip_check: Option<IpCheckResult>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InboundConfigV2 {
    protocol: InboundProtocolV2,
    listen: String,
    port: u16,
    auth: Option<AuthConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum InboundProtocolV2 {
    Socks,
    Http,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppStateV1 {
    rules: Vec<ProxyRuleV1>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyRuleV1 {
    id: String,
    remark: String,
    enabled: bool,
    inbound: InboundConfigV2,
    outbound: SocksOutboundConfigV1,
    #[serde(default)]
    ip_check: Option<IpCheckResult>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SocksOutboundConfigV1 {
    host: String,
    port: u16,
    auth: Option<AuthConfig>,
}

fn migrate_v1_app_state(value: Value) -> CommandResult<AppStateV2> {
    let state = serde_json::from_value::<AppStateV1>(value)
        .map_err(|error| format!("Failed to parse v1 app state JSON: {error}"))?;
    Ok(AppStateV2 {
        rules: state
            .rules
            .into_iter()
            .map(|rule| ProxyRuleV2 {
                id: rule.id,
                remark: rule.remark,
                enabled: rule.enabled,
                inbound: rule.inbound,
                outbound: OutboundConfig::Socks(SocksOutboundConfig {
                    host: rule.outbound.host,
                    port: rule.outbound.port,
                    auth: rule.outbound.auth,
                }),
                ip_check: rule.ip_check,
            })
            .collect(),
    })
}

fn migrate_v2_to_v4(v2: AppStateV2) -> CommandResult<AppState> {
    let rules = v2
        .rules
        .into_iter()
        .map(|r| ProxyRule {
            id: r.id,
            remark: r.remark,
            enabled: r.enabled,
            inbound: InboundConfig {
                protocol: match r.inbound.protocol {
                    InboundProtocolV2::Socks => InboundProtocol::Socks,
                    InboundProtocolV2::Http => InboundProtocol::Http,
                },
                listen: r.inbound.listen,
                port: r.inbound.port,
                auth: r.inbound.auth,
            },
            outbound: r.outbound,
            ip_check: r.ip_check,
        })
        .collect();

    Ok(AppState {
        schema_version: 4,
        rules,
    })
}

fn migrate_v3_to_v4(v3: AppStateV3) -> CommandResult<AppState> {
    let mut rules = Vec::new();

    for rule in v3.rules {
        let mut matching_outbound = None;

        if let Some(group) = v3.groups.iter().find(|g| g.id == rule.group_id) {
            let proxy_name = group
                .proxies
                .iter()
                .find(|p| *p != "DIRECT" && *p != "REJECT" && *p != "fallback");

            if let Some(p_name) = proxy_name {
                if let Some(proxy_node) = v3.proxies.iter().find(|p| p.name == *p_name) {
                    matching_outbound = Some(proxy_node.config.clone());
                }
            }
        }

        let outbound = matching_outbound.unwrap_or_else(|| {
            OutboundConfig::Socks(SocksOutboundConfig {
                host: "127.0.0.1".to_string(),
                port: 1080,
                auth: None,
            })
        });

        let inbound_protocol = match rule.inbound_type.as_str() {
            "socks" => InboundProtocol::Socks,
            "http" => InboundProtocol::Http,
            _ => InboundProtocol::Mixed,
        };

        rules.push(ProxyRule {
            id: rule.id,
            remark: rule.name,
            enabled: rule.enabled,
            inbound: InboundConfig {
                protocol: inbound_protocol,
                listen: rule.listen,
                port: rule.port,
                auth: None,
            },
            outbound,
            ip_check: rule.ip_check,
        });
    }

    Ok(AppState {
        schema_version: 4,
        rules,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyRule {
    pub id: String,
    pub remark: String,
    pub enabled: bool,
    pub inbound: InboundConfig,
    pub outbound: OutboundConfig,
    #[serde(default)]
    pub ip_check: Option<IpCheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IpCheckResult {
    pub ip: String,
    pub country: Option<String>,
    pub checked_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpInfoResponse {
    pub ip: String,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InboundConfig {
    pub protocol: InboundProtocol,
    pub listen: String,
    pub port: u16,
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InboundProtocol {
    Mixed,
    Socks,
    Http,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum OutboundConfig {
    Socks(SocksOutboundConfig),
    Vless(VlessOutboundConfig),
    Shadowsocks(ShadowsocksOutboundConfig),
    Trojan(TrojanOutboundConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrojanOutboundConfig {
    pub address: String,
    pub port: u16,
    pub password: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub level: Option<u32>,
    pub transport: TrojanTransportConfig,
    pub tls: Option<TrojanTlsConfig>,
    pub reality: Option<TrojanRealityConfig>,
    #[serde(default)]
    pub import_source: Option<ImportSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrojanTransportConfig {
    pub kind: TrojanTransportKind,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TrojanTransportKind {
    Tcp,
    Ws,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrojanTlsConfig {
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub allow_insecure: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrojanRealityConfig {
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
    pub public_key: String,
    pub short_id: Option<String>,
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SocksOutboundConfig {
    pub host: String,
    pub port: u16,
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VlessOutboundConfig {
    pub address: String,
    pub port: u16,
    pub id: String,
    pub encryption: String,
    pub flow: Option<String>,
    #[serde(default)]
    pub level: Option<u32>,
    pub transport: VlessTransportConfig,
    pub tls: Option<VlessTlsConfig>,
    pub reality: Option<VlessRealityConfig>,
    #[serde(default)]
    pub import_source: Option<ImportSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VlessTransportConfig {
    pub kind: VlessTransportKind,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VlessTransportKind {
    Tcp,
    Ws,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VlessTlsConfig {
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub allow_insecure: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VlessRealityConfig {
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
    pub public_key: String,
    pub short_id: Option<String>,
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ShadowsocksOutboundConfig {
    pub address: String,
    pub port: u16,
    pub method: String,
    pub password: String,
    pub uot: bool,
    pub uot_version: Option<u8>,
    #[serde(default)]
    pub import_source: Option<ImportSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportSource {
    pub raw_url: String,
    pub imported_at: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParseOutboundUrlResult {
    pub outbound: OutboundConfig,
    pub display_name: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewRuleRequest {
    pub remark: Option<String>,
    pub inbound_protocol: Option<InboundProtocol>,
    pub inbound_listen: Option<String>,
    pub inbound_port: Option<u16>,
    pub inbound_auth: Option<AuthConfig>,
    pub outbound: OutboundConfig,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRuleRequest {
    pub id: String,
    pub remark: String,
    pub enabled: bool,
    pub inbound: InboundConfig,
    pub outbound: OutboundConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortValidation {
    pub has_duplicate_ports: bool,
    pub duplicate_ports: Vec<u16>,
    pub unavailable_ports: Vec<u16>,
    pub valid: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortAvailability {
    pub port: u16,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub running: bool,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyRulesResult {
    pub state: AppState,
    pub generated_config_path: std::path::PathBuf,
    pub restarted: bool,
    pub status: RuntimeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MihomoBinaryValidation {
    pub path: std::path::PathBuf,
    pub exists: bool,
    pub is_file: bool,
    pub valid: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MihomoVersionInfo {
    pub version: String,
    pub display_text: String,
}

pub fn validate_state(state: &AppState) -> CommandResult<()> {
    if state.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "Unsupported app state schema version {}",
            state.schema_version
        ));
    }

    validate_rules(&state.rules)?;

    Ok(())
}

pub fn validate_rules(rules: &[ProxyRule]) -> CommandResult<()> {
    let mut ids = HashSet::new();
    for rule in rules {
        if rule.id.trim().is_empty() {
            return Err("Rule id cannot be empty".to_string());
        }
        if !ids.insert(rule.id.as_str()) {
            return Err(format!("Duplicate rule id: {}", rule.id));
        }
        if rule.remark.trim().is_empty() {
            return Err("Rule remark cannot be empty".to_string());
        }
        if rule.inbound.listen.trim().is_empty() {
            return Err(format!("Rule '{}' has an empty listen address", rule.id));
        }
        if rule.inbound.port < 1 {
            return Err(format!("Rule '{}' has an invalid port", rule.id));
        }
        validate_outbound_config(&rule.id, &rule.outbound)?;
    }
    Ok(())
}

pub fn validate_outbound_config(proxy_id: &str, outbound: &OutboundConfig) -> CommandResult<()> {
    match outbound {
        OutboundConfig::Socks(config) => {
            validate_auth(config.auth.as_ref())?;
            if config.host.trim().is_empty() {
                return Err(format!("Proxy '{proxy_id}' has an empty Socks host"));
            }
        }
        OutboundConfig::Vless(config) => validate_vless_outbound(proxy_id, config)?,
        OutboundConfig::Shadowsocks(config) => validate_shadowsocks_outbound(proxy_id, config)?,
        OutboundConfig::Trojan(config) => validate_trojan_outbound(proxy_id, config)?,
    }
    Ok(())
}

pub fn validate_trojan_outbound(proxy_id: &str, config: &TrojanOutboundConfig) -> CommandResult<()> {
    if config.address.trim().is_empty() {
        return Err(format!("Proxy '{proxy_id}' has an empty Trojan address"));
    }
    if config.password.is_empty() {
        return Err(format!("Proxy '{proxy_id}' has an empty Trojan password"));
    }
    if config.tls.is_some() && config.reality.is_some() {
        return Err(format!(
            "Proxy '{proxy_id}' cannot enable both Trojan TLS and REALITY security"
        ));
    }
    if let Some(reality) = &config.reality {
        if reality.public_key.trim().is_empty() {
            return Err(format!("Proxy '{proxy_id}' has an empty REALITY public key"));
        }
    }
    Ok(())
}

pub fn validate_vless_outbound(proxy_id: &str, config: &VlessOutboundConfig) -> CommandResult<()> {
    if config.address.trim().is_empty() {
        return Err(format!("Proxy '{proxy_id}' has an empty VLESS address"));
    }
    if config.id.trim().is_empty() {
        return Err(format!("Proxy '{proxy_id}' has an empty VLESS id"));
    }
    if config.encryption.trim().is_empty() {
        return Err(format!(
            "Proxy '{proxy_id}' has an empty VLESS encryption value"
        ));
    }
    if let Some(flow) = config.flow.as_deref() {
        if !flow.is_empty() && !SUPPORTED_VLESS_FLOWS.contains(&flow) {
            return Err(format!(
                "Proxy '{proxy_id}' has an unsupported VLESS flow '{flow}'"
            ));
        }
    }
    if config.tls.is_some() && config.reality.is_some() {
        return Err(format!(
            "Proxy '{proxy_id}' cannot enable both VLESS TLS and REALITY security"
        ));
    }
    if let Some(reality) = &config.reality {
        if reality.public_key.trim().is_empty() {
            return Err(format!("Proxy '{proxy_id}' has an empty REALITY public key"));
        }
    }
    Ok(())
}

pub fn validate_shadowsocks_outbound(
    proxy_id: &str,
    config: &ShadowsocksOutboundConfig,
) -> CommandResult<()> {
    if config.address.trim().is_empty() {
        return Err(format!("Proxy '{proxy_id}' has an empty Shadowsocks address"));
    }
    if config.method.trim().is_empty() {
        return Err(format!("Proxy '{proxy_id}' has an empty Shadowsocks method"));
    }
    let method = config.method.trim().to_ascii_lowercase();
    if method == "none" || method == "plain" {
        return Err(format!(
            "Proxy '{proxy_id}' uses unsafe Shadowsocks method '{}'",
            config.method
        ));
    }
    if !SUPPORTED_SHADOWSOCKS_METHODS.contains(&method.as_str()) {
        return Err(format!(
            "Proxy '{proxy_id}' has an unsupported Shadowsocks method '{}'",
            config.method
        ));
    }
    if config.password.is_empty() {
        return Err(format!(
            "Proxy '{proxy_id}' has an empty Shadowsocks password"
        ));
    }
    if let Some(version) = config.uot_version {
        if version != 1 && version != 2 {
            return Err(format!(
                "Proxy '{proxy_id}' has an unsupported Shadowsocks UoT version {version}"
            ));
        }
        if !config.uot {
            return Err(format!(
                "Proxy '{proxy_id}' cannot set UoT version while UoT is disabled"
            ));
        }
    }
    Ok(())
}

pub fn validate_auth(auth: Option<&AuthConfig>) -> CommandResult<()> {
    if let Some(auth) = auth {
        if auth.username.is_empty() || auth.password.is_empty() {
            return Err("Authentication username and password are both required".to_string());
        }
    }
    Ok(())
}
