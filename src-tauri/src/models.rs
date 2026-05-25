use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashSet;

pub const SCHEMA_VERSION: u32 = 3;
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
    pub proxies: Vec<ProxyNode>,
    pub groups: Vec<ProxyGroup>,
    pub rules: Vec<ListenerRule>,
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
            proxies: Vec::new(),
            groups: Vec::new(),
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
            migrate_v2_to_v3(v1)
        }
        2 => {
            let v2 = serde_json::from_value::<AppStateV2>(value)
                .map_err(|error| format!("Failed to parse v2 app state JSON: {error}"))?;
            migrate_v2_to_v3(v2)
        }
        3 => serde_json::from_value::<AppStateV3>(value)
            .map(|state| state.into_app_state())
            .map_err(|error| format!("Failed to parse v3 app state JSON: {error}")),
        version => Err(format!("Unsupported app state schema version {version}")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppStateV3 {
    schema_version: u32,
    proxies: Vec<ProxyNode>,
    groups: Vec<ProxyGroup>,
    rules: Vec<ListenerRule>,
}

impl AppStateV3 {
    fn into_app_state(self) -> AppState {
        AppState {
            schema_version: self.schema_version,
            proxies: self.proxies,
            groups: self.groups,
            rules: self.rules,
        }
    }
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
    inbound: InboundConfig,
    outbound: OutboundConfig,
    #[serde(default)]
    ip_check: Option<IpCheckResult>,
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
    inbound: InboundConfig,
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

fn migrate_v2_to_v3(v2_state: AppStateV2) -> CommandResult<AppState> {
    let mut proxies = Vec::new();
    let mut groups = Vec::new();
    let mut rules = Vec::new();

    for rule in v2_state.rules {
        let proxy_id = format!("proxy-{}", rule.id);
        let group_id = format!("group-{}", rule.id);
        
        let proxy_name = if rule.remark.trim().is_empty() {
            format!("Node-{}", rule.id)
        } else {
            format!("{}-Node", rule.remark.trim())
        };

        proxies.push(ProxyNode {
            id: proxy_id.clone(),
            name: proxy_name.clone(),
            config: rule.outbound,
        });

        let group_name = if rule.remark.trim().is_empty() {
            format!("Group-{}", rule.id)
        } else {
            format!("{}-Group", rule.remark.trim())
        };

        groups.push(ProxyGroup {
            id: group_id.clone(),
            name: group_name.clone(),
            group_type: "select".to_string(),
            proxies: vec![proxy_name],
        });

        rules.push(ListenerRule {
            id: rule.id,
            name: rule.remark,
            listen: rule.inbound.listen,
            port: rule.inbound.port,
            inbound_type: "mixed".to_string(),
            group_id,
            enabled: rule.enabled,
            ip_check: rule.ip_check,
        });
    }

    Ok(AppState {
        schema_version: 3,
        proxies,
        groups,
        rules,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyNode {
    pub id: String,
    pub name: String,
    pub config: OutboundConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyGroup {
    pub id: String,
    pub name: String,
    pub group_type: String, // "select"
    pub proxies: Vec<String>, // list of proxy name strings
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListenerRule {
    pub id: String,
    pub name: String,
    pub listen: String,
    pub port: u16,
    pub inbound_type: String, // "mixed" | "socks" | "http"
    pub group_id: String, // linked group_id
    pub enabled: bool,
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

    validate_listener_rules(&state.rules)?;
    validate_proxies(&state.proxies)?;
    validate_groups(&state.groups, &state.proxies)?;

    Ok(())
}

pub fn validate_listener_rules(rules: &[ListenerRule]) -> CommandResult<()> {
    let mut ids = HashSet::new();
    for rule in rules {
        if rule.id.trim().is_empty() {
            return Err("Rule id cannot be empty".to_string());
        }
        if !ids.insert(rule.id.as_str()) {
            return Err(format!("Duplicate rule id: {}", rule.id));
        }
        if rule.name.trim().is_empty() {
            return Err("Rule name cannot be empty".to_string());
        }
        if rule.listen.trim().is_empty() {
            return Err(format!("Rule '{}' has an empty listen address", rule.id));
        }
        if rule.port < 1 {
            return Err(format!("Rule '{}' has an invalid port", rule.id));
        }
    }
    Ok(())
}

pub fn validate_proxies(proxies: &[ProxyNode]) -> CommandResult<()> {
    let mut names = HashSet::new();
    for proxy in proxies {
        if proxy.id.trim().is_empty() {
            return Err("Proxy id cannot be empty".to_string());
        }
        if proxy.name.trim().is_empty() {
            return Err("Proxy name cannot be empty".to_string());
        }
        if !names.insert(proxy.name.as_str()) {
            return Err(format!("Duplicate proxy name: {}", proxy.name));
        }
        validate_outbound_config(&proxy.id, &proxy.config)?;
    }
    Ok(())
}

pub fn validate_groups(groups: &[ProxyGroup], proxies: &[ProxyNode]) -> CommandResult<()> {
    let mut names = HashSet::new();
    let proxy_names: HashSet<&str> = proxies.iter().map(|p| p.name.as_str()).collect();

    for group in groups {
        if group.id.trim().is_empty() {
            return Err("Group id cannot be empty".to_string());
        }
        if group.name.trim().is_empty() {
            return Err("Group name cannot be empty".to_string());
        }
        if !names.insert(group.name.as_str()) {
            return Err(format!("Duplicate group name: {}", group.name));
        }
        if group.proxies.is_empty() {
            return Err(format!("Group '{}' must contain at least one proxy", group.name));
        }
        for member in &group.proxies {
            if member != "DIRECT" && member != "REJECT" && !proxy_names.contains(member.as_str()) {
                return Err(format!(
                    "Group '{}' refers to non-existent proxy '{}'",
                    group.name, member
                ));
            }
        }
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
