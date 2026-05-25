use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashSet;

pub const SCHEMA_VERSION: u32 = 2;
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
        1 => migrate_v1_app_state(value),
        2 => serde_json::from_value::<AppStateV2>(value)
            .map(|state| state.into_app_state())
            .map_err(|error| format!("Failed to parse v2 app state JSON: {error}")),
        version => Err(format!("Unsupported app state schema version {version}")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppStateV2 {
    schema_version: u32,
    rules: Vec<ProxyRule>,
}

impl AppStateV2 {
    fn into_app_state(self) -> AppState {
        AppState {
            schema_version: self.schema_version,
            rules: self.rules,
        }
    }
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

fn migrate_v1_app_state(value: Value) -> CommandResult<AppState> {
    let state = serde_json::from_value::<AppStateV1>(value)
        .map_err(|error| format!("Failed to parse v1 app state JSON: {error}"))?;
    Ok(AppState {
        schema_version: SCHEMA_VERSION,
        rules: state
            .rules
            .into_iter()
            .map(|rule| ProxyRule {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpCheckResult {
    pub ip: String,
    pub country: Option<String>,
    pub checked_at: u64,
}

#[derive(Debug, Deserialize)]
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

    validate_rule_ids(&state.rules)?;
    validate_duplicate_ports(&state.rules)?;

    for rule in &state.rules {
        validate_rule(rule)?;
    }

    Ok(())
}

pub fn validate_rule_ids(rules: &[ProxyRule]) -> CommandResult<()> {
    let mut ids = HashSet::new();
    for rule in rules {
        if rule.id.trim().is_empty() {
            return Err("Rule id cannot be empty".to_string());
        }
        if !ids.insert(rule.id.as_str()) {
            return Err(format!("Duplicate rule id: {}", rule.id));
        }
    }
    Ok(())
}

pub fn validate_duplicate_ports(rules: &[ProxyRule]) -> CommandResult<()> {
    let validation = crate::utils::duplicate_port_validation(rules);
    if validation.has_duplicate_ports {
        return Err(format!(
            "Duplicate local ports are not allowed: {:?}",
            validation.duplicate_ports
        ));
    }
    Ok(())
}

pub fn validate_rule(rule: &ProxyRule) -> CommandResult<()> {
    validate_auth(rule.inbound.auth.as_ref())?;

    if rule.inbound.listen.trim().is_empty() {
        return Err(format!("Rule '{}' has an empty listen address", rule.id));
    }

    validate_outbound_config(&rule.id, &rule.outbound)?;

    Ok(())
}

pub fn validate_outbound_config(rule_id: &str, outbound: &OutboundConfig) -> CommandResult<()> {
    match outbound {
        OutboundConfig::Socks(config) => {
            validate_auth(config.auth.as_ref())?;
            if config.host.trim().is_empty() {
                return Err(format!("Rule '{rule_id}' has an empty outbound host"));
            }
        }
        OutboundConfig::Vless(config) => validate_vless_outbound(rule_id, config)?,
        OutboundConfig::Shadowsocks(config) => validate_shadowsocks_outbound(rule_id, config)?,
        OutboundConfig::Trojan(config) => validate_trojan_outbound(rule_id, config)?,
    }
    Ok(())
}

pub fn validate_trojan_outbound(rule_id: &str, config: &TrojanOutboundConfig) -> CommandResult<()> {
    if config.address.trim().is_empty() {
        return Err(format!("Rule '{rule_id}' has an empty Trojan address"));
    }
    if config.password.is_empty() {
        return Err(format!("Rule '{rule_id}' has an empty Trojan password"));
    }
    if config.tls.is_some() && config.reality.is_some() {
        return Err(format!(
            "Rule '{rule_id}' cannot enable both Trojan TLS and REALITY security"
        ));
    }
    if let Some(reality) = &config.reality {
        if reality.public_key.trim().is_empty() {
            return Err(format!("Rule '{rule_id}' has an empty REALITY public key"));
        }
    }
    Ok(())
}

pub fn validate_vless_outbound(rule_id: &str, config: &VlessOutboundConfig) -> CommandResult<()> {
    if config.address.trim().is_empty() {
        return Err(format!("Rule '{rule_id}' has an empty VLESS address"));
    }
    if config.id.trim().is_empty() {
        return Err(format!("Rule '{rule_id}' has an empty VLESS id"));
    }
    if config.encryption.trim().is_empty() {
        return Err(format!(
            "Rule '{rule_id}' has an empty VLESS encryption value"
        ));
    }
    if let Some(flow) = config.flow.as_deref() {
        if !flow.is_empty() && !SUPPORTED_VLESS_FLOWS.contains(&flow) {
            return Err(format!(
                "Rule '{rule_id}' has an unsupported VLESS flow '{flow}'"
            ));
        }
    }
    if config.tls.is_some() && config.reality.is_some() {
        return Err(format!(
            "Rule '{rule_id}' cannot enable both VLESS TLS and REALITY security"
        ));
    }
    if let Some(reality) = &config.reality {
        if reality.public_key.trim().is_empty() {
            return Err(format!("Rule '{rule_id}' has an empty REALITY public key"));
        }
    }
    Ok(())
}

pub fn validate_shadowsocks_outbound(
    rule_id: &str,
    config: &ShadowsocksOutboundConfig,
) -> CommandResult<()> {
    if config.address.trim().is_empty() {
        return Err(format!("Rule '{rule_id}' has an empty Shadowsocks address"));
    }
    if config.method.trim().is_empty() {
        return Err(format!("Rule '{rule_id}' has an empty Shadowsocks method"));
    }
    let method = config.method.trim().to_ascii_lowercase();
    if method == "none" || method == "plain" {
        return Err(format!(
            "Rule '{rule_id}' uses unsafe Shadowsocks method '{}'",
            config.method
        ));
    }
    if !SUPPORTED_SHADOWSOCKS_METHODS.contains(&method.as_str()) {
        return Err(format!(
            "Rule '{rule_id}' has an unsupported Shadowsocks method '{}'",
            config.method
        ));
    }
    if config.password.is_empty() {
        return Err(format!(
            "Rule '{rule_id}' has an empty Shadowsocks password"
        ));
    }
    if let Some(version) = config.uot_version {
        if version != 1 && version != 2 {
            return Err(format!(
                "Rule '{rule_id}' has an unsupported Shadowsocks UoT version {version}"
            ));
        }
        if !config.uot {
            return Err(format!(
                "Rule '{rule_id}' cannot set UoT version while UoT is disabled"
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
