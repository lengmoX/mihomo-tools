use base64::{engine::general_purpose, Engine as _};
use percent_encoding::percent_decode_str;
use std::{
    collections::HashSet,
    env, fs,
    net::{SocketAddr, TcpListener, ToSocketAddrs},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use crate::models::{
    AppState, CommandResult, ListenerRule, PortValidation, RuntimePaths,
};

pub const STATE_FILE_NAME: &str = "app-state.json";
pub const GENERATED_CONFIG_FILE_NAME: &str = "generated-config.yaml";
pub const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1";
pub const MIN_AUTO_PORT: u16 = 50_000;
pub const MAX_AUTO_PORT: u16 = 65_535;

pub fn runtime_paths() -> CommandResult<RuntimePaths> {
    let runtime_root = resolve_runtime_root()?;
    let data_dir = runtime_root.join("data");

    Ok(RuntimePaths {
        app_state_path: data_dir.join(STATE_FILE_NAME),
        generated_config_path: data_dir.join(GENERATED_CONFIG_FILE_NAME),
        mihomo_binary_path: runtime_root.join("mihomo").join("mihomo.exe"),
        runtime_root,
        data_dir,
    })
}

pub fn resolve_runtime_root() -> CommandResult<PathBuf> {
    let exe_path = env::current_exe()
        .map_err(|error| format!("Failed to resolve executable path: {error}"))?;
    exe_path
        .parent()
        .map(PathBuf::from)
        .ok_or_else(|| "Failed to resolve executable directory".to_string())
}

pub fn ensure_data_dir() -> CommandResult<RuntimePaths> {
    let paths = runtime_paths()?;
    fs::create_dir_all(&paths.data_dir)
        .map_err(|error| format!("Failed to create data directory: {error}"))?;
    Ok(paths)
}

pub fn read_app_state_from_disk() -> CommandResult<AppState> {
    let paths = ensure_data_dir()?;
    if !paths.app_state_path.exists() {
        return Ok(AppState::default());
    }

    let state_text = fs::read_to_string(&paths.app_state_path)
        .map_err(|error| format!("Failed to read app state: {error}"))?;
    let state: AppState = serde_json::from_str(&state_text)
        .map_err(|error| format!("Failed to parse app state JSON: {error}"))?;
    crate::models::validate_state(&state)?;
    Ok(state)
}

pub fn write_app_state_to_disk(state: &AppState) -> CommandResult<AppState> {
    crate::models::validate_state(state)?;
    let paths = ensure_data_dir()?;
    let state_text = serde_json::to_string_pretty(state)
        .map_err(|error| format!("Failed to serialize app state: {error}"))?;
    fs::write(&paths.app_state_path, state_text)
        .map_err(|error| format!("Failed to write app state: {error}"))?;
    Ok(state.clone())
}

pub fn write_generated_config_to_disk(state: &AppState) -> CommandResult<PathBuf> {
    let config = crate::config::generate_config_value(state)?;
    let paths = ensure_data_dir()?;
    let config_text = serde_yaml::to_string(&config)
        .map_err(|error| format!("Failed to serialize generated Mihomo config: {error}"))?;
    fs::write(&paths.generated_config_path, config_text)
        .map_err(|error| format!("Failed to write generated Mihomo config: {error}"))?;
    Ok(paths.generated_config_path)
}

pub fn duplicate_port_validation(rules: &[ListenerRule]) -> PortValidation {
    let mut seen = HashSet::new();
    let mut duplicates = HashSet::new();

    for rule in rules.iter().filter(|rule| rule.enabled) {
        if !seen.insert(rule.port) {
            duplicates.insert(rule.port);
        }
    }

    let mut duplicate_ports = duplicates.into_iter().collect::<Vec<_>>();
    duplicate_ports.sort_unstable();

    port_validation_with_availability(rules, duplicate_ports)
}

pub fn port_validation_with_availability(
    rules: &[ListenerRule],
    duplicate_ports: Vec<u16>,
) -> PortValidation {
    let mut unavailable_ports = Vec::new();
    for rule in rules.iter().filter(|rule| rule.enabled) {
        if !is_port_available(&rule.listen, rule.port)
            && !unavailable_ports.contains(&rule.port)
        {
            unavailable_ports.push(rule.port);
        }
    }
    unavailable_ports.sort_unstable();

    let has_duplicate_ports = !duplicate_ports.is_empty();
    let valid = !has_duplicate_ports && unavailable_ports.is_empty();
    let message = if valid {
        "All enabled local ports are available".to_string()
    } else {
        let mut messages = Vec::new();
        if has_duplicate_ports {
            messages.push(format!(
                "duplicate enabled local ports: {:?}",
                duplicate_ports
            ));
        }
        if !unavailable_ports.is_empty() {
            messages.push(format!(
                "unavailable enabled local ports: {:?}",
                unavailable_ports
            ));
        }
        messages.join("; ")
    };

    PortValidation {
        has_duplicate_ports,
        duplicate_ports,
        unavailable_ports,
        valid,
        message,
    }
}

pub fn is_port_available(listen: &str, port: u16) -> bool {
    let Ok(addresses) = (listen, port).to_socket_addrs() else {
        return false;
    };

    addresses.into_iter().any(can_bind)
}

fn can_bind(address: SocketAddr) -> bool {
    TcpListener::bind(address).is_ok()
}

pub fn choose_unused_port(existing_rules: &[ListenerRule]) -> CommandResult<u16> {
    let used_ports = existing_rules
        .iter()
        .filter(|rule| rule.enabled)
        .map(|rule| rule.port)
        .collect::<HashSet<_>>();
    let total_ports = u32::from(MAX_AUTO_PORT - MIN_AUTO_PORT) + 1;
    let start_offset = random_port_offset(total_ports);

    for step in 0..total_ports {
        let port = MIN_AUTO_PORT + ((start_offset + step) % total_ports) as u16;
        if !used_ports.contains(&port) && is_port_available(DEFAULT_LISTEN_ADDRESS, port) {
            return Ok(port);
        }
    }

    Err("No available local ports found in 50000..=65535".to_string())
}

pub fn random_port_offset(total_ports: u32) -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    nanos % total_ports
}

pub fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn normalize_country_code(country: Option<String>) -> Option<String> {
    let country = country?.trim().to_ascii_uppercase();
    if country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Some(country)
    } else {
        None
    }
}

pub fn build_proxy_url(listen: &str, port: u16, inbound_type: &str) -> String {
    let scheme = match inbound_type {
        "socks" => "socks5h",
        "http" => "http",
        _ => "socks5h", // default to socks5h for mixed type URL representation
    };

    format!("{scheme}://{}:{}", listen, port)
}

pub fn new_rule_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros())
        .unwrap_or(0);
    format!("rule-{timestamp}")
}

pub fn percent_decode(value: &str) -> CommandResult<String> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .map_err(|error| format!("Failed to percent-decode URL value: {error}"))
}

pub fn decode_base64_optional(value: &str) -> Option<String> {
    decode_base64_required(value).ok()
}

pub fn decode_base64_required(value: &str) -> CommandResult<String> {
    let normalized = value.replace('-', "+").replace('_', "/");
    let padding = (4 - normalized.len() % 4) % 4;
    let padded = format!("{}{}", normalized, "=".repeat(padding));
    let bytes = general_purpose::STANDARD
        .decode(padded)
        .map_err(|error| format!("Failed to decode base64 Shadowsocks value: {error}"))?;
    String::from_utf8(bytes)
        .map_err(|error| format!("Decoded Shadowsocks value is not UTF-8: {error}"))
}
