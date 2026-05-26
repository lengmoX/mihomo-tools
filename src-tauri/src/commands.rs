use serde_json::Value;
use std::collections::{HashSet, HashMap};
use std::path::PathBuf;
use std::time::Instant;
use serde::Deserialize;

use crate::models::{
    AppState, ApplyRulesResult, CommandResult, OutboundConfig,
    ParseOutboundUrlResult, PortAvailability, PortValidation, RuntimePaths,
    RuntimeStatus, MihomoBinaryValidation, MihomoVersionInfo, ProxyRule
};
use crate::process::{read_mihomo_version, AppRuntimeState};
use crate::utils::{
    duplicate_port_validation, ensure_data_dir, is_port_available, new_rule_id,
    read_app_state_from_disk, runtime_paths, write_app_state_to_disk,
    write_generated_config_to_disk, DEFAULT_LISTEN_ADDRESS
};
use crate::parser::parse_outbound_url_value;

#[tauri::command]
pub fn load_app_state() -> CommandResult<AppState> {
    read_app_state_from_disk()
}

#[tauri::command]
pub fn save_app_state(state: AppState) -> CommandResult<AppState> {
    write_app_state_to_disk(&state)
}

async fn reload_mihomo_config(config_path: &std::path::Path) -> CommandResult<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|e| format!("Failed to build HTTP client for config reload: {e}"))?;

    let config_path_str = config_path.to_string_lossy().to_string();
    let body = serde_json::json!({
        "path": config_path_str
    });

    let res = client.put("http://127.0.0.1:37896/configs?force=true")
        .json(&body)
        .send()
        .await;

    match res {
        Ok(resp) => {
            if resp.status().is_success() {
                Ok(())
            } else {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                Err(format!("Reload API returned status {status}: {text}"))
            }
        }
        Err(e) => {
            Err(format!("Failed to send reload request: {e}"))
        }
    }
}

#[tauri::command]
pub async fn save_and_apply_app_state(
    state: AppState,
    runtime_state: tauri::State<'_, AppRuntimeState>,
) -> CommandResult<ApplyRulesResult> {
    let state = write_app_state_to_disk(&state)?;
    let generated_config_path = write_generated_config_to_disk(&state)?;

    let was_running = {
        let mut manager = runtime_state
            .process
            .lock()
            .map_err(|_| "Failed to lock runtime process state".to_string())?;
        manager.status()?.running
    };

    let status = if was_running {
        let paths = runtime_paths()?;
        if !paths.mihomo_binary_path.is_file() {
            return Err(format!(
                "Mihomo binary was not found at {}",
                paths.mihomo_binary_path.display()
            ));
        }

        if let Err(e) = reload_mihomo_config(&paths.generated_config_path).await {
            println!("Hot reload failed, falling back to restart: {e}");
            let mut manager = runtime_state
                .process
                .lock()
                .map_err(|_| "Failed to lock runtime process state".to_string())?;
            manager.stop()?;
            manager.start(paths.mihomo_binary_path, paths.generated_config_path)?
        } else {
            let mut manager = runtime_state
                .process
                .lock()
                .map_err(|_| "Failed to lock runtime process state".to_string())?;
            manager.status()?
        }
    } else {
        let mut manager = runtime_state
            .process
            .lock()
            .map_err(|_| "Failed to lock runtime process state".to_string())?;
        manager.status()?
    };

    Ok(ApplyRulesResult {
        state,
        generated_config_path,
        restarted: was_running,
        status,
    })
}

#[tauri::command]
pub fn add_rule(mut rule: ProxyRule) -> CommandResult<AppState> {
    let mut state = read_app_state_from_disk()?;
    rule.id = new_rule_id();
    rule.ip_check = None;
    state.rules.push(rule);
    write_app_state_to_disk(&state)
}

#[tauri::command]
pub fn duplicate_rule(rule_id: String) -> CommandResult<AppState> {
    let mut state = read_app_state_from_disk()?;
    let index = state
        .rules
        .iter()
        .position(|rule| rule.id == rule_id)
        .ok_or_else(|| format!("Rule '{}' was not found", rule_id))?;

    let original_rule = &state.rules[index];
    let mut target_port = original_rule.inbound.port;
    let listen = original_rule.inbound.listen.clone();
    let used_ports: HashSet<u16> = state.rules.iter().map(|r| r.inbound.port).collect();

    let mut found = false;
    for _ in 0..65536 {
        if target_port == 65535 {
            target_port = 50000;
        } else {
            target_port += 1;
        }

        if !used_ports.contains(&target_port) && is_port_available(&listen, target_port) {
            found = true;
            break;
        }
    }

    if !found {
        return Err("No available local ports found in 50000..=65535".to_string());
    }

    let mut new_rule = original_rule.clone();
    new_rule.id = new_rule_id();
    new_rule.remark = format!("{} - copy", original_rule.remark);
    new_rule.inbound.port = target_port;
    new_rule.ip_check = None;

    state.rules.insert(index + 1, new_rule);
    write_app_state_to_disk(&state)
}

#[tauri::command]
pub fn update_rule(rule: ProxyRule) -> CommandResult<AppState> {
    let mut state = read_app_state_from_disk()?;
    let index = state
        .rules
        .iter()
        .position(|r| r.id == rule.id)
        .ok_or_else(|| format!("Rule '{}' was not found", rule.id))?;
    let previous_rule = &state.rules[index];
    let ip_check =
        if previous_rule.inbound == rule.inbound && previous_rule.outbound == rule.outbound {
            previous_rule.ip_check.clone()
        } else {
            None
        };

    state.rules[index] = ProxyRule {
        id: rule.id,
        remark: rule.remark,
        enabled: rule.enabled,
        inbound: rule.inbound,
        outbound: rule.outbound,
        ip_check,
    };
    write_app_state_to_disk(&state)
}

#[tauri::command]
pub fn set_rule_enabled(rule_id: String, enabled: bool) -> CommandResult<AppState> {
    let mut state = read_app_state_from_disk()?;
    let rule = state
        .rules
        .iter_mut()
        .find(|rule| rule.id == rule_id)
        .ok_or_else(|| format!("Rule '{rule_id}' was not found"))?;
    rule.enabled = enabled;
    write_app_state_to_disk(&state)
}

#[tauri::command]
pub fn remove_rule(rule_id: String) -> CommandResult<AppState> {
    let mut state = read_app_state_from_disk()?;
    let original_len = state.rules.len();
    state.rules.retain(|rule| rule.id != rule_id);

    if state.rules.len() == original_len {
        return Err(format!("Rule '{rule_id}' was not found"));
    }

    write_app_state_to_disk(&state)
}

#[tauri::command]
pub fn delete_rule(rule_id: String) -> CommandResult<AppState> {
    remove_rule(rule_id)
}

#[tauri::command]
pub async fn check_rule_ip(
    rule_id: String,
    runtime_state: tauri::State<'_, AppRuntimeState>,
) -> CommandResult<AppState> {
    {
        let mut manager = runtime_state
            .process
            .lock()
            .map_err(|_| "Failed to lock runtime process state".to_string())?;
        if !manager.status()?.running {
            return Err("Start Mihomo before checking a rule IP".to_string());
        }
    }

    let mut state = read_app_state_from_disk()?;
    let index = state
        .rules
        .iter()
        .position(|rule| rule.id == rule_id)
        .ok_or_else(|| format!("Rule '{rule_id}' was not found"))?;

    if !state.rules[index].enabled {
        return Err("Enable the rule before checking its IP".to_string());
    }

    let rule = state.rules[index].clone();
    let ip_check = tauri::async_runtime::spawn_blocking(move || crate::ip_check::fetch_ip_info(&rule))
        .await
        .map_err(|error| format!("Failed to join IP check task: {error}"))??;
    state.rules[index].ip_check = Some(ip_check);
    write_app_state_to_disk(&state)
}

#[tauri::command]
pub async fn check_rules_ip_batch(
    rule_ids: Vec<String>,
    runtime_state: tauri::State<'_, AppRuntimeState>,
) -> CommandResult<AppState> {
    {
        let mut manager = runtime_state
            .process
            .lock()
            .map_err(|_| "Failed to lock runtime process state".to_string())?;
        if !manager.status()?.running {
            return Err("Start Mihomo before checking rule IPs".to_string());
        }
    }

    let state = read_app_state_from_disk()?;
    let mut rules_to_check = Vec::new();
    for id in &rule_ids {
        if let Some(rule) = state.rules.iter().find(|r| r.id == *id) {
            if rule.enabled {
                rules_to_check.push(rule.clone());
            }
        }
    }

    if rules_to_check.is_empty() {
        return Err("No enabled rules selected for IP checking".to_string());
    }

    let mut handles = Vec::new();
    for rule in rules_to_check {
        let handle = tauri::async_runtime::spawn_blocking(move || {
            let res = crate::ip_check::fetch_ip_info(&rule);
            (rule.id.clone(), res)
        });
        handles.push(handle);
    }

    let mut check_results = Vec::new();
    for handle in handles {
        if let Ok((rule_id, Ok(ip_check))) = handle.await {
            check_results.push((rule_id, ip_check));
        }
    }

    let mut state = read_app_state_from_disk()?;
    for (rule_id, ip_check) in check_results {
        if let Some(index) = state.rules.iter().position(|r| r.id == rule_id) {
            state.rules[index].ip_check = Some(ip_check);
        }
    }

    write_app_state_to_disk(&state)
}

#[tauri::command]
pub fn parse_socks_outbound_url(input: String) -> CommandResult<OutboundConfig> {
    let result = crate::parser::parse_socks_url(&input)?;
    Ok(result.outbound)
}

#[tauri::command]
pub fn parse_socks_proxy_url(input: String) -> CommandResult<OutboundConfig> {
    parse_socks_outbound_url(input)
}

#[tauri::command]
pub fn parse_outbound_url(input: String) -> CommandResult<ParseOutboundUrlResult> {
    parse_outbound_url_value(&input)
}

#[tauri::command]
pub fn generate_mihomo_config(state: Option<AppState>) -> CommandResult<Value> {
    let state = match state {
        Some(state) => state,
        None => read_app_state_from_disk()?,
    };
    let config = crate::config::generate_config_value(&state)?;
    write_generated_config_to_disk(&state)?;
    Ok(config)
}

#[tauri::command]
pub fn write_mihomo_config(state: Option<AppState>) -> CommandResult<PathBuf> {
    let state = match state {
        Some(state) => state,
        None => read_app_state_from_disk()?,
    };
    write_generated_config_to_disk(&state)
}

#[tauri::command]
pub fn validate_mihomo_binary() -> CommandResult<MihomoBinaryValidation> {
    let paths = runtime_paths()?;
    let exists = paths.mihomo_binary_path.exists();
    let is_file = paths.mihomo_binary_path.is_file();
    let valid = exists && is_file;
    let message = if valid {
        "Mihomo binary exists".to_string()
    } else if exists {
        format!(
            "Mihomo binary path is not a file: {}",
            paths.mihomo_binary_path.display()
        )
    } else {
        format!(
            "Mihomo binary was not found at {}",
            paths.mihomo_binary_path.display()
        )
    };

    Ok(MihomoBinaryValidation {
        path: paths.mihomo_binary_path,
        exists,
        is_file,
        valid,
        message,
    })
}

#[tauri::command]
pub fn get_mihomo_version() -> CommandResult<MihomoVersionInfo> {
    let paths = runtime_paths()?;

    if !paths.mihomo_binary_path.is_file() {
        return Err(format!(
            "Mihomo binary was not found at {}",
            paths.mihomo_binary_path.display()
        ));
    }

    read_mihomo_version(&paths.mihomo_binary_path)
}

#[tauri::command]
pub fn check_port_available(port: u16, listen: Option<String>) -> CommandResult<PortAvailability> {
    let listen = listen.unwrap_or_else(|| DEFAULT_LISTEN_ADDRESS.to_string());
    Ok(PortAvailability {
        port,
        available: is_port_available(&listen, port),
    })
}

#[tauri::command]
pub fn validate_rule_ports(state: AppState) -> CommandResult<PortValidation> {
    crate::models::validate_state(&state)?;
    Ok(duplicate_port_validation(&state.rules))
}

#[tauri::command]
pub fn get_runtime_paths() -> CommandResult<RuntimePaths> {
    ensure_data_dir()
}

#[tauri::command]
pub fn get_runtime_status(
    runtime_state: tauri::State<'_, AppRuntimeState>,
) -> CommandResult<RuntimeStatus> {
    runtime_state
        .process
        .lock()
        .map_err(|_| "Failed to lock runtime process state".to_string())?
        .status()
}

#[tauri::command]
pub fn get_mihomo_status(
    runtime_state: tauri::State<'_, AppRuntimeState>,
) -> CommandResult<RuntimeStatus> {
    get_runtime_status(runtime_state)
}

#[tauri::command]
pub fn start_mihomo(runtime_state: tauri::State<'_, AppRuntimeState>) -> CommandResult<RuntimeStatus> {
    runtime_state.clear_stats();
    let state = read_app_state_from_disk()?;
    let port_validation = duplicate_port_validation(&state.rules);
    if !port_validation.valid {
        return Err(port_validation.message);
    }

    let paths = ensure_data_dir()?;
    if !paths.mihomo_binary_path.is_file() {
        return Err(format!(
            "Mihomo binary was not found at {}",
            paths.mihomo_binary_path.display()
        ));
    }

    write_generated_config_to_disk(&state)?;

    runtime_state
        .process
        .lock()
        .map_err(|_| "Failed to lock runtime process state".to_string())?
        .start(paths.mihomo_binary_path, paths.generated_config_path)
}

#[tauri::command]
pub fn stop_mihomo(runtime_state: tauri::State<'_, AppRuntimeState>) -> CommandResult<RuntimeStatus> {
    runtime_state.clear_stats();
    runtime_state
        .process
        .lock()
        .map_err(|_| "Failed to lock runtime process state".to_string())?
        .stop()
}

#[tauri::command]
pub async fn restart_mihomo(runtime_state: tauri::State<'_, AppRuntimeState>) -> CommandResult<RuntimeStatus> {
    let paths = runtime_paths()?;
    let is_running = {
        let mut manager = runtime_state
            .process
            .lock()
            .map_err(|_| "Failed to lock runtime process state".to_string())?;
        manager.status()?.running
    };

    if is_running {
        if let Err(e) = reload_mihomo_config(&paths.generated_config_path).await {
            println!("Hot reload failed during restart, falling back to process restart: {e}");
            let mut manager = runtime_state
                .process
                .lock()
                .map_err(|_| "Failed to lock runtime process state".to_string())?;
            manager.stop()?;
            manager.start(paths.mihomo_binary_path, paths.generated_config_path)
        } else {
            let mut manager = runtime_state
                .process
                .lock()
                .map_err(|_| "Failed to lock runtime process state".to_string())?;
            manager.status()
        }
    } else {
        start_mihomo(runtime_state)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MihomoMetadata {
    inbound_port: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MihomoConnection {
    id: String,
    upload: u64,
    download: u64,
    metadata: MihomoMetadata,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MihomoConnectionsResponse {
    connections: Vec<MihomoConnection>,
}

#[tauri::command]
pub async fn query_mihomo_stats(
    runtime_state: tauri::State<'_, AppRuntimeState>,
) -> CommandResult<crate::models::MihomoQueryStatsResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let res = client.get("http://127.0.0.1:37896/connections")
        .send()
        .await;

    let conn_resp: MihomoConnectionsResponse = match res {
        Ok(resp) => {
            if resp.status().is_success() {
                resp.json::<MihomoConnectionsResponse>()
                    .await
                    .map_err(|e| format!("Failed to parse connections JSON: {e}"))?
            } else {
                return Ok(crate::models::MihomoQueryStatsResult { rules: Vec::new() });
            }
        }
        Err(_) => {
            return Ok(crate::models::MihomoQueryStatsResult { rules: Vec::new() });
        }
    };

    let mut current_conns = std::collections::HashSet::new();
    let mut active_connections_count: HashMap<u16, usize> = HashMap::new();
    let mut port_deltas: HashMap<u16, (u64, u64)> = HashMap::new();

    // Sum active traffic deltas and connections by inbound port
    {
        let mut last_conns = runtime_state.last_connections.lock()
            .map_err(|_| "Failed to lock last_connections".to_string())?;

        let mut totals = runtime_state.traffic_totals.lock()
            .map_err(|_| "Failed to lock traffic_totals".to_string())?;

        for conn in conn_resp.connections {
            let inbound_port_opt = conn.metadata.inbound_port.as_ref().and_then(|val| {
                if let Some(port_num) = val.as_u64() {
                    Some(port_num as u16)
                } else if let Some(port_str) = val.as_str() {
                    port_str.parse::<u16>().ok()
                } else {
                    None
                }
            });

            if let Some(inbound_port) = inbound_port_opt {
                if inbound_port > 0 {
                    current_conns.insert(conn.id.clone());

                    let count = active_connections_count.entry(inbound_port).or_insert(0);
                    *count += 1;

                    let last_info = last_conns.entry(conn.id.clone()).or_insert_with(|| crate::process::ConnectionInfo {
                        inbound_port,
                        last_upload: 0,
                        last_download: 0,
                    });

                    let delta_up = conn.upload.saturating_sub(last_info.last_upload);
                    let delta_down = conn.download.saturating_sub(last_info.last_download);

                    let deltas = port_deltas.entry(inbound_port).or_insert((0, 0));
                    deltas.0 += delta_up;
                    deltas.1 += delta_down;

                    let port_total = totals.entry(inbound_port).or_insert((0, 0));
                    port_total.0 += delta_up;
                    port_total.1 += delta_down;

                    last_info.last_upload = conn.upload;
                    last_info.last_download = conn.download;
                }
            }
        }

        // Clean up closed connections
        last_conns.retain(|id, _| current_conns.contains(id));
    }

    // Calculate time elapsed
    let now = Instant::now();
    let mut last_poll = runtime_state.last_poll_time.lock()
        .map_err(|_| "Failed to lock last_poll_time".to_string())?;
    
    let delta_t = if let Some(last_time) = *last_poll {
        let diff = now.duration_since(last_time).as_secs_f64();
        if diff > 0.1 { diff } else { 1.0 }
    } else {
        1.0
    };
    *last_poll = Some(now);

    // Calculate speeds
    let mut current_speeds = HashMap::new();
    for (port, deltas) in port_deltas {
        let up_speed = (deltas.0 as f64 / delta_t) as u64;
        let down_speed = (deltas.1 as f64 / delta_t) as u64;
        current_speeds.insert(port, (up_speed, down_speed));
    }

    let mut rules_stats = Vec::new();
    let state_res = read_app_state_from_disk();
    if let Ok(state) = state_res {
        let totals = runtime_state.traffic_totals.lock()
            .map_err(|_| "Failed to lock traffic_totals".to_string())?;
        
        for rule in state.rules {
            let port = rule.inbound.port;
            let active_conns = *active_connections_count.get(&port).unwrap_or(&0);
            let speed = *current_speeds.get(&port).unwrap_or(&(0, 0));
            let total = *totals.get(&port).unwrap_or(&(0, 0));

            rules_stats.push(crate::models::MihomoRuleStat {
                inbound_port: port,
                upload_speed: speed.0,
                download_speed: speed.1,
                upload_total: total.0,
                download_total: total.1,
                active_connections: active_conns,
            });
        }
    }

    Ok(crate::models::MihomoQueryStatsResult { rules: rules_stats })
}
