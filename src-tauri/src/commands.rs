use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

use crate::models::{
    AppState, ApplyRulesResult, CommandResult, NewRuleRequest, OutboundConfig,
    ParseOutboundUrlResult, PortAvailability, PortValidation, ProxyRule, RuntimePaths,
    RuntimeStatus, UpdateRuleRequest, XrayBinaryValidation, XrayVersionInfo,
};
use crate::process::{read_xray_version, AppRuntimeState};
use crate::utils::{
    create_rule, duplicate_port_validation, ensure_data_dir, is_port_available, new_rule_id,
    read_app_state_from_disk, runtime_paths, write_app_state_to_disk,
    write_generated_config_to_disk, DEFAULT_LISTEN_ADDRESS, XRAY_API_PORT,
};
use crate::parser::parse_outbound_url_value;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[tauri::command]
pub fn load_app_state() -> CommandResult<AppState> {
    read_app_state_from_disk()
}

#[tauri::command]
pub fn save_app_state(state: AppState) -> CommandResult<AppState> {
    write_app_state_to_disk(&state)
}

#[tauri::command]
pub fn save_and_apply_app_state(
    state: AppState,
    runtime_state: tauri::State<'_, AppRuntimeState>,
) -> CommandResult<ApplyRulesResult> {
    let state = write_app_state_to_disk(&state)?;
    let generated_config_path = write_generated_config_to_disk(&state)?;

    let mut manager = runtime_state
        .process
        .lock()
        .map_err(|_| "Failed to lock runtime process state".to_string())?;
    let was_running = manager.status()?.running;

    let status = if was_running {
        let paths = runtime_paths()?;
        if !paths.xray_binary_path.is_file() {
            return Err(format!(
                "Xray binary was not found at {}",
                paths.xray_binary_path.display()
            ));
        }

        manager.stop()?;
        manager.start(paths.xray_binary_path, paths.generated_config_path)?
    } else {
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
pub fn add_rule(request: NewRuleRequest) -> CommandResult<AppState> {
    let mut state = read_app_state_from_disk()?;
    let rule = create_rule(request, &state.rules)?;
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
pub fn update_rule(request: UpdateRuleRequest) -> CommandResult<AppState> {
    let mut state = read_app_state_from_disk()?;
    let index = state
        .rules
        .iter()
        .position(|rule| rule.id == request.id)
        .ok_or_else(|| format!("Rule '{}' was not found", request.id))?;
    let previous_rule = &state.rules[index];
    let ip_check =
        if previous_rule.inbound == request.inbound && previous_rule.outbound == request.outbound {
            previous_rule.ip_check.clone()
        } else {
            None
        };

    state.rules[index] = ProxyRule {
        id: request.id,
        remark: request.remark,
        enabled: request.enabled,
        inbound: request.inbound,
        outbound: request.outbound,
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
            return Err("Start Xray before checking a rule IP".to_string());
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
            return Err("Start Xray before checking rule IPs".to_string());
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
pub fn delete_rule(rule_id: String) -> CommandResult<AppState> {
    remove_rule(rule_id)
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
pub fn generate_xray_config(state: Option<AppState>) -> CommandResult<Value> {
    let state = match state {
        Some(state) => state,
        None => read_app_state_from_disk()?,
    };
    let config = crate::config::generate_config_value(&state)?;
    write_generated_config_to_disk(&state)?;
    Ok(config)
}

#[tauri::command]
pub fn write_xray_config(state: Option<AppState>) -> CommandResult<PathBuf> {
    let state = match state {
        Some(state) => state,
        None => read_app_state_from_disk()?,
    };
    write_generated_config_to_disk(&state)
}

#[tauri::command]
pub fn validate_xray_binary() -> CommandResult<XrayBinaryValidation> {
    let paths = runtime_paths()?;
    let exists = paths.xray_binary_path.exists();
    let is_file = paths.xray_binary_path.is_file();
    let valid = exists && is_file;
    let message = if valid {
        "Xray binary exists".to_string()
    } else if exists {
        format!(
            "Xray binary path is not a file: {}",
            paths.xray_binary_path.display()
        )
    } else {
        format!(
            "Xray binary was not found at {}",
            paths.xray_binary_path.display()
        )
    };

    Ok(XrayBinaryValidation {
        path: paths.xray_binary_path,
        exists,
        is_file,
        valid,
        message,
    })
}

#[tauri::command]
pub fn get_xray_version() -> CommandResult<XrayVersionInfo> {
    let paths = runtime_paths()?;

    if !paths.xray_binary_path.is_file() {
        return Err(format!(
            "Xray binary was not found at {}",
            paths.xray_binary_path.display()
        ));
    }

    read_xray_version(&paths.xray_binary_path)
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
pub fn get_xray_status(
    runtime_state: tauri::State<'_, AppRuntimeState>,
) -> CommandResult<RuntimeStatus> {
    get_runtime_status(runtime_state)
}

#[tauri::command]
pub fn start_xray(runtime_state: tauri::State<'_, AppRuntimeState>) -> CommandResult<RuntimeStatus> {
    let state = read_app_state_from_disk()?;
    let port_validation = duplicate_port_validation(&state.rules);
    if !port_validation.valid {
        return Err(port_validation.message);
    }

    let paths = ensure_data_dir()?;
    if !paths.xray_binary_path.is_file() {
        return Err(format!(
            "Xray binary was not found at {}",
            paths.xray_binary_path.display()
        ));
    }

    write_generated_config_to_disk(&state)?;

    runtime_state
        .process
        .lock()
        .map_err(|_| "Failed to lock runtime process state".to_string())?
        .start(paths.xray_binary_path, paths.generated_config_path)
}

#[tauri::command]
pub fn stop_xray(runtime_state: tauri::State<'_, AppRuntimeState>) -> CommandResult<RuntimeStatus> {
    runtime_state
        .process
        .lock()
        .map_err(|_| "Failed to lock runtime process state".to_string())?
        .stop()
}

#[tauri::command]
pub fn restart_xray(runtime_state: tauri::State<'_, AppRuntimeState>) -> CommandResult<RuntimeStatus> {
    {
        let mut manager = runtime_state
            .process
            .lock()
            .map_err(|_| "Failed to lock runtime process state".to_string())?;
        manager.stop()?;
    }
    start_xray(runtime_state)
}

#[tauri::command]
pub fn query_xray_stats(
    runtime_state: tauri::State<'_, AppRuntimeState>,
) -> CommandResult<Value> {
    {
        let mut manager = runtime_state
            .process
            .lock()
            .map_err(|_| "Failed to lock runtime process state".to_string())?;
        if !manager.status()?.running {
            return Ok(json!({ "stat": [] }));
        }
    }

    let paths = runtime_paths()?;
    if !paths.xray_binary_path.is_file() {
        return Err("Xray binary was not found".to_string());
    }

    let mut command = Command::new(&paths.xray_binary_path);
    command
        .arg("api")
        .arg("statsquery")
        .arg(format!("--server=127.0.0.1:{XRAY_API_PORT}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);

    let output = command
        .output()
        .map_err(|error| format!("Failed to execute Xray API command: {error}"))?;

    if !output.status.success() {
        // If the process is starting up or terminating, the loopback call might temporarily fail.
        // Return an empty stats result gracefully to avoid breaking frontend UI.
        return Ok(json!({ "stat": [] }));
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&stdout_str)
        .map_err(|error| format!("Failed to parse Stats JSON: {error}"))?;

    Ok(parsed)
}
