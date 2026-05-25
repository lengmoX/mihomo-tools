use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use crate::models::{CommandResult, RuntimeStatus, MihomoVersionInfo};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Default)]
pub struct MihomoProcessManager {
    pub child: Option<Child>,
}

impl MihomoProcessManager {
    pub fn status(&mut self) -> CommandResult<RuntimeStatus> {
        if let Some(child) = self.child.as_mut() {
            if child
                .try_wait()
                .map_err(|error| error.to_string())?
                .is_some()
            {
                self.child = None;
                return Ok(RuntimeStatus {
                    running: false,
                    pid: None,
                });
            }

            return Ok(RuntimeStatus {
                running: true,
                pid: Some(child.id()),
            });
        }

        Ok(RuntimeStatus {
            running: false,
            pid: None,
        })
    }

    pub fn start(
        &mut self,
        binary_path: PathBuf,
        config_path: PathBuf,
    ) -> CommandResult<RuntimeStatus> {
        if self.status()?.running {
            return Err("Mihomo is already running".to_string());
        }

        let mut command = Command::new(binary_path);
        let data_dir = config_path.parent().ok_or_else(|| "Failed to get config parent dir".to_string())?.to_path_buf();
        command
            .arg("-d")
            .arg(&data_dir)
            .arg("-f")
            .arg(config_path)
            .stdin(Stdio::null());

        if let Ok(file) = std::fs::File::create(data_dir.join("mihomo.log")) {
            if let Ok(err_file) = file.try_clone() {
                command.stdout(Stdio::from(file));
                command.stderr(Stdio::from(err_file));
            } else {
                command.stdout(Stdio::null());
                command.stderr(Stdio::null());
            }
        } else {
            command.stdout(Stdio::null());
            command.stderr(Stdio::null());
        }

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        let child = command
            .spawn()
            .map_err(|error| format!("Failed to start Mihomo: {error}"))?;

        let pid = child.id();
        self.child = Some(child);

        Ok(RuntimeStatus {
            running: true,
            pid: Some(pid),
        })
    }

    pub fn stop(&mut self) -> CommandResult<RuntimeStatus> {
        if let Some(mut child) = self.child.take() {
            if child
                .try_wait()
                .map_err(|error| error.to_string())?
                .is_none()
            {
                child
                    .kill()
                    .map_err(|error| format!("Failed to stop Mihomo: {error}"))?;
                let _ = child.wait();
            }
        }

        Ok(RuntimeStatus {
            running: false,
            pid: None,
        })
    }
}

use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
pub struct ConnectionInfo {
    pub inbound_port: u16,
    pub last_upload: u64,
    pub last_download: u64,
}

pub struct AppRuntimeState {
    pub process: Mutex<MihomoProcessManager>,
    pub last_connections: Mutex<HashMap<String, ConnectionInfo>>,
    pub traffic_totals: Mutex<HashMap<u16, (u64, u64)>>, // Key: inbound port, Value: (upload_total, download_total)
    pub last_poll_time: Mutex<Option<Instant>>,
    pub last_speeds: Mutex<HashMap<u16, (u64, u64)>>, // Key: inbound port, Value: (upload_speed, download_speed) in bytes/sec
}

impl Default for AppRuntimeState {
    fn default() -> Self {
        Self {
            process: Mutex::new(MihomoProcessManager::default()),
            last_connections: Mutex::new(HashMap::new()),
            traffic_totals: Mutex::new(HashMap::new()),
            last_poll_time: Mutex::new(None),
            last_speeds: Mutex::new(HashMap::new()),
        }
    }
}

impl AppRuntimeState {
    pub fn clear_stats(&self) {
        if let Ok(mut conns) = self.last_connections.lock() {
            conns.clear();
        }
        if let Ok(mut totals) = self.traffic_totals.lock() {
            totals.clear();
        }
        if let Ok(mut poll_time) = self.last_poll_time.lock() {
            *poll_time = None;
        }
        if let Ok(mut speeds) = self.last_speeds.lock() {
            speeds.clear();
        }
    }
}

pub fn parse_mihomo_version(output_text: &str) -> CommandResult<MihomoVersionInfo> {
    let first_line = output_text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| "Mihomo version output was empty".to_string())?;

    let version = first_line
        .split_whitespace()
        .find(|word| word.starts_with('v') && word.chars().nth(1).is_some_and(|c| c.is_ascii_digit()))
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Failed to parse Mihomo version from '{first_line}'"))?;

    Ok(MihomoVersionInfo {
        version,
        display_text: first_line.to_string(),
    })
}

pub fn read_mihomo_version(binary_path: &Path) -> CommandResult<MihomoVersionInfo> {
    let mut command = Command::new(binary_path);
    command
        .arg("-v")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);

    let output = command
        .output()
        .map_err(|error| format!("Failed to read Mihomo version: {error}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let separator = if stdout.is_empty() || stderr.is_empty() { "" } else { "\n" };
    let combined_output = format!("{stdout}{separator}{stderr}");

    if !output.status.success() {
        let detail = combined_output.trim();
        return Err(if detail.is_empty() {
            format!("Mihomo version command exited with status {}", output.status)
        } else {
            format!("Mihomo version command failed: {detail}")
        });
    }

    parse_mihomo_version(&combined_output)
}
