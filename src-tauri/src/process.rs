use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use crate::models::{CommandResult, RuntimeStatus, XrayVersionInfo};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Default)]
pub struct XrayProcessManager {
    pub child: Option<Child>,
}

impl XrayProcessManager {
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
            return Err("Xray is already running".to_string());
        }

        let mut command = Command::new(binary_path);
        command
            .arg("run")
            .arg("-config")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        let child = command
            .spawn()
            .map_err(|error| format!("Failed to start Xray: {error}"))?;

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
                    .map_err(|error| format!("Failed to stop Xray: {error}"))?;
                let _ = child.wait();
            }
        }

        Ok(RuntimeStatus {
            running: false,
            pid: None,
        })
    }
}

pub struct AppRuntimeState {
    pub process: Mutex<XrayProcessManager>,
}

impl Default for AppRuntimeState {
    fn default() -> Self {
        Self {
            process: Mutex::new(XrayProcessManager::default()),
        }
    }
}

pub fn parse_xray_version(output_text: &str) -> CommandResult<XrayVersionInfo> {
    let first_line = output_text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| "Xray version output was empty".to_string())?;

    let version = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("Failed to parse Xray version from '{first_line}'"))?;

    Ok(XrayVersionInfo {
        version: version.to_string(),
        display_text: first_line.to_string(),
    })
}

pub fn read_xray_version(binary_path: &Path) -> CommandResult<XrayVersionInfo> {
    let mut command = Command::new(binary_path);
    command
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);

    let output = command
        .output()
        .map_err(|error| format!("Failed to read Xray version: {error}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let separator = if stdout.is_empty() || stderr.is_empty() { "" } else { "\n" };
    let combined_output = format!("{stdout}{separator}{stderr}");

    if !output.status.success() {
        let detail = combined_output.trim();
        return Err(if detail.is_empty() {
            format!("Xray version command exited with status {}", output.status)
        } else {
            format!("Xray version command failed: {detail}")
        });
    }

    parse_xray_version(&combined_output)
}
