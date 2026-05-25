# Frontend Backend Integration

This document describes how the React frontend should call the Rust/Tauri backend commands for `xray-tools`.

## Current Status

The backend API is implemented in `src-tauri/src/lib.rs` and registered with Tauri.

The frontend is not integrated yet. `src/App.tsx` is still the default Tauri template and currently calls:

```ts
invoke("greet", { name })
```

That command no longer exists in the backend. Before building the real UI, remove the template `greet` flow and replace it with the commands below.

## Invoke Conventions

Use Tauri v2's `invoke`:

```ts
import { invoke } from "@tauri-apps/api/core";
```

Command names are snake_case, matching the Rust command names.

Rust struct fields are serialized as camelCase. Rust command argument names should also be passed as camelCase from TypeScript. For example, Rust `rule_id` is called as `ruleId` from the frontend.

Backend errors are returned as strings, so frontend calls should wrap `invoke` in `try/catch` and display the caught message.

## TypeScript Types

Create a frontend API/types module such as `src/api/backend.ts` or `src/types/backend.ts` with these types.

```ts
export type InboundProtocol = "socks" | "http";
export type OutboundProtocol = "socks";

export interface AuthConfig {
  username: string;
  password: string;
}

export interface InboundConfig {
  protocol: InboundProtocol;
  listen: string;
  port: number;
  auth: AuthConfig | null;
}

export interface OutboundConfig {
  protocol: OutboundProtocol;
  host: string;
  port: number;
  auth: AuthConfig | null;
}

export interface IpCheckResult {
  ip: string;
  country: string | null;
  checkedAt: number;
}

export interface ProxyRule {
  id: string;
  remark: string;
  enabled: boolean;
  inbound: InboundConfig;
  outbound: OutboundConfig;
  ipCheck: IpCheckResult | null;
}

export interface AppState {
  schemaVersion: 1;
  rules: ProxyRule[];
}

export interface NewRuleRequest {
  remark?: string | null;
  inboundProtocol?: InboundProtocol | null;
  inboundListen?: string | null;
  inboundPort?: number | null;
  inboundAuth?: AuthConfig | null;
  outbound: OutboundConfig;
  enabled?: boolean | null;
}

export interface UpdateRuleRequest {
  id: string;
  remark: string;
  enabled: boolean;
  inbound: InboundConfig;
  outbound: OutboundConfig;
}

export interface RuntimeStatus {
  running: boolean;
  pid: number | null;
}

export interface RuntimePaths {
  runtimeRoot: string;
  dataDir: string;
  appStatePath: string;
  generatedConfigPath: string;
  xrayBinaryPath: string;
}

export interface XrayBinaryValidation {
  path: string;
  exists: boolean;
  isFile: boolean;
  valid: boolean;
  message: string;
}

export interface PortAvailability {
  port: number;
  available: boolean;
}

export interface PortValidation {
  hasDuplicatePorts: boolean;
  duplicatePorts: number[];
  unavailablePorts: number[];
  valid: boolean;
  message: string;
}

export interface ApplyRulesResult {
  state: AppState;
  generatedConfigPath: string;
  restarted: boolean;
  status: RuntimeStatus;
}
```

Use `null` for absent auth fields when sending a full object. Optional request fields can be omitted when calling `add_rule`.

## Recommended API Wrapper

Wrap raw `invoke` calls instead of calling command strings throughout components.

```ts
import { invoke } from "@tauri-apps/api/core";

export const backend = {
  loadAppState: () => invoke<AppState>("load_app_state"),

  saveAppState: (state: AppState) =>
    invoke<AppState>("save_app_state", { state }),

  saveAndApplyAppState: (state: AppState) =>
    invoke<ApplyRulesResult>("save_and_apply_app_state", { state }),

  addRule: (request: NewRuleRequest) =>
    invoke<AppState>("add_rule", { request }),

  updateRule: (request: UpdateRuleRequest) =>
    invoke<AppState>("update_rule", { request }),

  setRuleEnabled: (ruleId: string, enabled: boolean) =>
    invoke<AppState>("set_rule_enabled", { ruleId, enabled }),

  removeRule: (ruleId: string) =>
    invoke<AppState>("remove_rule", { ruleId }),

  checkRuleIp: (ruleId: string) =>
    invoke<AppState>("check_rule_ip", { ruleId }),

  parseSocksOutboundUrl: (input: string) =>
    invoke<OutboundConfig>("parse_socks_outbound_url", { input }),

  generateXrayConfig: (state: AppState | null = null) =>
    invoke<Record<string, unknown>>("generate_xray_config", { state }),

  writeXrayConfig: (state: AppState | null = null) =>
    invoke<string>("write_xray_config", { state }),

  validateXrayBinary: () =>
    invoke<XrayBinaryValidation>("validate_xray_binary"),

  checkPortAvailable: (port: number, listen: string | null = null) =>
    invoke<PortAvailability>("check_port_available", { port, listen }),

  validateRulePorts: (state: AppState) =>
    invoke<PortValidation>("validate_rule_ports", { state }),

  getRuntimePaths: () => invoke<RuntimePaths>("get_runtime_paths"),

  getRuntimeStatus: () => invoke<RuntimeStatus>("get_runtime_status"),

  startXray: () => invoke<RuntimeStatus>("start_xray"),

  stopXray: () => invoke<RuntimeStatus>("stop_xray"),

  restartXray: () => invoke<RuntimeStatus>("restart_xray"),
};
```

Aliases also exist for compatibility:

- `delete_rule` is equivalent to `remove_rule`.
- `parse_socks_proxy_url` is equivalent to `parse_socks_outbound_url`.
- `get_xray_status` is equivalent to `get_runtime_status`.

Prefer the primary names shown in the wrapper above.

## Command Reference

### State Commands

`load_app_state`

- Args: none
- Returns: `AppState`
- Behavior: creates `data/` if needed and returns an empty default state when `data/app-state.json` does not exist.

`save_app_state`

- Args: `{ state: AppState }`
- Returns: `AppState`
- Behavior: validates and writes `data/app-state.json` only. It does not regenerate config or restart Xray.

`save_and_apply_app_state`

- Args: `{ state: AppState }`
- Returns: `ApplyRulesResult`
- Behavior: validates and writes `data/app-state.json`, writes `data/generated-config.json`, and restarts Xray only if it is already running.
- Recommended frontend save action: use this command when the user clicks Save or toggles a rule and expects the running core to pick up the change.

### Rule Commands

`add_rule`

- Args: `{ request: NewRuleRequest }`
- Returns: `AppState`
- Behavior: creates a new rule with a generated stable id. Missing local port uses a random available port from `50000..=65535`. Missing inbound protocol defaults to `socks`. Missing listen address defaults to `127.0.0.1`. Missing `enabled` defaults to `true`.

`update_rule`

- Args: `{ request: UpdateRuleRequest }`
- Returns: `AppState`
- Behavior: replaces an existing rule by id.

`set_rule_enabled`

- Args: `{ ruleId: string, enabled: boolean }`
- Returns: `AppState`
- Behavior: updates only the rule's enabled flag and saves state. It does not regenerate config or restart Xray by itself.

`remove_rule`

- Args: `{ ruleId: string }`
- Returns: `AppState`
- Behavior: removes a rule by id.

`check_rule_ip`

- Args: `{ ruleId: string }`
- Returns: `AppState`
- Behavior: requires the managed Xray process to be running and the rule to be enabled. The backend requests `https://ipinfo.io/json` through the rule's local inbound proxy, stores the returned IP address, country code, and check timestamp in `rule.ipCheck`, then writes `data/app-state.json`. Frontend should display the cached `ipCheck` value by default and call this command only when the user explicitly checks again.

### Proxy Parsing

`parse_socks_outbound_url`

- Args: `{ input: string }`
- Returns: `OutboundConfig`
- Supported formats:
  - `socks5://host:port`
  - `socks5://user:pass@host:port`
  - `socks://host:port`
  - `socks://user:pass@host:port`

Use this for a paste-to-parse UI. On success, fill the outbound form fields from the returned config. On error, show the backend error message.

### Config Commands

`generate_xray_config`

- Args: `{ state: AppState | null }`
- Returns: generated Xray config JSON
- Behavior: generates and writes `data/generated-config.json`. If `state` is `null`, it loads state from disk.

`write_xray_config`

- Args: `{ state: AppState | null }`
- Returns: generated config path as a string
- Behavior: writes `data/generated-config.json`. If `state` is `null`, it loads state from disk.

Only enabled rules are included in the generated Xray config. Disabled rules stay in app state but do not produce inbounds, outbounds, or routing rules.

### Validation Commands

`validate_xray_binary`

- Args: none
- Returns: `XrayBinaryValidation`
- Behavior: checks whether `xray/xray.exe` exists next to the runtime root.

`check_port_available`

- Args: `{ port: number, listen?: string | null }`
- Returns: `PortAvailability`
- Behavior: checks whether the local listen/port can be bound. Defaults listen to `127.0.0.1`.

`validate_rule_ports`

- Args: `{ state: AppState }`
- Returns: `PortValidation`
- Behavior: validates duplicate enabled local ports and reports conflicts. This is useful before saving or starting Xray.

### Runtime Commands

`get_runtime_paths`

- Args: none
- Returns: `RuntimePaths`
- Behavior: returns the resolved portable runtime paths and creates `data/` if needed.

`get_runtime_status`

- Args: none
- Returns: `RuntimeStatus`
- Behavior: reports whether the backend-managed Xray child process is running.

`start_xray`

- Args: none
- Returns: `RuntimeStatus`
- Behavior: loads app state from disk, validates enabled rule ports, writes generated config, validates `xray/xray.exe`, and starts Xray with `run -config <generated-config-path>`.

`stop_xray`

- Args: none
- Returns: `RuntimeStatus`
- Behavior: stops the backend-managed Xray child process if present.

`restart_xray`

- Args: none
- Returns: `RuntimeStatus`
- Behavior: stops the current backend-managed child process and starts Xray again from the saved state.

## Recommended Frontend Flow

### App Startup

1. Call `get_runtime_paths` to show users where to place `xray/xray.exe` if needed.
2. Call `validate_xray_binary` and display a warning if `valid` is false.
3. Call `load_app_state` and initialize React state.
4. Call `get_runtime_status` and initialize the start/stop controls.

### Add Rule

1. Parse pasted upstream SOCKS URL with `parse_socks_outbound_url` when applicable.
2. Call `add_rule` with `NewRuleRequest`.
3. Put the returned `AppState` into React state.
4. If the app should immediately apply changes, call `save_and_apply_app_state` with the returned state.

### Edit Rule

1. Update the rule locally in React state.
2. Optionally call `validate_rule_ports` before saving.
3. Call `save_and_apply_app_state`.
4. Replace React state with `result.state`.
5. Refresh runtime controls from `result.status`.

### Enable Or Disable Rule

For immediate apply, prefer editing the local `AppState` and calling `save_and_apply_app_state` once.

Use `set_rule_enabled` only when you need a lightweight backend save for the enabled flag without applying the change to the running Xray process.

### Start Xray

1. Call `validate_xray_binary`.
2. Call `validate_rule_ports` with current state.
3. Call `save_and_apply_app_state` if there are unsaved UI edits.
4. Call `start_xray`.
5. Store the returned `RuntimeStatus`.

### Stop Or Restart Xray

- Stop button: call `stop_xray`.
- Restart button: call `restart_xray`.
- After either command, update UI controls from the returned `RuntimeStatus`.

## Important UI Notes

- Rule `remark` is user-visible only. It is persisted but not used for generated Xray tags.
- Rule `id` is the stable backend identifier. Do not regenerate it on the frontend.
- Disabled rules should remain visible and editable in the UI.
- Disabled rules are not included in generated Xray config.
- If Xray is running, `save_and_apply_app_state` restarts it so new rules take effect.
- If Xray is stopped, `save_and_apply_app_state` does not start it automatically.
- `save_app_state` is only for saving without applying runtime changes.

## Error Handling

Use one shared helper for frontend calls:

```ts
export async function callBackend<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(message);
  }
}
```

Display backend error strings directly near the relevant form or control. Common errors include missing Xray binary, duplicate local ports, invalid proxy URL format, and unsupported state schema version.
