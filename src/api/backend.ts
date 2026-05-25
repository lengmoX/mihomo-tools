import { invoke } from "@tauri-apps/api/core";

export type InboundProtocol = "socks" | "http";
export type OutboundProtocol = "socks" | "vless" | "shadowsocks" | "trojan";

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

export type OutboundConfig = SocksOutboundConfig | VlessOutboundConfig | ShadowsocksOutboundConfig | TrojanOutboundConfig;

export interface SocksOutboundConfig {
  protocol: "socks";
  host: string;
  port: number;
  auth: AuthConfig | null;
}

export type VlessFlow = "xtls-rprx-vision" | "xtls-rprx-vision-udp443";
export type VlessTransportKind = "tcp" | "ws";

export interface VlessTransportConfig {
  kind: VlessTransportKind;
  path: string | null;
  host: string | null;
}

export interface VlessTlsConfig {
  serverName: string | null;
  fingerprint: string | null;
  allowInsecure: boolean | null;
}

export interface VlessRealityConfig {
  serverName: string | null;
  fingerprint: string | null;
  publicKey: string;
  shortId: string | null;
  spiderX: string | null;
}

export interface ImportSource {
  rawUrl: string;
  importedAt: number;
  warnings: string[];
}

export interface VlessOutboundConfig {
  protocol: "vless";
  address: string;
  port: number;
  id: string;
  encryption: string;
  flow: VlessFlow | null;
  level: number | null;
  transport: VlessTransportConfig;
  tls: VlessTlsConfig | null;
  reality: VlessRealityConfig | null;
  importSource: ImportSource | null;
}

export interface ShadowsocksOutboundConfig {
  protocol: "shadowsocks";
  address: string;
  port: number;
  method: string;
  password: string;
  uot: boolean;
  uotVersion: 1 | 2 | null;
  importSource: ImportSource | null;
}

export type TrojanTransportKind = "tcp" | "ws";

export interface TrojanTransportConfig {
  kind: TrojanTransportKind;
  path: string | null;
  host: string | null;
}

export interface TrojanTlsConfig {
  serverName: string | null;
  fingerprint: string | null;
  allowInsecure: boolean | null;
}

export interface TrojanRealityConfig {
  serverName: string | null;
  fingerprint: string | null;
  publicKey: string;
  shortId: string | null;
  spiderX: string | null;
}

export interface TrojanOutboundConfig {
  protocol: "trojan";
  address: string;
  port: number;
  password: string;
  email: string | null;
  level: number | null;
  transport: TrojanTransportConfig;
  tls: TrojanTlsConfig | null;
  reality: TrojanRealityConfig | null;
  importSource: ImportSource | null;
}

export interface ProxyRule {
  id: string;
  remark: string;
  enabled: boolean;
  inbound: InboundConfig;
  outbound: OutboundConfig;
  ipCheck: IpCheckResult | null;
}

export interface IpCheckResult {
  ip: string;
  country: string | null;
  checkedAt: number;
}

export interface AppState {
  schemaVersion: 2;
  rules: ProxyRule[];
}

export interface ParseOutboundUrlResult {
  outbound: OutboundConfig;
  displayName: string | null;
  warnings: string[];
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

export interface XrayVersionInfo {
  version: string;
  displayText: string;
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

export interface XrayStatItem {
  name: string;
  value: number;
}

export interface XrayQueryStatsResult {
  stat?: XrayStatItem[];
}

export const backend = {
  loadAppState: () => invoke<AppState>("load_app_state"),

  saveAppState: (state: AppState) => invoke<AppState>("save_app_state", { state }),

  saveAndApplyAppState: (state: AppState) => invoke<ApplyRulesResult>("save_and_apply_app_state", { state }),

  addRule: (request: NewRuleRequest) => invoke<AppState>("add_rule", { request }),

  duplicateRule: (ruleId: string) => invoke<AppState>("duplicate_rule", { ruleId }),

  updateRule: (request: UpdateRuleRequest) => invoke<AppState>("update_rule", { request }),

  setRuleEnabled: (ruleId: string, enabled: boolean) => invoke<AppState>("set_rule_enabled", { ruleId, enabled }),

  removeRule: (ruleId: string) => invoke<AppState>("remove_rule", { ruleId }),

  checkRuleIp: (ruleId: string) => invoke<AppState>("check_rule_ip", { ruleId }),

  checkRulesIpBatch: (ruleIds: string[]) => invoke<AppState>("check_rules_ip_batch", { ruleIds }),

  parseOutboundUrl: (input: string) => invoke<ParseOutboundUrlResult>("parse_outbound_url", { input }),

  parseSocksOutboundUrl: (input: string) => invoke<OutboundConfig>("parse_socks_outbound_url", { input }),

  generateXrayConfig: (state: AppState | null = null) => invoke<Record<string, unknown>>("generate_xray_config", { state }),

  writeXrayConfig: (state: AppState | null = null) => invoke<string>("write_xray_config", { state }),

  validateXrayBinary: () => invoke<XrayBinaryValidation>("validate_xray_binary"),

  getXrayVersion: () => invoke<XrayVersionInfo>("get_xray_version"),

  checkPortAvailable: (port: number, listen: string | null = null) =>
    invoke<PortAvailability>("check_port_available", { port, listen }),

  validateRulePorts: (state: AppState) => invoke<PortValidation>("validate_rule_ports", { state }),

  getRuntimePaths: () => invoke<RuntimePaths>("get_runtime_paths"),

  getRuntimeStatus: () => invoke<RuntimeStatus>("get_runtime_status"),

  startXray: () => invoke<RuntimeStatus>("start_xray"),

  stopXray: () => invoke<RuntimeStatus>("stop_xray"),

  restartXray: () => invoke<RuntimeStatus>("restart_xray"),

  queryXrayStats: () => invoke<XrayQueryStatsResult>("query_xray_stats"),
};
