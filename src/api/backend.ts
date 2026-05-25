import { invoke } from "@tauri-apps/api/core";

export type OutboundProtocol = "socks" | "vless" | "shadowsocks" | "trojan";

export interface AuthConfig {
  username: string;
  password: string;
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

export interface IpCheckResult {
  ip: string;
  country: string | null;
  checkedAt: number;
}

export interface ProxyNode {
  id: string;
  name: string;
  config: OutboundConfig;
}

export interface ProxyGroup {
  id: string;
  name: string;
  groupType: string; // "select"
  proxies: string[];
}

export interface ListenerRule {
  id: string;
  name: string;
  listen: string;
  port: number;
  inboundType: string; // "mixed" | "socks" | "http"
  groupId: string;
  enabled: boolean;
  ipCheck: IpCheckResult | null;
}

export interface AppState {
  schemaVersion: number; // 3
  proxies: ProxyNode[];
  groups: ProxyGroup[];
  rules: ListenerRule[];
}

export interface ParseOutboundUrlResult {
  outbound: OutboundConfig;
  displayName: string | null;
  warnings: string[];
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
  mihomoBinaryPath: string;
}

export interface MihomoBinaryValidation {
  path: string;
  exists: boolean;
  isFile: boolean;
  valid: boolean;
  message: string;
}

export interface MihomoVersionInfo {
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

export interface ProxyDeletionAnalysis {
  canDelete: boolean;
  isUniqueInAny: boolean;
  affectedGroups: string[];
  affectedRules: string[];
}

export interface ProxyGroupDeletionAnalysis {
  canDelete: boolean;
  affectedRules: string[];
}

export interface MihomoStatItem {
  name: string;
  value: number;
}

export interface MihomoQueryStatsResult {
  stat?: MihomoStatItem[];
}

export const backend = {
  loadAppState: () => invoke<AppState>("load_app_state"),

  saveAppState: (state: AppState) => invoke<AppState>("save_app_state", { state }),

  saveAndApplyAppState: (state: AppState) => invoke<ApplyRulesResult>("save_and_apply_app_state", { state }),

  addRule: (rule: ListenerRule) => invoke<AppState>("add_rule", { rule }),

  duplicateRule: (ruleId: string) => invoke<AppState>("duplicate_rule", { ruleId }),

  updateRule: (rule: ListenerRule) => invoke<AppState>("update_rule", { rule }),

  setRuleEnabled: (ruleId: string, enabled: boolean) => invoke<AppState>("set_rule_enabled", { ruleId, enabled }),

  removeRule: (ruleId: string) => invoke<AppState>("remove_rule", { ruleId }),

  deleteRule: (ruleId: string) => invoke<AppState>("delete_rule", { ruleId }),

  addProxyNode: (node: ProxyNode) => invoke<AppState>("add_proxy_node", { node }),

  updateProxyNode: (node: ProxyNode) => invoke<AppState>("update_proxy_node", { node }),

  analyzeProxyDeletion: (proxyId: string) => invoke<ProxyDeletionAnalysis>("analyze_proxy_deletion", { proxyId }),

  deleteProxyNodeSafe: (proxyId: string, forceDisableRules: boolean, replacementProxyId: string | null) =>
    invoke<AppState>("delete_proxy_node_safe", { proxyId, forceDisableRules, replacementProxyId }),

  addProxyGroup: (group: ProxyGroup) => invoke<AppState>("add_proxy_group", { group }),

  updateProxyGroup: (group: ProxyGroup) => invoke<AppState>("update_proxy_group", { group }),

  analyzeProxyGroupDeletion: (groupId: string) => invoke<ProxyGroupDeletionAnalysis>("analyze_proxy_group_deletion", { groupId }),

  deleteProxyGroupSafe: (groupId: string, forceDisableRules: boolean) =>
    invoke<AppState>("delete_proxy_group_safe", { groupId, forceDisableRules }),

  checkRuleIp: (ruleId: string) => invoke<AppState>("check_rule_ip", { ruleId }),

  checkRulesIpBatch: (ruleIds: string[]) => invoke<AppState>("check_rules_ip_batch", { ruleIds }),

  parseOutboundUrl: (input: string) => invoke<ParseOutboundUrlResult>("parse_outbound_url", { input }),

  parseSocksOutboundUrl: (input: string) => invoke<OutboundConfig>("parse_socks_outbound_url", { input }),

  generateMihomoConfig: (state: AppState | null = null) => invoke<Record<string, unknown>>("generate_mihomo_config", { state }),

  writeMihomoConfig: (state: AppState | null = null) => invoke<string>("write_mihomo_config", { state }),

  validateMihomoBinary: () => invoke<MihomoBinaryValidation>("validate_mihomo_binary"),

  getMihomoVersion: () => invoke<MihomoVersionInfo>("get_mihomo_version"),

  checkPortAvailable: (port: number, listen: string | null = null) =>
    invoke<PortAvailability>("check_port_available", { port, listen }),

  validateRulePorts: (state: AppState) => invoke<PortValidation>("validate_rule_ports", { state }),

  getRuntimePaths: () => invoke<RuntimePaths>("get_runtime_paths"),

  getRuntimeStatus: () => invoke<RuntimeStatus>("get_runtime_status"),

  startMihomo: () => invoke<RuntimeStatus>("start_mihomo"),

  stopMihomo: () => invoke<RuntimeStatus>("stop_mihomo"),

  restartMihomo: () => invoke<RuntimeStatus>("restart_mihomo"),

  queryMihomoStats: () => invoke<MihomoQueryStatsResult>("query_mihomo_stats"),
};
