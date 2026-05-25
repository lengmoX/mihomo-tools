import { useEffect, useMemo, useState, type FormEvent, type ReactElement } from "react";
import {
  backend, type AppState, type AuthConfig, type OutboundConfig,
  type OutboundProtocol, type ListenerRule, type ProxyNode, type ProxyGroup,
  type RuntimeStatus, type VlessFlow, type MihomoBinaryValidation, type MihomoVersionInfo,
  type ProxyDeletionAnalysis, type ProxyGroupDeletionAnalysis
} from "./api/backend";
import { RuntimeHero } from "./features/runtime/RuntimeHero";
import type { StatusMeta } from "./features/runtime/runtime-types";
import "./App.css";

type TabName = "rules" | "groups" | "proxies";

type RuleFormState = {
  name: string;
  listen: string;
  port: string;
  inboundType: string;
  groupId: string;
  enabled: boolean;
};

type GroupFormState = {
  name: string;
  groupType: string;
  proxies: string[];
};

type NodeFormState = {
  name: string;
  protocol: OutboundProtocol;
  outboundProxyUrl: string;
  address: string;
  port: string;
  socksUsername: string;
  socksPassword: string;
  vlessId: string;
  vlessEncryption: string;
  vlessFlow: "" | VlessFlow;
  vlessLevel: string;
  vlessSecurity: "none" | "tls" | "reality";
  vlessServerName: string;
  vlessFingerprint: string;
  vlessRealityPublicKey: string;
  vlessRealityShortId: string;
  vlessRealitySpiderX: string;
  vlessAllowInsecure: boolean;
  vlessTransportKind: "tcp" | "ws";
  vlessTransportPath: string;
  vlessTransportHost: string;
  shadowsocksMethod: string;
  shadowsocksPassword: string;
  shadowsocksUot: boolean;
  shadowsocksUotVersion: "" | "1" | "2";
  trojanPassword: string;
  trojanEmail: string;
  trojanLevel: string;
  trojanSecurity: "none" | "tls" | "reality";
  trojanServerName: string;
  trojanFingerprint: string;
  trojanRealityPublicKey: string;
  trojanRealityShortId: string;
  trojanRealitySpiderX: string;
  trojanAllowInsecure: boolean;
  trojanTransportKind: "tcp" | "ws";
  trojanTransportPath: string;
  trojanTransportHost: string;
  importedOutbound: OutboundConfig | null;
};

type ModalMode = "create" | "edit";

type RuleModalState = {
  mode: ModalMode;
  editingId: string | null;
  draft: RuleFormState;
};

type GroupModalState = {
  mode: ModalMode;
  editingId: string | null;
  draft: GroupFormState;
};

type NodeModalState = {
  mode: ModalMode;
  editingId: string | null;
  draft: NodeFormState;
};

type IconName =
  | "play"
  | "stop"
  | "restart"
  | "save"
  | "copy"
  | "edit"
  | "delete"
  | "plus"
  | "check"
  | "scan"
  | "close"
  | "search"
  | "layers"
  | "info";

type RuntimeActionName = "play" | "stop" | "restart" | "save";

type RuntimeAction = {
  name: RuntimeActionName;
  label: string;
  title: string;
};

type BusyAction = RuntimeActionName | "startup" | "toggle" | "delete" | "rule" | "batch-ip" | `ip-${string}` | "";

type ToastTone = "success" | "warning" | "error";

type ToastNotification = {
  id: number;
  tone: ToastTone;
  message: string;
};

const emptyAppState: AppState = {
  schemaVersion: 3,
  proxies: [],
  groups: [],
  rules: [],
};

const inboundTypeOptions = [
  { value: "mixed", label: "Mixed (SOCKS + HTTP)" },
  { value: "socks", label: "SOCKS5" },
  { value: "http", label: "HTTP" },
];

const outboundProtocolOptions: OutboundProtocol[] = ["socks", "vless", "shadowsocks", "trojan"];
const vlessFlowOptions: VlessFlow[] = ["xtls-rprx-vision", "xtls-rprx-vision-udp443"];
const minAutoInboundPort = 50_000;
const maxAutoInboundPort = 65_535;
const toastAutoDismissMs = 4_200;
const shadowsocksMethodOptions = [
  "2022-blake3-aes-128-gcm",
  "2022-blake3-aes-256-gcm",
  "2022-blake3-chacha20-poly1305",
  "aes-256-gcm",
  "aes-128-gcm",
  "chacha20-poly1305",
  "chacha20-ietf-poly1305",
  "xchacha20-poly1305",
  "xchacha20-ietf-poly1305",
] as const;



const runtimeActions: RuntimeAction[] = [
  { name: "play", label: "启动 Mihomo", title: "启动" },
  { name: "stop", label: "停止 Mihomo", title: "停止" },
  { name: "restart", label: "重启 Mihomo", title: "重启" },
  { name: "save", label: "保存配置", title: "保存配置" },
];

const iconPaths: Record<IconName, ReactElement> = {
  play: <path d="M8 5.5v13l10-6.5-10-6.5Z" />,
  stop: <path d="M7 7h10v10H7z" />,
  restart: <path d="M17.6 8.2A6.5 6.5 0 1 0 18 15h-2.2A4.5 4.5 0 1 1 16 9.7l-2.4 2.4H20V5.7l-2.4 2.5Z" />,
  save: <path d="M6 5h10.2L19 7.8V19H5V5h1Zm2 2v4h7V7H8Zm0 8v2h8v-2H8Z" />,
  copy: <path d="M8 8h9v11H8V8Zm-3 6V5h9v2H7v7H5Z" />,
  edit: <path d="m6 16.8.5-3.1 7.8-7.8 2.8 2.8-7.8 7.8-3.3.3Zm9.7-12.3 2.8 2.8 1-1a2 2 0 0 0-2.8-2.8l-1 1Z" />,
  delete: <path d="M8 7V5h8v2h4v2H4V7h4Zm-1 4h10l-.8 8H7.8L7 11Z" />,
  plus: <path d="M11 5h2v6h6v2h-6v6h-2v-6H5v-2h6V5Z" />,
  check: <path d="m9.4 15.6-3.2-3.2-1.4 1.4 4.6 4.6 9-9L17 8l-7.6 7.6Z" />,
  scan: <path d="M5 7V5h5v2H7v3H5V7Zm12-2h2v5h-2V7h-3V5h3ZM7 17h3v2H5v-5h2v3Zm12-3v5h-5v-2h3v-3h2ZM8 11h8v2H8v-2Z" />,
  close: <path d="m6.4 5 5.6 5.6L17.6 5 19 6.4 13.4 12l5.6 5.6-1.4 1.4-5.6-5.6L6.4 19 5 17.6l5.6-5.6L5 6.4 6.4 5Z" />,
  search: <path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5Zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14Z" />,
  layers: <path d="m12 16.5-9-4.9 1.5-.8 7.5 4.1 7.5-4.1 1.5.8-9 4.9zm0-3.9-9-4.9 1.5-.8 7.5 4.1 7.5-4.1 1.5.8-9 4.9zm0-3.9L3 3.8l9 4.9 9-4.9-9 4.9z" />,
  info: <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z" />,
};

function Icon({ name }: { name: IconName }) {
  return (
    <svg className="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      {iconPaths[name]}
    </svg>
  );
}

function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

function formatTime() {
  return new Date().toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" });
}



function formatLocalInboundAddress(listen: string, port: number) {
  const shortListen = listen === "127.0.0.1" ? "127" : listen === "0.0.0.0" ? "0" : listen;
  return `${shortListen}:${port}`;
}

function randomAutoInboundPort() {
  const portCount = maxAutoInboundPort - minAutoInboundPort + 1;
  return minAutoInboundPort + Math.floor(Math.random() * portCount);
}

function formatOutboundProtocol(protocol: OutboundProtocol) {
  if (protocol === "socks") return "SOCKS5";
  if (protocol === "vless") return "VLESS";
  if (protocol === "trojan") return "Trojan";
  return "Shadowsocks";
}

function getOutboundAddress(outbound: OutboundConfig) {
  return outbound.protocol === "socks" ? `${outbound.host}:${outbound.port}` : `${outbound.address}:${outbound.port}`;
}

function formatCountryFlag(country: string | null) {
  if (country === null || !/^[A-Za-z]{2}$/.test(country)) {
    return "--";
  }
  return country
    .toUpperCase()
    .split("")
    .map((character) => String.fromCodePoint(127397 + character.charCodeAt(0)))
    .join("");
}

function toNodeDraft(node: ProxyNode): NodeFormState {
  const address = node.config.protocol === "socks" ? node.config.host : node.config.address;
  const socksAuth = node.config.protocol === "socks" ? node.config.auth : null;
  const vlessSecurity = node.config.protocol === "vless" && node.config.reality !== null ? "reality" : node.config.protocol === "vless" && node.config.tls !== null ? "tls" : "none";
  const trojanSecurity = node.config.protocol === "trojan" && node.config.reality !== null ? "reality" : node.config.protocol === "trojan" && node.config.tls !== null ? "tls" : "none";

  return {
    name: node.name,
    protocol: node.config.protocol,
    outboundProxyUrl: "",
    address,
    port: String(node.config.port),
    socksUsername: socksAuth?.username ?? "",
    socksPassword: socksAuth?.password ?? "",
    vlessId: node.config.protocol === "vless" ? node.config.id : "",
    vlessEncryption: node.config.protocol === "vless" ? node.config.encryption : "none",
    vlessFlow: node.config.protocol === "vless" ? node.config.flow ?? "" : "",
    vlessLevel: node.config.protocol === "vless" ? String(node.config.level ?? "") : "",
    vlessSecurity,
    vlessServerName: node.config.protocol === "vless" ? node.config.reality?.serverName ?? node.config.tls?.serverName ?? "" : "",
    vlessFingerprint: node.config.protocol === "vless" ? node.config.reality?.fingerprint ?? node.config.tls?.fingerprint ?? "" : "",
    vlessRealityPublicKey: node.config.protocol === "vless" ? node.config.reality?.publicKey ?? "" : "",
    vlessRealityShortId: node.config.protocol === "vless" ? node.config.reality?.shortId ?? "" : "",
    vlessRealitySpiderX: node.config.protocol === "vless" ? node.config.reality?.spiderX ?? "" : "",
    vlessAllowInsecure: node.config.protocol === "vless" ? !!node.config.tls?.allowInsecure : false,
    vlessTransportKind: node.config.protocol === "vless" ? node.config.transport.kind : "tcp",
    vlessTransportPath: node.config.protocol === "vless" ? node.config.transport.path ?? "" : "",
    vlessTransportHost: node.config.protocol === "vless" ? node.config.transport.host ?? "" : "",
    shadowsocksMethod: node.config.protocol === "shadowsocks" ? node.config.method : shadowsocksMethodOptions[0],
    shadowsocksPassword: node.config.protocol === "shadowsocks" ? node.config.password : "",
    shadowsocksUot: node.config.protocol === "shadowsocks" ? node.config.uot : false,
    shadowsocksUotVersion: node.config.protocol === "shadowsocks" ? String(node.config.uotVersion ?? "") as "" | "1" | "2" : "",
    trojanPassword: node.config.protocol === "trojan" ? node.config.password : "",
    trojanEmail: node.config.protocol === "trojan" ? node.config.email ?? "" : "",
    trojanLevel: node.config.protocol === "trojan" ? String(node.config.level ?? "") : "",
    trojanSecurity,
    trojanServerName: node.config.protocol === "trojan" ? node.config.reality?.serverName ?? node.config.tls?.serverName ?? "" : "",
    trojanFingerprint: node.config.protocol === "trojan" ? node.config.reality?.fingerprint ?? node.config.tls?.fingerprint ?? "" : "",
    trojanRealityPublicKey: node.config.protocol === "trojan" ? node.config.reality?.publicKey ?? "" : "",
    trojanRealityShortId: node.config.protocol === "trojan" ? node.config.reality?.shortId ?? "" : "",
    trojanRealitySpiderX: node.config.protocol === "trojan" ? node.config.reality?.spiderX ?? "" : "",
    trojanAllowInsecure: node.config.protocol === "trojan" ? !!node.config.tls?.allowInsecure : false,
    trojanTransportKind: node.config.protocol === "trojan" ? node.config.transport.kind : "tcp",
    trojanTransportPath: node.config.protocol === "trojan" ? node.config.transport.path ?? "" : "",
    trojanTransportHost: node.config.protocol === "trojan" ? node.config.transport.host ?? "" : "",
    importedOutbound: node.config.protocol === "socks" ? null : node.config,
  };
}

function createEmptyNodeDraft(nextIndex: number): NodeFormState {
  return {
    name: `节点-${nextIndex}`,
    protocol: "socks",
    outboundProxyUrl: "",
    address: "",
    port: "1080",
    socksUsername: "",
    socksPassword: "",
    vlessId: "",
    vlessEncryption: "none",
    vlessFlow: "",
    vlessLevel: "",
    vlessSecurity: "none",
    vlessServerName: "",
    vlessFingerprint: "",
    vlessRealityPublicKey: "",
    vlessRealityShortId: "",
    vlessRealitySpiderX: "",
    vlessAllowInsecure: false,
    vlessTransportKind: "tcp",
    vlessTransportPath: "",
    vlessTransportHost: "",
    shadowsocksMethod: shadowsocksMethodOptions[0],
    shadowsocksPassword: "",
    shadowsocksUot: false,
    shadowsocksUotVersion: "",
    trojanPassword: "",
    trojanEmail: "",
    trojanLevel: "",
    trojanSecurity: "tls",
    trojanServerName: "",
    trojanFingerprint: "",
    trojanRealityPublicKey: "",
    trojanRealityShortId: "",
    trojanRealitySpiderX: "",
    trojanAllowInsecure: false,
    trojanTransportKind: "tcp",
    trojanTransportPath: "",
    trojanTransportHost: "",
    importedOutbound: null,
  };
}

function parsePort(portValue: string) {
  const port = Number(portValue);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return null;
  }
  return port;
}



function parseOptionalNonNegativeInteger(value: string) {
  if (value.trim() === "") {
    return null;
  }
  const numberValue = Number(value);
  return Number.isInteger(numberValue) && numberValue >= 0 ? numberValue : Number.NaN;
}

function buildAuthConfig(username: string, password: string): AuthConfig | null {
  const trimmedUsername = username.trim();
  if (trimmedUsername === "" && password === "") {
    return null;
  }
  if (trimmedUsername === "" || password === "") {
    return null;
  }
  return { username: trimmedUsername, password };
}



function buildOutboundFromDraft(draft: NodeFormState): OutboundConfig | null {
  const port = parsePort(draft.port);
  const vlessLevel = parseOptionalNonNegativeInteger(draft.vlessLevel);

  if (port === null || Number.isNaN(vlessLevel)) {
    return null;
  }

  if (draft.protocol === "vless") {
    const tlsFields = {
      serverName: draft.vlessServerName.trim() === "" ? null : draft.vlessServerName.trim(),
      fingerprint: draft.vlessFingerprint.trim() === "" ? null : draft.vlessFingerprint.trim(),
      allowInsecure: draft.vlessAllowInsecure,
    };
    const securityFields = {
      serverName: draft.vlessServerName.trim() === "" ? null : draft.vlessServerName.trim(),
      fingerprint: draft.vlessFingerprint.trim() === "" ? null : draft.vlessFingerprint.trim(),
    };

    return {
      protocol: "vless",
      address: draft.address.trim(),
      port,
      id: draft.vlessId.trim(),
      encryption: draft.vlessEncryption.trim(),
      flow: draft.vlessFlow === "" ? null : draft.vlessFlow,
      level: vlessLevel,
      transport: {
        kind: draft.vlessTransportKind,
        path: draft.vlessTransportKind === "ws" && draft.vlessTransportPath.trim() !== "" ? draft.vlessTransportPath.trim() : null,
        host: draft.vlessTransportKind === "ws" && draft.vlessTransportHost.trim() !== "" ? draft.vlessTransportHost.trim() : null,
      },
      tls: draft.vlessSecurity === "tls" ? tlsFields : null,
      reality:
        draft.vlessSecurity === "reality"
          ? {
              ...securityFields,
              publicKey: draft.vlessRealityPublicKey.trim(),
              shortId: draft.vlessRealityShortId.trim() === "" ? null : draft.vlessRealityShortId.trim(),
              spiderX: draft.vlessRealitySpiderX.trim() === "" ? null : draft.vlessRealitySpiderX.trim(),
            }
          : null,
      importSource: draft.importedOutbound?.protocol === "vless" ? draft.importedOutbound.importSource : null,
    };
  }

  if (draft.protocol === "shadowsocks") {
    return {
      protocol: "shadowsocks",
      address: draft.address.trim(),
      port,
      method: draft.shadowsocksMethod.trim(),
      password: draft.shadowsocksPassword,
      uot: draft.shadowsocksUot,
      uotVersion: draft.shadowsocksUot && draft.shadowsocksUotVersion !== "" ? Number(draft.shadowsocksUotVersion) as 1 | 2 : null,
      importSource: draft.importedOutbound?.protocol === "shadowsocks" ? draft.importedOutbound.importSource : null,
    };
  }

  if (draft.protocol === "trojan") {
    const tlsFields = {
      serverName: draft.trojanServerName.trim() === "" ? null : draft.trojanServerName.trim(),
      fingerprint: draft.trojanFingerprint.trim() === "" ? null : draft.trojanFingerprint.trim(),
      allowInsecure: draft.trojanAllowInsecure,
    };
    const securityFields = {
      serverName: draft.trojanServerName.trim() === "" ? null : draft.trojanServerName.trim(),
      fingerprint: draft.trojanFingerprint.trim() === "" ? null : draft.trojanFingerprint.trim(),
    };
    const trojanLevel = parseOptionalNonNegativeInteger(draft.trojanLevel);

    return {
      protocol: "trojan",
      address: draft.address.trim(),
      port,
      password: draft.trojanPassword,
      email: draft.trojanEmail.trim() === "" ? null : draft.trojanEmail.trim(),
      level: Number.isNaN(trojanLevel) ? null : trojanLevel,
      transport: {
        kind: draft.trojanTransportKind,
        path: draft.trojanTransportKind === "ws" && draft.trojanTransportPath.trim() !== "" ? draft.trojanTransportPath.trim() : null,
        host: draft.trojanTransportKind === "ws" && draft.trojanTransportHost.trim() !== "" ? draft.trojanTransportHost.trim() : null,
      },
      tls: draft.trojanSecurity === "tls" ? tlsFields : null,
      reality:
        draft.trojanSecurity === "reality"
          ? {
              ...securityFields,
              publicKey: draft.trojanRealityPublicKey.trim(),
              shortId: draft.trojanRealityShortId.trim() === "" ? null : draft.trojanRealityShortId.trim(),
              spiderX: draft.trojanRealitySpiderX.trim() === "" ? null : draft.trojanRealitySpiderX.trim(),
            }
          : null,
      importSource: draft.importedOutbound?.protocol === "trojan" ? draft.importedOutbound.importSource : null,
    };
  }

  return {
    protocol: "socks",
    host: draft.address.trim(),
    port,
    auth: buildAuthConfig(draft.socksUsername, draft.socksPassword),
  };
}

function applyOutboundToDraft(draft: NodeFormState, outbound: OutboundConfig): NodeFormState {
  const nextDraft: NodeFormState = {
    ...draft,
    protocol: outbound.protocol,
    address: outbound.protocol === "socks" ? outbound.host : outbound.address,
    port: String(outbound.port),
    importedOutbound: outbound.protocol === "socks" ? null : outbound,
  };

  if (outbound.protocol === "socks") {
    return {
      ...nextDraft,
      socksUsername: outbound.auth?.username ?? "",
      socksPassword: outbound.auth?.password ?? "",
    };
  }

  if (outbound.protocol === "vless") {
    const security = outbound.reality !== null ? "reality" : outbound.tls !== null ? "tls" : "none";
    return {
      ...nextDraft,
      vlessId: outbound.id,
      vlessEncryption: outbound.encryption,
      vlessFlow: outbound.flow ?? "",
      vlessLevel: String(outbound.level ?? ""),
      vlessSecurity: security,
      vlessServerName: outbound.reality?.serverName ?? outbound.tls?.serverName ?? "",
      vlessFingerprint: outbound.reality?.fingerprint ?? outbound.tls?.fingerprint ?? "",
      vlessRealityPublicKey: outbound.reality?.publicKey ?? "",
      vlessRealityShortId: outbound.reality?.shortId ?? "",
      vlessRealitySpiderX: outbound.reality?.spiderX ?? "",
      vlessAllowInsecure: outbound.tls?.allowInsecure ?? false,
      vlessTransportKind: outbound.transport.kind,
      vlessTransportPath: outbound.transport.path ?? "",
      vlessTransportHost: outbound.transport.host ?? "",
    };
  }

  if (outbound.protocol === "trojan") {
    const security = outbound.reality !== null ? "reality" : outbound.tls !== null ? "tls" : "none";
    return {
      ...nextDraft,
      trojanPassword: outbound.password,
      trojanEmail: outbound.email ?? "",
      trojanLevel: String(outbound.level ?? ""),
      trojanSecurity: security,
      trojanServerName: outbound.reality?.serverName ?? outbound.tls?.serverName ?? "",
      trojanFingerprint: outbound.reality?.fingerprint ?? outbound.tls?.fingerprint ?? "",
      trojanRealityPublicKey: outbound.reality?.publicKey ?? "",
      trojanRealityShortId: outbound.reality?.shortId ?? "",
      trojanRealitySpiderX: outbound.reality?.spiderX ?? "",
      trojanAllowInsecure: outbound.tls?.allowInsecure ?? false,
      trojanTransportKind: outbound.transport.kind,
      trojanTransportPath: outbound.transport.path ?? "",
      trojanTransportHost: outbound.transport.host ?? "",
    };
  }

  return {
    ...nextDraft,
    shadowsocksMethod: outbound.method,
    shadowsocksPassword: outbound.password,
    shadowsocksUot: outbound.uot,
    shadowsocksUotVersion: outbound.uotVersion === null ? "" : String(outbound.uotVersion) as "1" | "2",
  };
}

function isOutboundProtocol(value: string): value is OutboundProtocol {
  return outboundProtocolOptions.some((protocol) => protocol === value);
}

function buildInboundProxyUrl(rule: ListenerRule) {
  const scheme = rule.inboundType === "socks" ? "socks5" : "http";
  return `${scheme}://${rule.listen}:${rule.port}`;
}



function App() {
  const [appState, setAppState] = useState<AppState>(emptyAppState);
  const [theme, setTheme] = useState<"system" | "light" | "dark">(() => {
    const saved = localStorage.getItem("mihomo-tools-theme");
    return (saved === "light" || saved === "dark" || saved === "system") ? saved : "system";
  });
  const [runtimeStatus, setRuntimeStatus] = useState<RuntimeStatus>({ running: false, pid: null });
  const [mihomoValidation, setMihomoValidation] = useState<MihomoBinaryValidation | null>(null);
  const [mihomoVersion, setMihomoVersion] = useState<MihomoVersionInfo | null>(null);
  const [activeTab, setActiveTab] = useState<TabName>("rules");

  const [selectedRuleIds, setSelectedRuleIds] = useState<string[]>([]);
  const [copiedKey, setCopiedKey] = useState<string>("");
  const [lastSavedAt, setLastSavedAt] = useState("尚未保存");
  const [toastNotification, setToastNotification] = useState<ToastNotification | null>(null);
  const [busyAction, setBusyAction] = useState<BusyAction>("startup");
  const [searchQuery, setSearchQuery] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [checkingRuleIds, setCheckingRuleIds] = useState<string[]>([]);

  // Modals state
  const [ruleModal, setRuleModal] = useState<RuleModalState | null>(null);
  const [groupModal, setGroupModal] = useState<GroupModalState | null>(null);
  const [nodeModal, setNodeModal] = useState<NodeModalState | null>(null);

  // Safety Deletion Modals state
  const [proxyDeleteAnalysis, setProxyDeleteAnalysis] = useState<{
    proxyId: string;
    proxyName: string;
    analysis: ProxyDeletionAnalysis;
    forceDisableRules: boolean;
    replacementProxyId: string | null;
  } | null>(null);

  const [groupDeleteAnalysis, setGroupDeleteAnalysis] = useState<{
    groupId: string;
    groupName: string;
    analysis: ProxyGroupDeletionAnalysis;
    forceDisableRules: boolean;
  } | null>(null);

  // Batch import state
  const [batchAddOpen, setBatchAddOpen] = useState(false);
  const [batchAddText, setBatchAddText] = useState("");
  const [batchAddInboundType, setBatchAddInboundType] = useState("mixed");
  const [batchAddInboundListen, setBatchAddInboundListen] = useState("127.0.0.1");
  const [batchAddError, setBatchAddError] = useState("");

  const [ruleFormError, setRuleFormError] = useState("");
  const [groupFormError, setGroupFormError] = useState("");
  const [nodeFormError, setNodeFormError] = useState("");

  const isBusy = busyAction !== "";

  // Visibility & polling
  useEffect(() => {
    let timerId: number | null = null;
    const pollStatus = async () => {
      if (document.visibilityState !== "visible") return;
      try {
        const status = await backend.getRuntimeStatus();
        setRuntimeStatus(status);
      } catch (err) {
        console.error("Failed to check runtime status:", err);
      }
    };
    pollStatus();
    timerId = window.setInterval(pollStatus, 3000);
    return () => {
      if (timerId) window.clearInterval(timerId);
    };
  }, []);

  // Theme application
  useEffect(() => {
    const updateThemeAttribute = (currentTheme: "system" | "light" | "dark") => {
      if (currentTheme === "system") {
        const isSystemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        document.documentElement.setAttribute("data-theme", isSystemDark ? "dark" : "light");
      } else {
        document.documentElement.setAttribute("data-theme", currentTheme);
      }
    };
    updateThemeAttribute(theme);

    if (theme === "system") {
      const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
      const handleChange = (event: MediaQueryListEvent) => {
        document.documentElement.setAttribute("data-theme", event.matches ? "dark" : "light");
      };
      mediaQuery.addEventListener("change", handleChange);
      return () => mediaQuery.removeEventListener("change", handleChange);
    }
  }, [theme]);

  const handleThemeChange = (nextTheme: "system" | "light" | "dark") => {
    setTheme(nextTheme);
    localStorage.setItem("mihomo-tools-theme", nextTheme);
  };

  // State initialization
  useEffect(() => {
    let shouldUpdate = true;
    async function loadBackendState() {
      setBusyAction("startup");
      try {
        const [validation, state, status, version] = await Promise.all([
          backend.validateMihomoBinary(),
          backend.loadAppState(),
          backend.getRuntimeStatus(),
          backend.getMihomoVersion().catch(() => null),
        ]);
        if (!shouldUpdate) return;
        setMihomoValidation(validation);
        setAppState(state);
        setRuntimeStatus(status);
        setMihomoVersion(version);
        setLastSavedAt("已从磁盘载入");
      } catch (error) {
        if (shouldUpdate) {
          showToast("error", `启动时读取后端状态失败：${getErrorMessage(error)}`);
        }
      } finally {
        if (shouldUpdate) setBusyAction("");
      }
    }
    loadBackendState();
    return () => {
      shouldUpdate = false;
    };
  }, []);

  useEffect(() => {
    if (toastNotification === null) return;
    const timeoutId = window.setTimeout(() => {
      setToastNotification((curr) => curr?.id === toastNotification.id ? null : curr);
    }, toastAutoDismissMs);
    return () => window.clearTimeout(timeoutId);
  }, [toastNotification]);

  useEffect(() => {
    if (mihomoValidation !== null && !mihomoValidation.valid) {
      showToast("warning", `${mihomoValidation.message}。请将 Mihomo 二进制文件放置在：${mihomoValidation.path}`);
    }
  }, [mihomoValidation]);

  const statusMeta = useMemo<StatusMeta>(() => {
    if (busyAction === "startup") {
      return { label: "加载中", detail: "正在载入应用配置和组件", tone: "is-restarting" };
    }
    if (busyAction === "restart") {
      return { label: "重启中", detail: "正在重新拉起 Mihomo 进程", tone: "is-restarting" };
    }
    if (runtimeStatus.running) {
      const pidText = runtimeStatus.pid ? ` (PID ${runtimeStatus.pid})` : "";
      return { label: "运行中", detail: `Mihomo 核心运行良好，本地端口已映射${pidText}`, tone: "is-running" };
    }
    return { label: "已停止", detail: "已停止转发，等待开启代理服务", tone: "is-stopped" };
  }, [busyAction, runtimeStatus]);

  function showToast(tone: ToastTone, message: string) {
    setToastNotification({ id: Date.now(), tone, message });
  }

  async function saveAndApplyState(nextState: AppState) {
    const result = await backend.saveAndApplyAppState(nextState);
    setAppState(result.state);
    setRuntimeStatus(result.status);
    setLastSavedAt(formatTime());
    showToast("success", result.restarted ? "配置已保存并重启运行中的 Mihomo" : "配置已保存成功！");
    return result.state;
  }

  // Rules Tab Filter
  const filteredRules = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return appState.rules;
    return appState.rules.filter((rule) => {
      const g = appState.groups.find(x => x.id === rule.groupId);
      return rule.name.toLowerCase().includes(query) ||
        String(rule.port).includes(query) ||
        (g?.name.toLowerCase().includes(query) ?? false);
    });
  }, [appState.rules, appState.groups, searchQuery]);

  const itemsPerPage = 10;
  const totalPages = Math.max(1, Math.ceil(filteredRules.length / itemsPerPage));

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, activeTab]);

  const paginatedRules = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    return filteredRules.slice(startIndex, startIndex + itemsPerPage);
  }, [filteredRules, currentPage]);

  const allSelected = filteredRules.length > 0 && filteredRules.every((rule) => selectedRuleIds.includes(rule.id));

  function isRuleSelected(ruleId: string) {
    return selectedRuleIds.includes(ruleId);
  }

  function toggleRuleSelection(ruleId: string) {
    setSelectedRuleIds((curr) =>
      curr.includes(ruleId) ? curr.filter((id) => id !== ruleId) : [...curr, ruleId]
    );
  }

  function toggleSelectAll() {
    if (allSelected) {
      const filteredIds = new Set(filteredRules.map((r) => r.id));
      setSelectedRuleIds((curr) => curr.filter((id) => !filteredIds.has(id)));
    } else {
      const filteredIds = filteredRules.map((r) => r.id);
      setSelectedRuleIds((curr) => Array.from(new Set([...curr, ...filteredIds])));
    }
  }

  // Actions for ListenerRules
  async function toggleRuleEnabled(rule: ListenerRule) {
    if (isBusy) return;
    setBusyAction(`ip-${rule.id}`);
    try {
      const nextRules = appState.rules.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r);
      await saveAndApplyState({ ...appState, rules: nextRules });
    } catch (err) {
      showToast("error", `切换状态失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function toggleSelectedRulesEnabled(enabled: boolean) {
    if (selectedRuleIds.length === 0 || isBusy) return;
    setBusyAction("toggle");
    try {
      const nextRules = appState.rules.map(r => selectedRuleIds.includes(r.id) ? { ...r, enabled } : r);
      await saveAndApplyState({ ...appState, rules: nextRules });
    } catch (err) {
      showToast("error", `批量操作失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function handleDeleteRule(ruleId: string) {
    if (isBusy) return;
    setBusyAction("delete");
    try {
      const nextState = await backend.deleteRule(ruleId);
      await saveAndApplyState(nextState);
      setSelectedRuleIds((curr) => curr.filter(id => id !== ruleId));
    } catch (err) {
      showToast("error", `删除规则失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function handleDeleteSelectedRules() {
    if (selectedRuleIds.length === 0 || isBusy) return;
    setBusyAction("delete");
    try {
      const nextRules = appState.rules.filter(r => !selectedRuleIds.includes(r.id));
      await saveAndApplyState({ ...appState, rules: nextRules });
      setSelectedRuleIds([]);
    } catch (err) {
      showToast("error", `批量删除失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function handleDuplicateRule(ruleId: string) {
    if (isBusy) return;
    setBusyAction("rule");
    try {
      const nextState = await backend.duplicateRule(ruleId);
      await saveAndApplyState(nextState);
    } catch (err) {
      showToast("error", `复制失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function checkRuleIp(rule: ListenerRule) {
    if (isBusy) return;
    setBusyAction(`ip-${rule.id}`);
    try {
      const state = await backend.checkRuleIp(rule.id);
      setAppState(state);
      showToast("success", `${rule.name} 出口 IP 刷新成功！`);
    } catch (err) {
      showToast("error", `IP 查询失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function checkSelectedRulesIp() {
    const enabledSelected = appState.rules.filter(r => selectedRuleIds.includes(r.id) && r.enabled);
    if (enabledSelected.length === 0) {
      showToast("warning", "请选择已启用的入口规则进行测速检测。");
      return;
    }
    setBusyAction("batch-ip");
    setCheckingRuleIds(enabledSelected.map(r => r.id));
    try {
      const state = await backend.checkRulesIpBatch(enabledSelected.map(r => r.id));
      setAppState(state);
      showToast("success", `批量 IP 检测已并行完成。`);
    } catch (err) {
      showToast("error", `批量检测失败：${getErrorMessage(err)}`);
    } finally {
      setCheckingRuleIds([]);
      setBusyAction("");
    }
  }

  // Runtime control
  async function handleRuntimeAction(action: RuntimeAction) {
    if (isBusy) return;
    setBusyAction(action.name);
    try {
      if (action.name === "save") {
        await saveAndApplyState(appState);
        return;
      }
      if (action.name === "play") {
        const val = await backend.validateMihomoBinary();
        setMihomoValidation(val);
        if (!val.valid) throw new Error(val.message);

        const portVal = await backend.validateRulePorts(appState);
        if (!portVal.valid) throw new Error(portVal.message);

        await backend.saveAppState(appState);
        const status = await backend.startMihomo();
        setRuntimeStatus(status);
        setLastSavedAt(formatTime());
        showToast("success", "Mihomo 代理核心已成功启动");
        return;
      }
      if (action.name === "stop") {
        const status = await backend.stopMihomo();
        setRuntimeStatus(status);
        showToast("success", "核心已停止运行");
        return;
      }
      if (action.name === "restart") {
        const status = await backend.restartMihomo();
        setRuntimeStatus(status);
        showToast("success", "已成功重载 Mihomo 服务");
      }
    } catch (err) {
      showToast("error", `${action.label}失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  // Port Autoselect helper
  async function findDefaultInboundPort() {
    const usedPorts = new Set(appState.rules.map(r => r.port));
    const count = maxAutoInboundPort - minAutoInboundPort + 1;
    const startPort = randomAutoInboundPort();
    const offset = startPort - minAutoInboundPort;

    for (let step = 0; step < count; step++) {
      const port = minAutoInboundPort + ((offset + step) % count);
      if (usedPorts.has(port)) continue;
      const res = await backend.checkPortAvailable(port, "127.0.0.1");
      if (res.available) return String(port);
    }
    return "";
  }

  // Rule Form Handler
  function openCreateRuleModal() {
    setRuleFormError("");
    setRuleModal({
      mode: "create",
      editingId: null,
      draft: {
        name: `入口-${appState.rules.length + 1}`,
        listen: "127.0.0.1",
        port: "",
        inboundType: "mixed",
        groupId: appState.groups[0]?.id ?? "",
        enabled: true,
      }
    });

    findDefaultInboundPort().then(port => {
      setRuleModal(curr => {
        if (!curr || curr.mode !== "create") return curr;
        return {
          ...curr,
          draft: { ...curr.draft, port: curr.draft.port || port }
        };
      });
    }).catch(() => {});
  }

  function openEditRuleModal(rule: ListenerRule) {
    setRuleFormError("");
    setRuleModal({
      mode: "edit",
      editingId: rule.id,
      draft: {
        name: rule.name,
        listen: rule.listen,
        port: String(rule.port),
        inboundType: rule.inboundType,
        groupId: rule.groupId,
        enabled: rule.enabled,
      }
    });
  }

  async function handleRuleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!ruleModal || isBusy) return;
    setRuleFormError("");

    const { name, listen, port: portStr, inboundType, groupId, enabled } = ruleModal.draft;
    const port = parsePort(portStr);

    if (!name.trim() || !listen.trim() || !groupId) {
      setRuleFormError("请填写全部必须的字段");
      return;
    }
    if (port === null) {
      setRuleFormError("本地端口必须是 1 到 65535 之间的有效整数");
      return;
    }

    setBusyAction("rule");
    try {
      const ruleObj: ListenerRule = {
        id: ruleModal.editingId ?? "",
        name: name.trim(),
        listen: listen.trim(),
        port,
        inboundType,
        groupId,
        enabled,
        ipCheck: null,
      };

      let nextState;
      if (ruleModal.mode === "create") {
        nextState = await backend.addRule(ruleObj);
      } else {
        nextState = await backend.updateRule(ruleObj);
      }
      await saveAndApplyState(nextState);
      setRuleModal(null);
    } catch (err) {
      setRuleFormError(`保存失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  // Group Form Handler
  function openCreateGroupModal() {
    setGroupFormError("");
    setGroupModal({
      mode: "create",
      editingId: null,
      draft: {
        name: `策略组-${appState.groups.length + 1}`,
        groupType: "select",
        proxies: [],
      }
    });
  }

  function openEditGroupModal(group: ProxyGroup) {
    setGroupFormError("");
    setGroupModal({
      mode: "edit",
      editingId: group.id,
      draft: {
        name: group.name,
        groupType: group.groupType,
        proxies: [...group.proxies],
      }
    });
  }

  async function handleGroupSubmit(e: FormEvent) {
    e.preventDefault();
    if (!groupModal || isBusy) return;
    setGroupFormError("");

    const { name, groupType, proxies } = groupModal.draft;
    if (!name.trim()) {
      setGroupFormError("名称不能为空");
      return;
    }
    if (proxies.length === 0) {
      setGroupFormError("请选择至少一个代理成员节点");
      return;
    }

    setBusyAction("rule");
    try {
      const groupObj: ProxyGroup = {
        id: groupModal.editingId ?? "",
        name: name.trim(),
        groupType,
        proxies,
      };

      let nextState;
      if (groupModal.mode === "create") {
        nextState = await backend.addProxyGroup(groupObj);
      } else {
        nextState = await backend.updateProxyGroup(groupObj);
      }
      await saveAndApplyState(nextState);
      setGroupModal(null);
    } catch (err) {
      setGroupFormError(`保存策略组失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function triggerDeleteGroup(group: ProxyGroup) {
    setBusyAction("delete");
    try {
      const analysis = await backend.analyzeProxyGroupDeletion(group.id);
      setGroupDeleteAnalysis({
        groupId: group.id,
        groupName: group.name,
        analysis,
        forceDisableRules: false,
      });
    } catch (err) {
      showToast("error", `分析引用失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function confirmDeleteGroup() {
    if (!groupDeleteAnalysis || isBusy) return;
    setBusyAction("delete");
    try {
      const nextState = await backend.deleteProxyGroupSafe(
        groupDeleteAnalysis.groupId,
        groupDeleteAnalysis.forceDisableRules
      );
      await saveAndApplyState(nextState);
      setGroupDeleteAnalysis(null);
    } catch (err) {
      showToast("error", `删除策略组失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  // Node Form Handler
  function openCreateNodeModal() {
    setNodeFormError("");
    setNodeModal({
      mode: "create",
      editingId: null,
      draft: createEmptyNodeDraft(appState.proxies.length + 1)
    });
  }

  function openEditNodeModal(node: ProxyNode) {
    setNodeFormError("");
    setNodeModal({
      mode: "edit",
      editingId: node.id,
      draft: toNodeDraft(node),
    });
  }

  async function handleNodeLinkImport(url: string) {
    if (!nodeModal || !url.trim()) return;
    setNodeFormError("");
    try {
      const parsed = await backend.parseOutboundUrl(url.trim());
      setNodeModal(curr => {
        if (!curr) return curr;
        return {
          ...curr,
          draft: applyOutboundToDraft(
            {
              ...curr.draft,
              name: parsed.displayName ?? curr.draft.name,
              outboundProxyUrl: url.trim(),
            },
            parsed.outbound
          )
        };
      });
      if (parsed.warnings.length > 0) {
        setNodeFormError(`解析成功，提示：${parsed.warnings.join("；")}`);
      }
    } catch (err) {
      setNodeFormError(`链接解析失败：${getErrorMessage(err)}`);
    }
  }

  async function handleNodeSubmit(e: FormEvent) {
    e.preventDefault();
    if (!nodeModal || isBusy) return;
    setNodeFormError("");

    const draft = { ...nodeModal.draft };
    if (!draft.name.trim() || !draft.address.trim()) {
      setNodeFormError("名称和服务器地址不能为空");
      return;
    }
    const port = parsePort(draft.port);
    if (port === null) {
      setNodeFormError("服务器端口必须是 1 到 65535 之间的整数");
      return;
    }

    const config = buildOutboundFromDraft(draft);
    if (!config) {
      setNodeFormError("表单参数校验失败，请检查各协议特定参数。");
      return;
    }

    setBusyAction("rule");
    try {
      const nodeObj: ProxyNode = {
        id: nodeModal.editingId ?? "",
        name: draft.name.trim(),
        config,
      };

      let nextState;
      if (nodeModal.mode === "create") {
        nextState = await backend.addProxyNode(nodeObj);
      } else {
        nextState = await backend.updateProxyNode(nodeObj);
      }
      await saveAndApplyState(nextState);
      setNodeModal(null);
    } catch (err) {
      setNodeFormError(`保存代理节点失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function triggerDeleteNode(node: ProxyNode) {
    setBusyAction("delete");
    try {
      const analysis = await backend.analyzeProxyDeletion(node.id);
      setProxyDeleteAnalysis({
        proxyId: node.id,
        proxyName: node.name,
        analysis,
        forceDisableRules: false,
        replacementProxyId: null,
      });
    } catch (err) {
      showToast("error", `分析引用失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function confirmDeleteNode() {
    if (!proxyDeleteAnalysis || isBusy) return;
    setBusyAction("delete");
    try {
      const nextState = await backend.deleteProxyNodeSafe(
        proxyDeleteAnalysis.proxyId,
        proxyDeleteAnalysis.forceDisableRules,
        proxyDeleteAnalysis.replacementProxyId
      );
      await saveAndApplyState(nextState);
      setProxyDeleteAnalysis(null);
    } catch (err) {
      showToast("error", `删除节点失败：${getErrorMessage(err)}`);
    } finally {
      setBusyAction("");
    }
  }

  // Clipboard batch import
  async function handleBatchAddSubmit(e: FormEvent) {
    e.preventDefault();
    if (isBusy) return;
    setBatchAddError("");

    const lines = batchAddText.split("\n").map(l => l.trim()).filter(l => l !== "");
    if (lines.length === 0) {
      setBatchAddError("请输入至少一个代理链接。");
      return;
    }

    setBusyAction("rule");
    try {
      const parseResults = [];
      for (let i = 0; i < lines.length; i++) {
        try {
          const parsed = await backend.parseOutboundUrl(lines[i]);
          parseResults.push(parsed);
        } catch (err) {
          throw new Error(`第 ${i + 1} 行解析失败：${getErrorMessage(err)}`);
        }
      }

      // 1. 批量为它们创建 ProxyNode 写入 proxies 列表
      let nextState = { ...appState };
      const createdNodeNames: string[] = [];
      const timestamp = Date.now();

      for (let i = 0; i < parseResults.length; i++) {
        const parsed = parseResults[i];
        let remark = parsed.displayName?.trim() ?? "";
        if (!remark) {
          remark = `节点_${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
        }
        // 防止重名
        let name = remark;
        let suffix = 1;
        while (nextState.proxies.some(p => p.name === name)) {
          name = `${remark}-${suffix}`;
          suffix++;
        }

        const nodeObj: ProxyNode = {
          id: `proxy-batch-${timestamp}-${i}`,
          name,
          config: parsed.outbound,
        };
        nextState.proxies.push(nodeObj);
        createdNodeNames.push(name);
      }

      // 2. 批量为每个代理节点单独创建一个专属策略组
      const createdGroupIds: Array<{ id: string; name: string }> = [];
      for (let i = 0; i < createdNodeNames.length; i++) {
        const nodeName = createdNodeNames[i];
        const gName = `${nodeName}-出口`;
        const gId = `group-batch-${timestamp}-${i}`;
        nextState.groups.push({
          id: gId,
          name: gName,
          groupType: "select",
          proxies: [nodeName, "DIRECT"],
        });
        createdGroupIds.push({ id: gId, name: gName });
      }

      // 3. 批量分配本地顺序端口创建 rules
      const usedPorts = new Set(appState.rules.map(r => r.port));
      const allocatedPorts: number[] = [];
      let currentPort = 50000;

      for (let i = 0; i < createdGroupIds.length; i++) {
        let found = false;
        while (currentPort <= 65535) {
          if (usedPorts.has(currentPort) || allocatedPorts.includes(currentPort)) {
            currentPort++;
            continue;
          }
          const availability = await backend.checkPortAvailable(currentPort, batchAddInboundListen);
          if (availability.available) {
            allocatedPorts.push(currentPort);
            found = true;
            currentPort++;
            break;
          }
          currentPort++;
        }
        if (!found) throw new Error("本地 50000-65535 范围内没有足够的空闲端口");
      }

      for (let i = 0; i < createdGroupIds.length; i++) {
        const { id: gId, name: gName } = createdGroupIds[i];
        const port = allocatedPorts[i];
        nextState.rules.push({
          id: `rule-batch-${timestamp}-${i}`,
          name: `${gName.replace("-出口", "")}-入口`,
          listen: batchAddInboundListen,
          port,
          inboundType: batchAddInboundType,
          groupId: gId,
          enabled: true,
          ipCheck: null,
        });
      }

      await saveAndApplyState(nextState);
      showToast("success", `批量导入已成功！共生成了 ${parseResults.length} 对端口、策略组与节点关系。`);
      setBatchAddOpen(false);
    } catch (err) {
      setBatchAddError(getErrorMessage(err));
    } finally {
      setBusyAction("");
    }
  }

  async function copyToClipboard(key: string, text: string) {
    setCopiedKey(key);
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      setCopiedKey("复制失败");
    }
    window.setTimeout(() => setCopiedKey(""), 1200);
  }

  return (
    <main className="app-shell">
      {toastNotification !== null ? (
        <div className="toast-layer" aria-live="polite" aria-atomic="true">
          <div className={`toast-card is-${toastNotification.tone}`} role="status">
            <span className="toast-mark">
              <Icon name={toastNotification.tone === "success" ? "check" : toastNotification.tone === "warning" ? "scan" : "close"} />
            </span>
            <p>{toastNotification.message}</p>
            <button className="toast-close" type="button" aria-label="关闭" onClick={() => setToastNotification(null)}>
              <Icon name="close" />
            </button>
          </div>
        </div>
      ) : null}

      <RuntimeHero
        isBusy={isBusy}
        onAction={(action) => void handleRuntimeAction(action)}
        runtimeActions={runtimeActions}
        statusMeta={statusMeta}
        versionInfo={mihomoVersion}
        theme={theme}
        onChangeTheme={handleThemeChange}
      />

      <section className="metrics-grid" aria-label="概览">
        <div className="metric-card">
          <span>{appState.rules.length}</span>
          <p>入口规则</p>
        </div>
        <div className="metric-card">
          <span>{appState.groups.length}</span>
          <p>代理组数</p>
        </div>
        <div className="metric-card">
          <span>{appState.proxies.length}</span>
          <p>节点总数</p>
        </div>
        <div className="metric-card wide">
          <span>{lastSavedAt}</span>
          <p>系统配置保存时间</p>
        </div>
      </section>

      {/* Tabs navigation */}
      <div className="tabs-nav" style={{ display: "flex", gap: "var(--space-3)", margin: "0 var(--space-5) var(--space-4)" }}>
        <button
          className={`tab-btn primary-button ${activeTab === "rules" ? "" : "ghost-button"}`}
          onClick={() => setActiveTab("rules")}
          style={{ borderRadius: "var(--radius-lg)" }}
        >
          <Icon name="layers" />
          <span style={{ marginLeft: "var(--space-2)" }}>入口端口规则</span>
        </button>
        <button
          className={`tab-btn primary-button ${activeTab === "groups" ? "" : "ghost-button"}`}
          onClick={() => setActiveTab("groups")}
          style={{ borderRadius: "var(--radius-lg)" }}
        >
          <Icon name="search" />
          <span style={{ marginLeft: "var(--space-2)" }}>出站策略组</span>
        </button>
        <button
          className={`tab-btn primary-button ${activeTab === "proxies" ? "" : "ghost-button"}`}
          onClick={() => setActiveTab("proxies")}
          style={{ borderRadius: "var(--radius-lg)" }}
        >
          <Icon name="play" />
          <span style={{ marginLeft: "var(--space-2)" }}>节点管理器</span>
        </button>
      </div>

      {/* Rules Tab */}
      {activeTab === "rules" && (
        <section className="rules-panel">
          <div className="toolbar">
            <div className="toolbar-title">
              <p className="eyebrow">Listeners</p>
              <h2>入口端口转发规则</h2>
            </div>
            <div className="search-bar">
              <Icon name="search" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.currentTarget.value)}
                placeholder="搜索规则或绑定的组..."
                className="search-input"
              />
              {searchQuery && (
                <button className="clear-search-btn" onClick={() => setSearchQuery("")}>
                  <Icon name="close" />
                </button>
              )}
            </div>
            <div className="toolbar-actions">
              <button className="ghost-button" onClick={toggleSelectAll} disabled={filteredRules.length === 0 || isBusy}>
                <Icon name="check" />
              </button>
              <button className="ghost-button" onClick={() => void toggleSelectedRulesEnabled(true)} disabled={selectedRuleIds.length === 0 || isBusy} title="批量启用">
                <Icon name="play" />
              </button>
              <button className="ghost-button" onClick={() => void toggleSelectedRulesEnabled(false)} disabled={selectedRuleIds.length === 0 || isBusy} title="批量停用">
                <Icon name="stop" />
              </button>
              <button className="ghost-button" onClick={openCreateRuleModal} disabled={isBusy} title="添加规则">
                <Icon name="plus" />
              </button>
              <button className="ghost-button" onClick={() => setBatchAddOpen(true)} disabled={isBusy} title="批量导入">
                <Icon name="layers" />
              </button>
              <button className="ghost-button" onClick={() => void checkSelectedRulesIp()} disabled={selectedRuleIds.length === 0 || isBusy} title="批量测速">
                <Icon name="scan" />
              </button>
              <button className="danger-button" onClick={handleDeleteSelectedRules} disabled={selectedRuleIds.length === 0 || isBusy}>
                <Icon name="delete" />
              </button>
            </div>
          </div>

          {paginatedRules.length > 0 ? (
            <div className="rule-list">
              {paginatedRules.map((rule) => {
                const groupObj = appState.groups.find((g) => g.id === rule.groupId);
                const inboundCopyKey = `${rule.id}-inbound-link`;
                const inboundUrl = buildInboundProxyUrl(rule);
                const isChecking = busyAction === `ip-${rule.id}` || checkingRuleIds.includes(rule.id);

                return (
                  <article className={`rule-card ${isRuleSelected(rule.id) ? "is-selected" : ""}`} key={rule.id}>
                    <label className="select-box">
                      <input
                        type="checkbox"
                        checked={isRuleSelected(rule.id)}
                        onChange={() => toggleRuleSelection(rule.id)}
                        disabled={isBusy}
                      />
                      <span></span>
                    </label>
                    <div className="rule-main">
                      <div className="rule-row">
                        <div className="rule-identity">
                          <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
                            <span className={`status-dot ${!runtimeStatus.running || !rule.enabled ? "is-inactive" : "is-active"}`} />
                            <h3>{rule.name}</h3>
                          </div>
                        </div>

                        <div className="endpoint-line local">
                          <strong>{rule.inboundType.toUpperCase()}</strong>
                          <span>{formatLocalInboundAddress(rule.listen, rule.port)}</span>
                          <button
                            className="copy-button compact-copy"
                            title={copiedKey === inboundCopyKey ? "已复制" : "复制链接"}
                            onClick={() => void copyToClipboard(inboundCopyKey, inboundUrl)}
                          >
                            <Icon name="copy" />
                          </button>
                        </div>

                        <div className="endpoint-line outbound" style={{ flex: 1.5 }}>
                          <strong>策略出口</strong>
                          <span style={{ color: "var(--color-accent-2)", fontWeight: 700 }}>
                            {groupObj ? groupObj.name : "未绑定组"}
                          </span>
                        </div>

                        <div className="ip-check-panel">
                          <div className="ip-check-result">
                            <span className="ip-flag">{formatCountryFlag(rule.ipCheck?.country ?? null)}</span>
                            <span className="ip-address">{rule.ipCheck?.ip ?? "未检测"}</span>
                          </div>
                          <button
                            className="copy-button compact-copy ip-check-button"
                            onClick={() => void checkRuleIp(rule)}
                            disabled={isBusy || !rule.enabled}
                          >
                            {isChecking ? "检测中" : "IP检测"}
                          </button>
                        </div>

                        <div className="rule-actions">
                          <button className="small-icon-button" onClick={() => void toggleRuleEnabled(rule)} disabled={isBusy} title={rule.enabled ? "停用" : "启用"}>
                            <Icon name={rule.enabled ? "stop" : "play"} />
                          </button>
                          <button className="small-icon-button" onClick={() => void handleDuplicateRule(rule.id)} disabled={isBusy} title="复制">
                            <Icon name="copy" />
                          </button>
                          <button className="small-icon-button" onClick={() => openEditRuleModal(rule)} disabled={isBusy} title="编辑">
                            <Icon name="edit" />
                          </button>
                          <button className="small-icon-button danger" onClick={() => void handleDeleteRule(rule.id)} disabled={isBusy} title="删除">
                            <Icon name="delete" />
                          </button>
                        </div>
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="empty-state">
              <Icon name="layers" />
              <h3>没有规则</h3>
              <p>请点击右侧“新建规则”按钮，为指纹浏览器新建转发端口。</p>
            </div>
          )}

          {filteredRules.length > 0 && totalPages > 1 ? (
            <div className="pagination-bar" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "var(--space-3) var(--space-5)", background: "rgba(255, 255, 255, 0.03)", borderRadius: "0 0 var(--radius-lg) var(--radius-lg)", borderTop: "1px solid rgba(255, 255, 255, 0.05)" }}>
              <div className="pagination-info" style={{ fontSize: "0.85rem", color: "var(--color-ink-weak)" }}>
                显示第 {(currentPage - 1) * itemsPerPage + 1} - {Math.min(currentPage * itemsPerPage, filteredRules.length)} 条，共 {filteredRules.length} 条
              </div>
              <div className="pagination-actions" style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
                <button
                  className="ghost-button pagination-btn"
                  type="button"
                  onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                >
                  <span>上一页</span>
                </button>

                <div className="pagination-pages" style={{ display: "flex", gap: "4px" }}>
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => {
                    const isCurrent = page === currentPage;
                    return (
                      <button
                        key={page}
                        className={isCurrent ? "primary-button pagination-page-btn" : "ghost-button pagination-page-btn"}
                        type="button"
                        onClick={() => setCurrentPage(page)}
                        style={{ minWidth: "32px", padding: "4px 8px" }}
                      >
                        {page}
                      </button>
                    );
                  })}
                </div>

                <button
                  className="ghost-button pagination-btn"
                  type="button"
                  onClick={() => setCurrentPage((prev) => Math.min(totalPages, prev + 1))}
                  disabled={currentPage === totalPages}
                >
                  <span>下一页</span>
                </button>
              </div>
            </div>
          ) : null}
        </section>
      )}

      {/* Groups Tab */}
      {activeTab === "groups" && (
        <section className="rules-panel">
          <div className="toolbar">
            <div className="toolbar-title">
              <p className="eyebrow">Proxy Groups</p>
              <h2>节点出站策略组</h2>
            </div>
            <div className="toolbar-actions">
              <button className="ghost-button" onClick={openCreateGroupModal} disabled={isBusy} title="新建策略组">
                <Icon name="plus" />
                <span style={{ marginLeft: "var(--space-2)" }}>新建组</span>
              </button>
            </div>
          </div>

          {appState.groups.length > 0 ? (
            <div className="rule-list">
              {appState.groups.map((group) => {
                const affectedRules = appState.rules.filter((r) => r.groupId === group.id);

                return (
                  <article className="rule-card" key={group.id} style={{ padding: "var(--space-4) var(--space-5)" }}>
                    <div className="rule-main" style={{ width: "100%" }}>
                      <div className="rule-row" style={{ flexWrap: "wrap", gap: "var(--space-4)" }}>
                        <div style={{ minWidth: "180px" }}>
                          <h3 style={{ fontSize: "1.1rem", color: "var(--color-ink)" }}>{group.name}</h3>
                          <span className="eyebrow">{group.groupType.toUpperCase()}</span>
                        </div>

                        <div style={{ flex: 2, minWidth: "250px" }}>
                          <strong style={{ display: "block", fontSize: "0.8rem", color: "var(--color-ink-weak)", marginBottom: "var(--space-1)" }}>成员节点</strong>
                          <div style={{ display: "flex", flexWrap: "wrap", gap: "var(--space-1)" }}>
                            {group.proxies.map((p, idx) => (
                              <span key={idx} style={{ background: "var(--color-field)", color: "var(--color-ink)", padding: "2px 8px", borderRadius: "var(--radius-md)", fontSize: "0.8rem" }}>
                                {p}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div style={{ minWidth: "150px" }}>
                          <span style={{ fontSize: "0.85rem", color: "var(--color-ink-weak)" }}>
                            关联规则: {affectedRules.length} 个
                          </span>
                        </div>

                        <div className="rule-actions">
                          <button className="small-icon-button" onClick={() => openEditGroupModal(group)} disabled={isBusy} title="编辑">
                            <Icon name="edit" />
                          </button>
                          <button className="small-icon-button danger" onClick={() => void triggerDeleteGroup(group)} disabled={isBusy} title="删除">
                            <Icon name="delete" />
                          </button>
                        </div>
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="empty-state">
              <Icon name="search" />
              <h3>暂无策略组</h3>
              <p>可以创建一个策略组，将若干个代理服务器归入同一组中。</p>
            </div>
          )}
        </section>
      )}

      {/* Proxies Tab */}
      {activeTab === "proxies" && (
        <section className="rules-panel">
          <div className="toolbar">
            <div className="toolbar-title">
              <p className="eyebrow">Proxy Nodes</p>
              <h2>上游代理出站节点</h2>
            </div>
            <div className="toolbar-actions">
              <button className="ghost-button" onClick={openCreateNodeModal} disabled={isBusy} title="新建节点">
                <Icon name="plus" />
                <span style={{ marginLeft: "var(--space-2)" }}>新建节点</span>
              </button>
            </div>
          </div>

          {appState.proxies.length > 0 ? (
            <div className="rule-list">
              {appState.proxies.map((node) => {
                const address = getOutboundAddress(node.config);
                const warningList = node.config.protocol !== "socks" ? node.config.importSource?.warnings ?? [] : [];

                return (
                  <article className="rule-card" key={node.id} style={{ padding: "var(--space-4) var(--space-5)" }}>
                    <div className="rule-main" style={{ width: "100%" }}>
                      <div className="rule-row">
                        <div style={{ minWidth: "150px" }}>
                          <h3 style={{ fontSize: "1.1rem", color: "var(--color-ink)" }}>{node.name}</h3>
                          <span style={{ display: "inline-block", background: "var(--color-field-strong)", color: "var(--color-accent)", padding: "1px 6px", borderRadius: "4px", fontSize: "0.75rem", fontWeight: 700, marginTop: "4px" }}>
                            {formatOutboundProtocol(node.config.protocol)}
                          </span>
                        </div>

                        <div style={{ flex: 2 }}>
                          <strong style={{ display: "block", fontSize: "0.8rem", color: "var(--color-ink-weak)" }}>服务器地址</strong>
                          <span style={{ fontFamily: "monospace", fontSize: "0.95rem" }}>{address}</span>
                          {warningList.length > 0 && (
                            <p style={{ color: "var(--color-accent-2)", fontSize: "0.75rem", marginTop: "2px" }}>
                              链接提示：{warningList.join("；")}
                            </p>
                          )}
                        </div>

                        <div className="rule-actions">
                          <button className="small-icon-button" onClick={() => openEditNodeModal(node)} disabled={isBusy} title="编辑">
                            <Icon name="edit" />
                          </button>
                          <button className="small-icon-button danger" onClick={() => void triggerDeleteNode(node)} disabled={isBusy} title="删除">
                            <Icon name="delete" />
                          </button>
                        </div>
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="empty-state">
              <Icon name="play" />
              <h3>暂无上游出口节点</h3>
              <p>导入或手动增加一些 SOCKS5 / Shadowsocks / VLESS / Trojan 代理出口吧。</p>
            </div>
          )}
        </section>
      )}

      {/* MODAL: ListenerRule Add/Edit */}
      {ruleModal && (
        <div className="modal-layer" role="presentation">
          <section className="rule-modal" role="dialog" aria-modal="true">
            <form onSubmit={(e) => void handleRuleSubmit(e)}>
              <div className="modal-header">
                <div>
                  <p className="eyebrow">Rule Editor</p>
                  <h2>{ruleModal.mode === "create" ? "新建入口转发端口" : "编辑入口端口规则"}</h2>
                  <p className="modal-description">配置本地浏览器连接的监听规则，并绑定指定出站代理策略组。</p>
                </div>
                <button className="small-icon-button" type="button" onClick={() => setRuleModal(null)}>
                  <Icon name="close" />
                </button>
              </div>

              <div className="modal-body">
                <section className="form-section">
                  <div className="form-grid">
                    <label className="field wide-field">
                      <span>入口名称</span>
                      <input
                        type="text"
                        value={ruleModal.draft.name}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, name: e.currentTarget.value } })}
                        placeholder="例如：浏览器账号 01"
                        required
                      />
                    </label>

                    <label className="field">
                      <span>入口类型</span>
                      <select
                        value={ruleModal.draft.inboundType}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, inboundType: e.currentTarget.value } })}
                      >
                        {inboundTypeOptions.map((opt) => (
                          <option value={opt.value} key={opt.value}>{opt.label}</option>
                        ))}
                      </select>
                    </label>

                    <label className="field">
                      <span>监听地址</span>
                      <input
                        type="text"
                        value={ruleModal.draft.listen}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, listen: e.currentTarget.value } })}
                        required
                      />
                    </label>

                    <label className="field">
                      <span>本地端口</span>
                      <input
                        type="number"
                        min="1"
                        max="65535"
                        value={ruleModal.draft.port}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, port: e.currentTarget.value } })}
                        placeholder="留空自动分配"
                        required={ruleModal.mode === "edit"}
                      />
                    </label>

                    <label className="field">
                      <span>分配出口策略组</span>
                      <select
                        value={ruleModal.draft.groupId}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, groupId: e.currentTarget.value } })}
                        required
                      >
                        <option value="" disabled>-- 选择出口策略组 --</option>
                        {appState.groups.map((g) => (
                          <option value={g.id} key={g.id}>{g.name}</option>
                        ))}
                      </select>
                    </label>

                    <label className="toggle-field wide-field">
                      <input
                        type="checkbox"
                        checked={ruleModal.draft.enabled}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, enabled: e.currentTarget.checked } })}
                      />
                      <span>启用此入口转发</span>
                    </label>
                  </div>
                </section>
              </div>

              {ruleFormError && <p className="form-error">{ruleFormError}</p>}

              <div className="modal-footer">
                <button className="ghost-button" type="button" onClick={() => setRuleModal(null)}>取消</button>
                <button className="primary-button" type="submit">保存规则</button>
              </div>
            </form>
          </section>
        </div>
      )}

      {/* MODAL: ProxyGroup Add/Edit */}
      {groupModal && (
        <div className="modal-layer" role="presentation">
          <section className="rule-modal" role="dialog" aria-modal="true">
            <form onSubmit={(e) => void handleGroupSubmit(e)}>
              <div className="modal-header">
                <div>
                  <p className="eyebrow">Group Editor</p>
                  <h2>{groupModal.mode === "create" ? "新建代理策略组" : "编辑策略组配置"}</h2>
                  <p className="modal-description">组织代理出站池。用户可在此组包含的节点范围内进行热切换。</p>
                </div>
                <button className="small-icon-button" type="button" onClick={() => setGroupModal(null)}>
                  <Icon name="close" />
                </button>
              </div>

              <div className="modal-body">
                <section className="form-section">
                  <div className="form-grid">
                    <label className="field wide-field">
                      <span>策略组名称</span>
                      <input
                        type="text"
                        value={groupModal.draft.name}
                        onChange={(e) => setGroupModal({ ...groupModal, draft: { ...groupModal.draft, name: e.currentTarget.value } })}
                        placeholder="例如：美国主出口组 / 账号池-A"
                        required
                      />
                    </label>

                    <label className="field wide-field">
                      <span>策略组类型</span>
                      <select
                        value={groupModal.draft.groupType}
                        onChange={(e) => setGroupModal({ ...groupModal, draft: { ...groupModal.draft, groupType: e.currentTarget.value } })}
                      >
                        <option value="select">手动选择 (Select)</option>
                      </select>
                    </label>

                    <div className="field wide-field">
                      <span style={{ display: "block", marginBottom: "var(--space-2)" }}>选择组内出口成员</span>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: "var(--space-2)", maxHeight: "250px", overflowY: "auto", padding: "var(--space-2)", background: "var(--color-field)", borderRadius: "var(--radius-md)" }}>
                        {/* Builtin proxy options */}
                        {["DIRECT", "REJECT"].map((builtin) => {
                          const isChecked = groupModal.draft.proxies.includes(builtin);
                          return (
                            <label key={builtin} style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", cursor: "pointer", color: "var(--color-accent-2)" }}>
                              <input
                                type="checkbox"
                                checked={isChecked}
                                onChange={(e) => {
                                  const list = e.currentTarget.checked
                                    ? [...groupModal.draft.proxies, builtin]
                                    : groupModal.draft.proxies.filter(p => p !== builtin);
                                  setGroupModal({ ...groupModal, draft: { ...groupModal.draft, proxies: list } });
                                }}
                              />
                              <strong>{builtin} (系统直连)</strong>
                            </label>
                          );
                        })}
                        {appState.proxies.map((node) => {
                          const isChecked = groupModal.draft.proxies.includes(node.name);
                          return (
                            <label key={node.id} style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", cursor: "pointer" }}>
                              <input
                                type="checkbox"
                                checked={isChecked}
                                onChange={(e) => {
                                  const list = e.currentTarget.checked
                                    ? [...groupModal.draft.proxies, node.name]
                                    : groupModal.draft.proxies.filter(p => p !== node.name);
                                  setGroupModal({ ...groupModal, draft: { ...groupModal.draft, proxies: list } });
                                }}
                              />
                              <span>{node.name}</span>
                            </label>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </section>
              </div>

              {groupFormError && <p className="form-error">{groupFormError}</p>}

              <div className="modal-footer">
                <button className="ghost-button" type="button" onClick={() => setGroupModal(null)}>取消</button>
                <button className="primary-button" type="submit">保存策略组</button>
              </div>
            </form>
          </section>
        </div>
      )}

      {/* MODAL: ProxyNode Add/Edit */}
      {nodeModal && (
        <div className="modal-layer" role="presentation">
          <section className="rule-modal" role="dialog" aria-modal="true">
            <form onSubmit={(e) => void handleNodeSubmit(e)}>
              <div className="modal-header">
                <div>
                  <p className="eyebrow">Node Editor</p>
                  <h2>{nodeModal.mode === "create" ? "添加代理节点" : "编辑代理节点参数"}</h2>
                  <p className="modal-description">配置上游出站代理。支持从 SOCKS5, Shadowsocks (ss), VLESS, Trojan 的剪贴板链接直接粘贴解析导入。</p>
                </div>
                <button className="small-icon-button" type="button" onClick={() => setNodeModal(null)}>
                  <Icon name="close" />
                </button>
              </div>

              <div className="modal-body">
                <section className="form-section">
                  <div className="form-grid">
                    <label className="field wide-field">
                      <span>代理配置链接解析 (粘贴链接自动导入)</span>
                      <input
                        type="text"
                        value={nodeModal.draft.outboundProxyUrl}
                        onChange={(e) => void handleNodeLinkImport(e.currentTarget.value)}
                        placeholder="socks5://... / ss://... / vless://... / trojan://"
                      />
                    </label>

                    <label className="field wide-field">
                      <span>节点名称 (必须唯一)</span>
                      <input
                        type="text"
                        value={nodeModal.draft.name}
                        onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, name: e.currentTarget.value } })}
                        placeholder="例如：日本 A 节点"
                        required
                      />
                    </label>

                    <label className="field">
                      <span>节点协议</span>
                      <select
                        value={nodeModal.draft.protocol}
                        onChange={(e) => {
                          if (isOutboundProtocol(e.currentTarget.value)) {
                            setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, protocol: e.currentTarget.value } });
                          }
                        }}
                      >
                        {outboundProtocolOptions.map(p => (
                          <option value={p} key={p}>{formatOutboundProtocol(p)}</option>
                        ))}
                      </select>
                    </label>

                    <label className="field wide-field" style={{ gridColumn: "span 2" }}>
                      <span>服务器地址</span>
                      <input
                        type="text"
                        value={nodeModal.draft.address}
                        onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, address: e.currentTarget.value } })}
                        placeholder="node.upstream.domain"
                        required
                      />
                    </label>

                    <label className="field">
                      <span>连接端口</span>
                      <input
                        type="number"
                        min="1"
                        max="65535"
                        value={nodeModal.draft.port}
                        onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, port: e.currentTarget.value } })}
                        required
                      />
                    </label>

                    {/* SOCKS specific */}
                    {nodeModal.draft.protocol === "socks" && (
                      <>
                        <label className="field">
                          <span>认证用户名</span>
                          <input
                            type="text"
                            value={nodeModal.draft.socksUsername}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, socksUsername: e.currentTarget.value } })}
                            placeholder="可选"
                          />
                        </label>
                        <label className="field">
                          <span>认证密码</span>
                          <input
                            type="password"
                            value={nodeModal.draft.socksPassword}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, socksPassword: e.currentTarget.value } })}
                            placeholder="可选"
                          />
                        </label>
                      </>
                    )}

                    {/* Shadowsocks specific */}
                    {nodeModal.draft.protocol === "shadowsocks" && (
                      <>
                        <label className="field wide-field">
                          <span>加密算法</span>
                          <input
                            list="shadowsocks-ciphers"
                            type="text"
                            value={nodeModal.draft.shadowsocksMethod}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, shadowsocksMethod: e.currentTarget.value } })}
                            required
                          />
                          <datalist id="shadowsocks-ciphers">
                            {shadowsocksMethodOptions.map(m => <option value={m} key={m} />)}
                          </datalist>
                        </label>
                        <label className="field wide-field">
                          <span>节点密码</span>
                          <input
                            type="password"
                            value={nodeModal.draft.shadowsocksPassword}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, shadowsocksPassword: e.currentTarget.value } })}
                            required
                          />
                        </label>
                      </>
                    )}

                    {/* VLESS specific */}
                    {nodeModal.draft.protocol === "vless" && (
                      <>
                        <label className="field wide-field">
                          <span>UUID / ID</span>
                          <input
                            type="text"
                            value={nodeModal.draft.vlessId}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessId: e.currentTarget.value } })}
                            placeholder="5783a3e7-e373-51cd-8642-c83782b807c5"
                            required
                          />
                        </label>
                        <label className="field">
                          <span>加密方案</span>
                          <input
                            type="text"
                            value={nodeModal.draft.vlessEncryption}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessEncryption: e.currentTarget.value } })}
                            placeholder="none"
                            required
                          />
                        </label>
                        <label className="field">
                          <span>安全传输协议</span>
                          <select
                            value={nodeModal.draft.vlessSecurity}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessSecurity: e.currentTarget.value as any } })}
                          >
                            <option value="none">无安全层</option>
                            <option value="tls">TLS</option>
                            <option value="reality">REALITY</option>
                          </select>
                        </label>
                        <label className="field">
                          <span>Flow</span>
                          <select
                            value={nodeModal.draft.vlessFlow}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessFlow: e.currentTarget.value as any } })}
                          >
                            <option value="">无</option>
                            {vlessFlowOptions.map(f => <option value={f} key={f}>{f}</option>)}
                          </select>
                        </label>
                        <label className="field">
                          <span>网络传输</span>
                          <select
                            value={nodeModal.draft.vlessTransportKind}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessTransportKind: e.currentTarget.value as any } })}
                          >
                            <option value="tcp">TCP</option>
                            <option value="ws">WebSocket (ws)</option>
                          </select>
                        </label>

                        {nodeModal.draft.vlessTransportKind === "ws" && (
                          <>
                            <label className="field">
                              <span>WS Path</span>
                              <input
                                type="text"
                                value={nodeModal.draft.vlessTransportPath}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessTransportPath: e.currentTarget.value } })}
                                placeholder="/"
                              />
                            </label>
                            <label className="field">
                              <span>WS Host</span>
                              <input
                                type="text"
                                value={nodeModal.draft.vlessTransportHost}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessTransportHost: e.currentTarget.value } })}
                                placeholder="sni.domain.com"
                              />
                            </label>
                          </>
                        )}

                        {nodeModal.draft.vlessSecurity !== "none" && (
                          <>
                            <label className="field">
                              <span>ServerName (SNI)</span>
                              <input
                                type="text"
                                value={nodeModal.draft.vlessServerName}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessServerName: e.currentTarget.value } })}
                                placeholder="domain.com"
                              />
                            </label>
                            <label className="field">
                              <span>Fingerprint</span>
                              <input
                                type="text"
                                value={nodeModal.draft.vlessFingerprint}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessFingerprint: e.currentTarget.value } })}
                                placeholder="chrome"
                              />
                            </label>
                          </>
                        )}

                        {nodeModal.draft.vlessSecurity === "tls" && (
                          <label className="toggle-field wide-field">
                            <input
                              type="checkbox"
                              checked={nodeModal.draft.vlessAllowInsecure}
                              onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessAllowInsecure: e.currentTarget.checked } })}
                            />
                            <span>忽略证书校验错误 (skip-cert-verify)</span>
                          </label>
                        )}

                        {nodeModal.draft.vlessSecurity === "reality" && (
                          <>
                            <label className="field wide-field">
                              <span>REALITY Public Key</span>
                              <input
                                type="text"
                                value={nodeModal.draft.vlessRealityPublicKey}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessRealityPublicKey: e.currentTarget.value } })}
                                required
                              />
                            </label>
                            <label className="field">
                              <span>REALITY Short ID</span>
                              <input
                                type="text"
                                value={nodeModal.draft.vlessRealityShortId}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, vlessRealityShortId: e.currentTarget.value } })}
                              />
                            </label>
                          </>
                        )}
                      </>
                    )}

                    {/* Trojan specific */}
                    {nodeModal.draft.protocol === "trojan" && (
                      <>
                        <label className="field wide-field">
                          <span>连接密码</span>
                          <input
                            type="password"
                            value={nodeModal.draft.trojanPassword}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, trojanPassword: e.currentTarget.value } })}
                            required
                          />
                        </label>
                        <label className="field">
                          <span>安全层</span>
                          <select
                            value={nodeModal.draft.trojanSecurity}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, trojanSecurity: e.currentTarget.value as any } })}
                          >
                            <option value="none">无安全层</option>
                            <option value="tls">TLS</option>
                            <option value="reality">REALITY</option>
                          </select>
                        </label>
                        <label className="field">
                          <span>网络传输</span>
                          <select
                            value={nodeModal.draft.trojanTransportKind}
                            onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, trojanTransportKind: e.currentTarget.value as any } })}
                          >
                            <option value="tcp">TCP</option>
                            <option value="ws">WebSocket (ws)</option>
                          </select>
                        </label>

                        {nodeModal.draft.trojanTransportKind === "ws" && (
                          <>
                            <label className="field">
                              <span>WS Path</span>
                              <input
                                type="text"
                                value={nodeModal.draft.trojanTransportPath}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, trojanTransportPath: e.currentTarget.value } })}
                                placeholder="/"
                              />
                            </label>
                            <label className="field">
                              <span>WS Host</span>
                              <input
                                type="text"
                                value={nodeModal.draft.trojanTransportHost}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, trojanTransportHost: e.currentTarget.value } })}
                                placeholder="sni.domain.com"
                              />
                            </label>
                          </>
                        )}

                        {nodeModal.draft.trojanSecurity !== "none" && (
                          <>
                            <label className="field">
                              <span>ServerName (SNI)</span>
                              <input
                                type="text"
                                value={nodeModal.draft.trojanServerName}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, trojanServerName: e.currentTarget.value } })}
                                placeholder="domain.com"
                              />
                            </label>
                            <label className="field">
                              <span>Fingerprint</span>
                              <input
                                type="text"
                                value={nodeModal.draft.trojanFingerprint}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, trojanFingerprint: e.currentTarget.value } })}
                                placeholder="chrome"
                              />
                            </label>
                          </>
                        )}

                        {nodeModal.draft.trojanSecurity === "tls" && (
                          <label className="toggle-field wide-field">
                            <input
                              type="checkbox"
                              checked={nodeModal.draft.trojanAllowInsecure}
                              onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, trojanAllowInsecure: e.currentTarget.checked } })}
                            />
                            <span>忽略证书校验错误 (skip-cert-verify)</span>
                          </label>
                        )}

                        {nodeModal.draft.trojanSecurity === "reality" && (
                          <>
                            <label className="field wide-field">
                              <span>REALITY Public Key</span>
                              <input
                                type="text"
                                value={nodeModal.draft.trojanRealityPublicKey}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, trojanRealityPublicKey: e.currentTarget.value } })}
                                required
                              />
                            </label>
                            <label className="field">
                              <span>REALITY Short ID</span>
                              <input
                                type="text"
                                value={nodeModal.draft.trojanRealityShortId}
                                onChange={(e) => setNodeModal({ ...nodeModal, draft: { ...nodeModal.draft, trojanRealityShortId: e.currentTarget.value } })}
                              />
                            </label>
                          </>
                        )}
                      </>
                    )}
                  </div>
                </section>
              </div>

              {nodeFormError && <p className="form-error">{nodeFormError}</p>}

              <div className="modal-footer">
                <button className="ghost-button" type="button" onClick={() => setNodeModal(null)}>取消</button>
                <button className="primary-button" type="submit">保存节点</button>
              </div>
            </form>
          </section>
        </div>
      )}

      {/* BATCH IMPORT MODAL */}
      {batchAddOpen && (
        <div className="modal-layer" role="presentation">
          <section className="rule-modal" role="dialog" aria-modal="true">
            <form onSubmit={(e) => void handleBatchAddSubmit(e)}>
              <div className="modal-header">
                <div>
                  <p className="eyebrow">Batch Importer</p>
                  <h2>批量导入代理节点规则</h2>
                  <p className="modal-description">一行输入一个出口链接。系统将自动生成对应的代理节点，并建立其专属策略出站组和本地顺序空闲监听端口。</p>
                </div>
                <button className="small-icon-button" type="button" onClick={() => setBatchAddOpen(false)}>
                  <Icon name="close" />
                </button>
              </div>
              <div className="modal-body">
                <section className="form-section">
                  <div className="form-grid">
                    <label className="field">
                      <span>入口协议</span>
                      <select
                        value={batchAddInboundType}
                        onChange={(e) => setBatchAddInboundType(e.currentTarget.value)}
                      >
                        {inboundTypeOptions.map(opt => (
                          <option value={opt.value} key={opt.value}>{opt.label}</option>
                        ))}
                      </select>
                    </label>
                    <label className="field">
                      <span>监听地址</span>
                      <input
                        type="text"
                        value={batchAddInboundListen}
                        onChange={(e) => setBatchAddInboundListen(e.currentTarget.value)}
                        required
                      />
                    </label>
                    <label className="field wide-field">
                      <span>出口链接 (每行一个，支持 ss, vless, trojan, socks)</span>
                      <textarea
                        rows={8}
                        value={batchAddText}
                        onChange={(e) => setBatchAddText(e.currentTarget.value)}
                        placeholder="socks5://host:port&#10;ss://...#备注&#10;vless://..."
                        required
                      />
                    </label>
                  </div>
                </section>
              </div>
              {batchAddError && <p className="form-error" style={{ margin: "0 var(--space-5)" }}>{batchAddError}</p>}
              <div className="modal-footer">
                <button className="ghost-button" type="button" onClick={() => setBatchAddOpen(false)}>取消</button>
                <button className="primary-button" type="submit">开始批量生成</button>
              </div>
            </form>
          </section>
        </div>
      )}

      {/* SAFETY DELETION CONFIRMATION: ProxyNode */}
      {proxyDeleteAnalysis && (
        <div className="modal-layer confirmation-layer" role="presentation">
          <section className="confirm-modal" role="dialog" aria-modal="true" style={{ maxWidth: "580px" }}>
            <div className="confirm-header">
              <div>
                <p className="eyebrow">Safety Check</p>
                <h2>确认删除节点：{proxyDeleteAnalysis.proxyName}</h2>
              </div>
              <button className="small-icon-button" type="button" onClick={() => setProxyDeleteAnalysis(null)}>
                <Icon name="close" />
              </button>
            </div>

            <div className="confirm-body" style={{ display: "grid", gap: "var(--space-3)" }}>
              {proxyDeleteAnalysis.analysis.affectedGroups.length === 0 ? (
                <p>该代理节点未被任何出站策略组使用，可以安全地物理删除。</p>
              ) : (
                <>
                  <p>
                    该代理节点正在被以下 <strong>{proxyDeleteAnalysis.analysis.affectedGroups.length}</strong> 个策略组引用：
                    <br />
                    <span style={{ color: "var(--color-accent-2)", fontWeight: 700 }}>
                      {proxyDeleteAnalysis.analysis.affectedGroups.join("，")}
                    </span>
                  </p>

                  {proxyDeleteAnalysis.analysis.isUniqueInAny ? (
                    <div style={{ background: "rgba(224, 86, 86, 0.15)", border: "1px solid var(--color-ink-strong)", padding: "var(--space-3)", borderRadius: "var(--radius-md)" }}>
                      <p style={{ color: "#e05656", fontWeight: 800, marginBottom: "var(--space-2)" }}>
                        ⚠️ 警告：唯一出口拦截
                      </p>
                      <p style={{ fontSize: "0.85rem", lineHeight: 1.5 }}>
                        此节点是某些策略组的唯一出站节点。如果直接删除，该策略组将变空，会导致绑定的端口规则
                        <strong style={{ color: "var(--color-accent)" }}> [{proxyDeleteAnalysis.analysis.affectedRules.join("，")}] </strong>
                        断网。
                      </p>

                      <div style={{ marginTop: "var(--space-4)", display: "grid", gap: "var(--space-3)" }}>
                        {/* Option 1: Replace */}
                        <label style={{ display: "flex", gap: "var(--space-2)", alignItems: "center", cursor: "pointer" }}>
                          <input
                            type="radio"
                            name="delete-action"
                            checked={!proxyDeleteAnalysis.forceDisableRules && proxyDeleteAnalysis.replacementProxyId !== null}
                            onChange={() => setProxyDeleteAnalysis({ ...proxyDeleteAnalysis, forceDisableRules: false, replacementProxyId: appState.proxies.find(p => p.id !== proxyDeleteAnalysis.proxyId)?.id ?? null })}
                          />
                          <div>
                            <strong>替换为此节点的替代出口：</strong>
                            <select
                              value={proxyDeleteAnalysis.replacementProxyId ?? ""}
                              onChange={(e) => setProxyDeleteAnalysis({ ...proxyDeleteAnalysis, forceDisableRules: false, replacementProxyId: e.currentTarget.value || null })}
                              disabled={proxyDeleteAnalysis.forceDisableRules}
                              style={{ padding: "4px", borderRadius: "4px", marginLeft: "8px" }}
                            >
                              <option value="" disabled>-- 选择另一个代理节点 --</option>
                              {appState.proxies.filter(p => p.id !== proxyDeleteAnalysis.proxyId).map(p => (
                                <option value={p.id} key={p.id}>{p.name}</option>
                              ))}
                            </select>
                          </div>
                        </label>

                        {/* Option 2: Disable rules */}
                        <label style={{ display: "flex", gap: "var(--space-2)", alignItems: "center", cursor: "pointer" }}>
                          <input
                            type="radio"
                            name="delete-action"
                            checked={proxyDeleteAnalysis.forceDisableRules}
                            onChange={() => setProxyDeleteAnalysis({ ...proxyDeleteAnalysis, forceDisableRules: true, replacementProxyId: null })}
                          />
                          <div>
                            <strong>强行删除，并停用相关的入口规则</strong>
                            <p style={{ fontSize: "0.75rem", color: "var(--color-ink-weak)" }}>将自动将关联的监听端口设为停用状态。</p>
                          </div>
                        </label>
                      </div>
                    </div>
                  ) : (
                    <p style={{ fontSize: "0.85rem" }}>
                      这些策略组还包含其他活跃节点成员。删除后此节点会从中移除，出口规则不会断网，可以安全移除。
                    </p>
                  )}
                </>
              )}
            </div>

            <div className="confirm-footer">
              <button className="ghost-button" type="button" onClick={() => setProxyDeleteAnalysis(null)}>
                取消
              </button>
              <button
                className="danger-button"
                type="button"
                onClick={() => void confirmDeleteNode()}
                disabled={proxyDeleteAnalysis.analysis.isUniqueInAny && !proxyDeleteAnalysis.forceDisableRules && !proxyDeleteAnalysis.replacementProxyId}
              >
                <Icon name="delete" />
                <span>确认删除</span>
              </button>
            </div>
          </section>
        </div>
      )}

      {/* SAFETY DELETION CONFIRMATION: ProxyGroup */}
      {groupDeleteAnalysis && (
        <div className="modal-layer confirmation-layer" role="presentation">
          <section className="confirm-modal" role="dialog" aria-modal="true">
            <div className="confirm-header">
              <div>
                <p className="eyebrow">Safety Check</p>
                <h2>确认删除策略组：{groupDeleteAnalysis.groupName}</h2>
              </div>
              <button className="small-icon-button" type="button" onClick={() => setGroupDeleteAnalysis(null)}>
                <Icon name="close" />
              </button>
            </div>

            <div className="confirm-body" style={{ display: "grid", gap: "var(--space-3)" }}>
              {groupDeleteAnalysis.analysis.affectedRules.length === 0 ? (
                <p>该策略组未被任何本地监听规则引用，可以安全地直接删除。</p>
              ) : (
                <div style={{ background: "rgba(224, 86, 86, 0.15)", border: "1px solid var(--color-ink-strong)", padding: "var(--space-3)", borderRadius: "var(--radius-md)" }}>
                  <p style={{ color: "#e05656", fontWeight: 800, marginBottom: "var(--space-2)" }}>
                    ⚠️ 该策略组正在被以下规则绑定使用：
                  </p>
                  <p style={{ color: "var(--color-accent)", fontWeight: 700, marginBottom: "var(--space-3)" }}>
                    [{groupDeleteAnalysis.analysis.affectedRules.join("，")}]
                  </p>
                  <label style={{ display: "flex", gap: "var(--space-2)", alignItems: "center", cursor: "pointer" }}>
                    <input
                      type="checkbox"
                      checked={groupDeleteAnalysis.forceDisableRules}
                      onChange={(e) => setGroupDeleteAnalysis({ ...groupDeleteAnalysis, forceDisableRules: e.currentTarget.checked })}
                    />
                    <div>
                      <strong>删除并强制停用引用此组的所有监听规则</strong>
                    </div>
                  </label>
                </div>
              )}
            </div>

            <div className="confirm-footer">
              <button className="ghost-button" type="button" onClick={() => setGroupDeleteAnalysis(null)}>
                取消
              </button>
              <button
                className="danger-button"
                type="button"
                onClick={() => void confirmDeleteGroup()}
                disabled={groupDeleteAnalysis.analysis.affectedRules.length > 0 && !groupDeleteAnalysis.forceDisableRules}
              >
                <Icon name="delete" />
                <span>确认删除</span>
              </button>
            </div>
          </section>
        </div>
      )}
    </main>
  );
}

export default App;
