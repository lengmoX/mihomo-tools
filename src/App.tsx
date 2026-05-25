import { useEffect, useMemo, useState, type FormEvent, type ReactElement } from "react";
import {
  backend, type AppState, type AuthConfig, type OutboundConfig,
  type OutboundProtocol, type ProxyRule,
  type RuntimeStatus, type VlessFlow, type MihomoBinaryValidation, type MihomoVersionInfo,
} from "./api/backend";
import { RuntimeHero } from "./features/runtime/RuntimeHero";
import type { StatusMeta } from "./features/runtime/runtime-types";
import "./App.css";

type RuleFormState = {
  remark: string;
  inboundProtocol: "mixed" | "socks" | "http";
  inboundListen: string;
  inboundPort: string;
  inboundUsername: string;
  inboundPassword: string;
  enabled: boolean;

  // Outbound configurations
  outboundProtocol: OutboundProtocol;
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

  // AnyTLS configurations
  anytlsPassword: string;
  anytlsClientFingerprint: string;
  anytlsUdp: boolean;
  anytlsIdleSessionCheckInterval: string;
  anytlsIdleSessionTimeout: string;
  anytlsMinIdleSession: string;
  anytlsSni: string;
  anytlsAlpn: string;
  anytlsSkipCertVerify: boolean;

  importedOutbound: OutboundConfig | null;
};

type ModalMode = "create" | "edit";

type RuleModalState = {
  mode: ModalMode;
  editingId: string | null;
  draft: RuleFormState;
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
  schemaVersion: 4,
  rules: [],
};

const inboundTypeOptions = [
  { value: "mixed", label: "Mixed (SOCKS + HTTP)" },
  { value: "socks", label: "SOCKS5" },
  { value: "http", label: "HTTP" },
];

const outboundProtocolOptions: OutboundProtocol[] = ["socks", "vless", "shadowsocks", "trojan", "anytls"];
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
  if (protocol === "anytls") return "AnyTLS";
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

function toOutboundFormState(outbound: OutboundConfig) {
  const address = outbound.protocol === "socks" ? outbound.host : outbound.address;
  const socksAuth = outbound.protocol === "socks" ? outbound.auth : null;
  const vlessSecurity = (outbound.protocol === "vless" && outbound.reality !== null ? "reality" : outbound.protocol === "vless" && outbound.tls !== null ? "tls" : "none") as "none" | "tls" | "reality";
  const trojanSecurity = (outbound.protocol === "trojan" && outbound.reality !== null ? "reality" : outbound.protocol === "trojan" && outbound.tls !== null ? "tls" : "none") as "none" | "tls" | "reality";

  return {
    outboundProtocol: outbound.protocol,
    outboundProxyUrl: "",
    address,
    port: String(outbound.port),
    socksUsername: socksAuth?.username ?? "",
    socksPassword: socksAuth?.password ?? "",
    vlessId: outbound.protocol === "vless" ? outbound.id : "",
    vlessEncryption: outbound.protocol === "vless" ? outbound.encryption : "none",
    vlessFlow: (outbound.protocol === "vless" ? outbound.flow ?? "" : "") as "" | VlessFlow,
    vlessLevel: outbound.protocol === "vless" ? String(outbound.level ?? "") : "",
    vlessSecurity,
    vlessServerName: outbound.protocol === "vless" ? outbound.reality?.serverName ?? outbound.tls?.serverName ?? "" : "",
    vlessFingerprint: outbound.protocol === "vless" ? outbound.reality?.fingerprint ?? outbound.tls?.fingerprint ?? "" : "",
    vlessRealityPublicKey: outbound.protocol === "vless" ? outbound.reality?.publicKey ?? "" : "",
    vlessRealityShortId: outbound.protocol === "vless" ? outbound.reality?.shortId ?? "" : "",
    vlessRealitySpiderX: outbound.protocol === "vless" ? outbound.reality?.spiderX ?? "" : "",
    vlessAllowInsecure: outbound.protocol === "vless" ? !!outbound.tls?.allowInsecure : false,
    vlessTransportKind: outbound.protocol === "vless" ? outbound.transport.kind : "tcp" as const,
    vlessTransportPath: outbound.protocol === "vless" ? outbound.transport.path ?? "" : "",
    vlessTransportHost: outbound.protocol === "vless" ? outbound.transport.host ?? "" : "",
    shadowsocksMethod: outbound.protocol === "shadowsocks" ? outbound.method : shadowsocksMethodOptions[0],
    shadowsocksPassword: outbound.protocol === "shadowsocks" ? outbound.password : "",
    shadowsocksUot: outbound.protocol === "shadowsocks" ? outbound.uot : false,
    shadowsocksUotVersion: outbound.protocol === "shadowsocks" ? String(outbound.uotVersion ?? "") as "" | "1" | "2" : "" as const,
    trojanPassword: outbound.protocol === "trojan" ? outbound.password : "",
    trojanEmail: outbound.protocol === "trojan" ? outbound.email ?? "" : "",
    trojanLevel: outbound.protocol === "trojan" ? String(outbound.level ?? "") : "",
    trojanSecurity,
    trojanServerName: outbound.protocol === "trojan" ? outbound.reality?.serverName ?? outbound.tls?.serverName ?? "" : "",
    trojanFingerprint: outbound.protocol === "trojan" ? outbound.reality?.fingerprint ?? outbound.tls?.fingerprint ?? "" : "",
    trojanRealityPublicKey: outbound.protocol === "trojan" ? outbound.reality?.publicKey ?? "" : "",
    trojanRealityShortId: outbound.protocol === "trojan" ? outbound.reality?.shortId ?? "" : "",
    trojanRealitySpiderX: outbound.protocol === "trojan" ? outbound.reality?.spiderX ?? "" : "",
    trojanAllowInsecure: outbound.protocol === "trojan" ? !!outbound.tls?.allowInsecure : false,
    trojanTransportKind: outbound.protocol === "trojan" ? outbound.transport.kind : "tcp" as const,
    trojanTransportPath: outbound.protocol === "trojan" ? outbound.transport.path ?? "" : "",
    trojanTransportHost: outbound.protocol === "trojan" ? outbound.transport.host ?? "" : "",

    // AnyTLS mapping
    anytlsPassword: outbound.protocol === "anytls" ? outbound.password : "",
    anytlsClientFingerprint: outbound.protocol === "anytls" ? outbound.clientFingerprint ?? "" : "",
    anytlsUdp: outbound.protocol === "anytls" ? !!outbound.udp : true,
    anytlsIdleSessionCheckInterval: outbound.protocol === "anytls" ? String(outbound.idleSessionCheckInterval ?? "") : "",
    anytlsIdleSessionTimeout: outbound.protocol === "anytls" ? String(outbound.idleSessionTimeout ?? "") : "",
    anytlsMinIdleSession: outbound.protocol === "anytls" ? String(outbound.minIdleSession ?? "") : "",
    anytlsSni: outbound.protocol === "anytls" ? outbound.sni ?? "" : "",
    anytlsAlpn: outbound.protocol === "anytls" ? (outbound.alpn ?? []).join(",") : "",
    anytlsSkipCertVerify: outbound.protocol === "anytls" ? !!outbound.skipCertVerify : false,

    importedOutbound: outbound.protocol === "socks" ? null : outbound,
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

function buildOutboundFromDraft(draft: RuleFormState): OutboundConfig | null {
  const port = parsePort(draft.port);
  const vlessLevel = parseOptionalNonNegativeInteger(draft.vlessLevel);

  if (port === null || Number.isNaN(vlessLevel)) {
    return null;
  }

  if (draft.outboundProtocol === "vless") {
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

  if (draft.outboundProtocol === "shadowsocks") {
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

  if (draft.outboundProtocol === "trojan") {
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

  if (draft.outboundProtocol === "anytls") {
    const checkInterval = parseOptionalNonNegativeInteger(draft.anytlsIdleSessionCheckInterval);
    const timeout = parseOptionalNonNegativeInteger(draft.anytlsIdleSessionTimeout);
    const minIdle = parseOptionalNonNegativeInteger(draft.anytlsMinIdleSession);

    if (Number.isNaN(checkInterval) || Number.isNaN(timeout) || Number.isNaN(minIdle)) {
      return null;
    }

    return {
      protocol: "anytls",
      address: draft.address.trim(),
      port,
      password: draft.anytlsPassword,
      clientFingerprint: draft.anytlsClientFingerprint.trim() === "" ? null : draft.anytlsClientFingerprint.trim(),
      udp: draft.anytlsUdp,
      idleSessionCheckInterval: checkInterval,
      idleSessionTimeout: timeout,
      minIdleSession: minIdle,
      sni: draft.anytlsSni.trim() === "" ? null : draft.anytlsSni.trim(),
      alpn: draft.anytlsAlpn.trim() === "" ? null : draft.anytlsAlpn.split(",").map(s => s.trim()).filter(Boolean),
      skipCertVerify: draft.anytlsSkipCertVerify,
      importSource: draft.importedOutbound?.protocol === "anytls" ? draft.importedOutbound.importSource : null,
    };
  }

  return {
    protocol: "socks",
    host: draft.address.trim(),
    port,
    auth: buildAuthConfig(draft.socksUsername, draft.socksPassword),
  };
}

function applyOutboundToDraft(draft: RuleFormState, outbound: OutboundConfig): RuleFormState {
  const nextDraft: RuleFormState = {
    ...draft,
    outboundProtocol: outbound.protocol,
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

  if (outbound.protocol === "anytls") {
    return {
      ...nextDraft,
      anytlsPassword: outbound.password,
      anytlsClientFingerprint: outbound.clientFingerprint ?? "",
      anytlsUdp: outbound.udp ?? true,
      anytlsIdleSessionCheckInterval: outbound.idleSessionCheckInterval !== null && outbound.idleSessionCheckInterval !== undefined ? String(outbound.idleSessionCheckInterval) : "",
      anytlsIdleSessionTimeout: outbound.idleSessionTimeout !== null && outbound.idleSessionTimeout !== undefined ? String(outbound.idleSessionTimeout) : "",
      anytlsMinIdleSession: outbound.minIdleSession !== null && outbound.minIdleSession !== undefined ? String(outbound.minIdleSession) : "",
      anytlsSni: outbound.sni ?? "",
      anytlsAlpn: (outbound.alpn ?? []).join(","),
      anytlsSkipCertVerify: !!outbound.skipCertVerify,
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

function buildInboundProxyUrl(rule: ProxyRule) {
  const scheme = rule.inbound.protocol === "socks" ? "socks5" : "http";
  return `${scheme}://${rule.inbound.listen}:${rule.inbound.port}`;
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

  // Batch import state
  const [batchAddOpen, setBatchAddOpen] = useState(false);
  const [batchAddText, setBatchAddText] = useState("");
  const [batchAddInboundType, setBatchAddInboundType] = useState("mixed");
  const [batchAddInboundListen, setBatchAddInboundListen] = useState("127.0.0.1");
  const [batchAddError, setBatchAddError] = useState("");

  const [ruleFormError, setRuleFormError] = useState("");

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

        if (validation.valid && !status.running) {
          try {
            const portVal = await backend.validateRulePorts(state);
            if (portVal.valid) {
              const startStatus = await backend.startMihomo();
              if (shouldUpdate) {
                setRuntimeStatus(startStatus);
                showToast("success", "已自动启动 Mihomo 代理内核");
              }
            } else {
              showToast("warning", `自动启动内核失败：${portVal.message}`);
            }
          } catch (e) {
            console.error("Auto-start Mihomo failed:", e);
            if (shouldUpdate) {
              showToast("warning", `自动启动内核失败：${getErrorMessage(e)}`);
            }
          }
        }
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

  const batchToggleMeta = useMemo(() => {
    if (selectedRuleIds.length === 0) {
      return { title: "批量启用/停用", icon: "play" as IconName };
    }
    const selectedRules = appState.rules.filter(r => selectedRuleIds.includes(r.id));
    const allEnabled = selectedRules.every(r => r.enabled);
    const allDisabled = selectedRules.every(r => !r.enabled);

    if (allEnabled) {
      return { title: "批量停用", icon: "stop" as IconName };
    } else if (allDisabled) {
      return { title: "批量启用", icon: "play" as IconName };
    } else {
      return { title: "批量停用", icon: "stop" as IconName };
    }
  }, [appState.rules, selectedRuleIds]);

  function showToast(tone: ToastTone, message: string) {
    setToastNotification({ id: Date.now(), tone, message });
  }

  async function saveAndApplyState(nextState: AppState) {
    const result = await backend.saveAndApplyAppState(nextState);
    setAppState(result.state);
    setRuntimeStatus(result.status);
    setLastSavedAt(formatTime());
    showToast("success", result.restarted ? "配置已保存并重载运行中的 Mihomo" : "配置已保存成功！");
    return result.state;
  }

  // Rules Tab Filter
  const filteredRules = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return appState.rules;
    return appState.rules.filter((rule) => {
      const outboundAddress = rule.outbound.protocol === "socks" ? rule.outbound.host : rule.outbound.address;
      return rule.remark.toLowerCase().includes(query) ||
        String(rule.inbound.port).includes(query) ||
        outboundAddress.toLowerCase().includes(query) ||
        rule.inbound.protocol.toLowerCase().includes(query);
    });
  }, [appState.rules, searchQuery]);

  const itemsPerPage = 10;
  const totalPages = Math.max(1, Math.ceil(filteredRules.length / itemsPerPage));

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery]);

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

  // Actions for ProxyRules
  async function toggleRuleEnabled(rule: ProxyRule) {
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

  async function toggleSelectedRules() {
    if (selectedRuleIds.length === 0 || isBusy) return;
    setBusyAction("toggle");
    try {
      const selectedRules = appState.rules.filter(r => selectedRuleIds.includes(r.id));
      const allEnabled = selectedRules.every(r => r.enabled);
      const allDisabled = selectedRules.every(r => !r.enabled);

      let targetEnabled: boolean;
      if (allEnabled) {
        targetEnabled = false;
      } else if (allDisabled) {
        targetEnabled = true;
      } else {
        targetEnabled = false;
      }

      const nextRules = appState.rules.map(r => selectedRuleIds.includes(r.id) ? { ...r, enabled: targetEnabled } : r);
      await saveAndApplyState({ ...appState, rules: nextRules });
    } catch (err) {
      showToast("error", `批量切换状态失败：${getErrorMessage(err)}`);
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

  async function checkRuleIp(rule: ProxyRule) {
    if (isBusy) return;
    setBusyAction(`ip-${rule.id}`);
    try {
      const state = await backend.checkRuleIp(rule.id);
      setAppState(state);
      showToast("success", `${rule.remark} 出口 IP 刷新成功！`);
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
    const usedPorts = new Set(appState.rules.map(r => r.inbound.port));
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
        remark: `规则-${appState.rules.length + 1}`,
        inboundProtocol: "mixed",
        inboundListen: "127.0.0.1",
        inboundPort: "",
        inboundUsername: "",
        inboundPassword: "",
        enabled: true,

        // Outbound default values
        outboundProtocol: "socks",
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

        // AnyTLS defaults
        anytlsPassword: "",
        anytlsClientFingerprint: "",
        anytlsUdp: true,
        anytlsIdleSessionCheckInterval: "",
        anytlsIdleSessionTimeout: "",
        anytlsMinIdleSession: "",
        anytlsSni: "",
        anytlsAlpn: "",
        anytlsSkipCertVerify: false,

        importedOutbound: null,
      }
    });

    findDefaultInboundPort().then(port => {
      setRuleModal(curr => {
        if (!curr || curr.mode !== "create") return curr;
        return {
          ...curr,
          draft: { ...curr.draft, inboundPort: curr.draft.inboundPort || port }
        };
      });
    }).catch(() => {});
  }

  function openEditRuleModal(rule: ProxyRule) {
    setRuleFormError("");
    const outboundDraft = toOutboundFormState(rule.outbound);
    setRuleModal({
      mode: "edit",
      editingId: rule.id,
      draft: {
        remark: rule.remark,
        inboundProtocol: rule.inbound.protocol,
        inboundListen: rule.inbound.listen,
        inboundPort: String(rule.inbound.port),
        inboundUsername: rule.inbound.auth?.username ?? "",
        inboundPassword: rule.inbound.auth?.password ?? "",
        enabled: rule.enabled,
        ...outboundDraft,
      }
    });
  }

  async function handlePasteOutboundUrl(url: string) {
    if (!ruleModal || !url.trim()) return;
    try {
      const parsed = await backend.parseOutboundUrl(url.trim());
      setRuleModal(curr => {
        if (!curr) return null;
        const nextDraft = applyOutboundToDraft(curr.draft, parsed.outbound);
        if (parsed.displayName) {
          nextDraft.remark = parsed.displayName;
        }
        return {
          ...curr,
          draft: {
            ...nextDraft,
            outboundProxyUrl: url.trim(),
          },
        };
      });
      if (parsed.warnings && parsed.warnings.length > 0) {
        showToast("warning", `导入有警告：${parsed.warnings.join("; ")}`);
      } else {
        showToast("success", "解析并填入出站代理信息成功！");
      }
    } catch (error) {
      showToast("error", `解析代理 URL 失败：${getErrorMessage(error)}`);
    }
  }

  async function handleRuleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!ruleModal || isBusy) return;
    setRuleFormError("");

    const { remark, inboundProtocol, inboundListen, inboundPort, inboundUsername, inboundPassword, enabled } = ruleModal.draft;
    const port = parsePort(inboundPort);

    if (!remark.trim() || !inboundListen.trim()) {
      setRuleFormError("请填写全部必须的字段");
      return;
    }
    if (port === null) {
      setRuleFormError("本地端口必须是 1 到 65535 之间的有效整数");
      return;
    }

    const outbound = buildOutboundFromDraft(ruleModal.draft);
    if (!outbound) {
      setRuleFormError("出站代理配置校验失败，请检查各出站字段是否正确填写");
      return;
    }

    setBusyAction("rule");
    try {
      const ruleObj: ProxyRule = {
        id: ruleModal.editingId ?? "",
        remark: remark.trim(),
        enabled,
        inbound: {
          protocol: inboundProtocol,
          listen: inboundListen.trim() || "127.0.0.1",
          port,
          auth: buildAuthConfig(inboundUsername, inboundPassword),
        },
        outbound,
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

      const usedPorts = new Set(appState.rules.map(r => r.inbound.port));
      const allocatedPorts: number[] = [];
      let currentPort = 50000;

      for (let i = 0; i < parseResults.length; i++) {
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

      let nextState = { ...appState };
      const timestamp = Date.now();

      for (let i = 0; i < parseResults.length; i++) {
        const parsed = parseResults[i];
        let remark = parsed.displayName?.trim() ?? "";
        if (!remark) {
          remark = `规则_${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
        }
        let name = remark;
        let suffix = 1;
        while (nextState.rules.some(r => r.remark === name)) {
          name = `${remark}-${suffix}`;
          suffix++;
        }

        const port = allocatedPorts[i];
        const newRule: ProxyRule = {
          id: `rule-batch-${timestamp}-${i}`,
          remark: name,
          enabled: true,
          inbound: {
            protocol: batchAddInboundType as "mixed" | "socks" | "http",
            listen: batchAddInboundListen,
            port,
            auth: null,
          },
          outbound: parsed.outbound,
          ipCheck: null,
        };
        nextState.rules.push(newRule);
      }

      await saveAndApplyState(nextState);
      showToast("success", `批量导入已成功！共生成了 ${parseResults.length} 条端口与出口节点规则。`);
      setBatchAddOpen(false);
      setBatchAddText("");
      setBatchAddError("");
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
          <p>入口规则总数</p>
        </div>
        <div className="metric-card">
          <span>{appState.rules.filter(r => r.enabled).length}</span>
          <p>已启用规则数</p>
        </div>
        <div className="metric-card wide">
          <span>{lastSavedAt}</span>
          <p>系统配置保存时间</p>
        </div>
      </section>

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
              <button className="ghost-button" onClick={() => void toggleSelectedRules()} disabled={selectedRuleIds.length === 0 || isBusy} title={batchToggleMeta.title}>
                <Icon name={batchToggleMeta.icon} />
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
                const inboundCopyKey = `${rule.id}-inbound-link`;
                const inboundUrl = buildInboundProxyUrl(rule);
                const isChecking = busyAction === `ip-${rule.id}` || checkingRuleIds.includes(rule.id);
                const outboundAddrStr = getOutboundAddress(rule.outbound);

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
                            <h3>{rule.remark}</h3>
                          </div>
                        </div>

                        <div className="endpoint-line local">
                          <strong>{rule.inbound.protocol.toUpperCase()}</strong>
                          <span>{formatLocalInboundAddress(rule.inbound.listen, rule.inbound.port)}</span>
                          <button
                            className="copy-button compact-copy"
                            title={copiedKey === inboundCopyKey ? "已复制" : "复制链接"}
                            onClick={() => void copyToClipboard(inboundCopyKey, inboundUrl)}
                          >
                            <Icon name="copy" />
                          </button>
                        </div>

                        <div className="endpoint-line outbound" style={{ flex: 1.5 }}>
                          <span style={{ color: "var(--color-accent)", fontWeight: 700 }}>
                            {formatOutboundProtocol(rule.outbound.protocol)}
                          </span>
                          <span style={{ color: "var(--color-accent-2)", fontSize: "0.85rem", marginLeft: "8px", fontFamily: "monospace" }}>
                            {outboundAddrStr}
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

      {/* MODAL: ProxyRule Add/Edit */}
      {ruleModal && (
        <div className="modal-layer" role="presentation">
          <section className="rule-modal" role="dialog" aria-modal="true">
            <form onSubmit={(e) => void handleRuleSubmit(e)}>
              <div className="modal-header">
                <div>
                  <p className="eyebrow">Rule Editor</p>
                  <h2>{ruleModal.mode === "create" ? "新建入口代理规则" : "编辑入口代理规则"}</h2>
                  <p className="modal-description">配置本地浏览器连接的监听端口并一站式绑定出站代理出口节点。</p>
                </div>
                <button className="small-icon-button" type="button" onClick={() => setRuleModal(null)}>
                  <Icon name="close" />
                </button>
              </div>

              <div className="modal-body">
                <h3 className="section-title-mod">本地入站监听配置</h3>
                <section className="form-section">
                  <div className="form-grid">
                    <label className="field wide-field">
                      <span>规则备注</span>
                      <input
                        type="text"
                        value={ruleModal.draft.remark}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, remark: e.currentTarget.value } })}
                        placeholder="例如：浏览器账号 01 / 规则 A"
                        required
                      />
                    </label>

                    <label className="field">
                      <span>入站协议</span>
                      <select
                        value={ruleModal.draft.inboundProtocol}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, inboundProtocol: e.currentTarget.value as any } })}
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
                        value={ruleModal.draft.inboundListen}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, inboundListen: e.currentTarget.value } })}
                        required
                      />
                    </label>

                    <label className="field">
                      <span>监听端口</span>
                      <input
                        type="number"
                        min="1"
                        max="65535"
                        value={ruleModal.draft.inboundPort}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, inboundPort: e.currentTarget.value } })}
                        placeholder="留空自动分配"
                        required={ruleModal.mode === "edit"}
                      />
                    </label>

                    <label className="toggle-field wide-field">
                      <input
                        type="checkbox"
                        checked={ruleModal.draft.enabled}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, enabled: e.currentTarget.checked } })}
                      />
                      <span>启用此入口转发</span>
                    </label>

                    <label className="field">
                      <span>入站认证用户名</span>
                      <input
                        type="text"
                        value={ruleModal.draft.inboundUsername}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, inboundUsername: e.currentTarget.value } })}
                        placeholder="可选"
                      />
                    </label>
                    <label className="field">
                      <span>入站认证密码</span>
                      <input
                        type="password"
                        value={ruleModal.draft.inboundPassword}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, inboundPassword: e.currentTarget.value } })}
                        placeholder="可选"
                      />
                    </label>
                  </div>
                </section>

                <h3 className="section-title-mod" style={{ marginTop: "var(--space-4)" }}>出站代理配置</h3>
                <section className="form-section">
                  <div className="form-grid">
                    <label className="field wide-field">
                      <span>导入代理链接 (粘贴链接自动导入)</span>
                      <input
                        type="text"
                        value={ruleModal.draft.outboundProxyUrl}
                        onChange={(e) => void handlePasteOutboundUrl(e.currentTarget.value)}
                        placeholder="粘贴 ss://... / vless://... / trojan://... 链接"
                      />
                    </label>

                    <label className="field">
                      <span>出站代理协议</span>
                      <select
                        value={ruleModal.draft.outboundProtocol}
                        onChange={(e) => {
                          if (isOutboundProtocol(e.currentTarget.value)) {
                            setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, outboundProtocol: e.currentTarget.value } });
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
                        value={ruleModal.draft.address}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, address: e.currentTarget.value } })}
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
                        value={ruleModal.draft.port}
                        onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, port: e.currentTarget.value } })}
                        required
                      />
                    </label>

                    {/* SOCKS specific */}
                    {ruleModal.draft.outboundProtocol === "socks" && (
                      <>
                        <label className="field">
                          <span>认证用户名</span>
                          <input
                            type="text"
                            value={ruleModal.draft.socksUsername}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, socksUsername: e.currentTarget.value } })}
                            placeholder="可选"
                          />
                        </label>
                        <label className="field">
                          <span>认证密码</span>
                          <input
                            type="password"
                            value={ruleModal.draft.socksPassword}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, socksPassword: e.currentTarget.value } })}
                            placeholder="可选"
                          />
                        </label>
                      </>
                    )}

                    {/* Shadowsocks specific */}
                    {ruleModal.draft.outboundProtocol === "shadowsocks" && (
                      <>
                        <label className="field wide-field">
                          <span>加密算法</span>
                          <input
                            list="shadowsocks-ciphers"
                            type="text"
                            value={ruleModal.draft.shadowsocksMethod}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, shadowsocksMethod: e.currentTarget.value } })}
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
                            value={ruleModal.draft.shadowsocksPassword}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, shadowsocksPassword: e.currentTarget.value } })}
                            required
                          />
                        </label>
                      </>
                    )}

                    {/* VLESS specific */}
                    {ruleModal.draft.outboundProtocol === "vless" && (
                      <>
                        <label className="field wide-field">
                          <span>UUID / ID</span>
                          <input
                            type="text"
                            value={ruleModal.draft.vlessId}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessId: e.currentTarget.value } })}
                            placeholder="5783a3e7-e373-51cd-8642-c83782b807c5"
                            required
                          />
                        </label>
                        <label className="field">
                          <span>加密方案</span>
                          <input
                            type="text"
                            value={ruleModal.draft.vlessEncryption}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessEncryption: e.currentTarget.value } })}
                            placeholder="none"
                            required
                          />
                        </label>
                        <label className="field">
                          <span>安全传输协议</span>
                          <select
                            value={ruleModal.draft.vlessSecurity}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessSecurity: e.currentTarget.value as any } })}
                          >
                            <option value="none">无安全层</option>
                            <option value="tls">TLS</option>
                            <option value="reality">REALITY</option>
                          </select>
                        </label>
                        <label className="field">
                          <span>Flow</span>
                          <select
                            value={ruleModal.draft.vlessFlow}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessFlow: e.currentTarget.value as any } })}
                          >
                            <option value="">无</option>
                            {vlessFlowOptions.map(f => <option value={f} key={f}>{f}</option>)}
                          </select>
                        </label>
                        <label className="field">
                          <span>网络传输</span>
                          <select
                            value={ruleModal.draft.vlessTransportKind}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessTransportKind: e.currentTarget.value as any } })}
                          >
                            <option value="tcp">TCP</option>
                            <option value="ws">WebSocket (ws)</option>
                          </select>
                        </label>

                        {ruleModal.draft.vlessTransportKind === "ws" && (
                          <>
                            <label className="field">
                              <span>WS Path</span>
                              <input
                                type="text"
                                value={ruleModal.draft.vlessTransportPath}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessTransportPath: e.currentTarget.value } })}
                                placeholder="/"
                              />
                            </label>
                            <label className="field">
                              <span>WS Host</span>
                              <input
                                type="text"
                                value={ruleModal.draft.vlessTransportHost}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessTransportHost: e.currentTarget.value } })}
                                placeholder="sni.domain.com"
                              />
                            </label>
                          </>
                        )}

                        {ruleModal.draft.vlessSecurity !== "none" && (
                          <>
                            <label className="field">
                              <span>ServerName (SNI)</span>
                              <input
                                type="text"
                                value={ruleModal.draft.vlessServerName}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessServerName: e.currentTarget.value } })}
                                placeholder="domain.com"
                              />
                            </label>
                            <label className="field">
                              <span>Fingerprint</span>
                              <input
                                type="text"
                                value={ruleModal.draft.vlessFingerprint}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessFingerprint: e.currentTarget.value } })}
                                placeholder="chrome"
                              />
                            </label>
                          </>
                        )}

                        {ruleModal.draft.vlessSecurity === "tls" && (
                          <label className="toggle-field wide-field">
                            <input
                              type="checkbox"
                              checked={ruleModal.draft.vlessAllowInsecure}
                              onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessAllowInsecure: e.currentTarget.checked } })}
                            />
                            <span>忽略证书校验错误 (skip-cert-verify)</span>
                          </label>
                        )}

                        {ruleModal.draft.vlessSecurity === "reality" && (
                          <>
                            <label className="field wide-field">
                              <span>REALITY Public Key</span>
                              <input
                                type="text"
                                value={ruleModal.draft.vlessRealityPublicKey}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessRealityPublicKey: e.currentTarget.value } })}
                                required
                              />
                            </label>
                            <label className="field">
                              <span>REALITY Short ID</span>
                              <input
                                type="text"
                                value={ruleModal.draft.vlessRealityShortId}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, vlessRealityShortId: e.currentTarget.value } })}
                              />
                            </label>
                          </>
                        )}
                      </>
                    )}

                    {/* Trojan specific */}
                    {ruleModal.draft.outboundProtocol === "trojan" && (
                      <>
                        <label className="field wide-field">
                          <span>连接密码</span>
                          <input
                            type="password"
                            value={ruleModal.draft.trojanPassword}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, trojanPassword: e.currentTarget.value } })}
                            required
                          />
                        </label>
                        <label className="field">
                          <span>安全层</span>
                          <select
                            value={ruleModal.draft.trojanSecurity}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, trojanSecurity: e.currentTarget.value as any } })}
                          >
                            <option value="none">无安全层</option>
                            <option value="tls">TLS</option>
                            <option value="reality">REALITY</option>
                          </select>
                        </label>
                        <label className="field">
                          <span>网络传输</span>
                          <select
                            value={ruleModal.draft.trojanTransportKind}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, trojanTransportKind: e.currentTarget.value as any } })}
                          >
                            <option value="tcp">TCP</option>
                            <option value="ws">WebSocket (ws)</option>
                          </select>
                        </label>

                        {ruleModal.draft.trojanTransportKind === "ws" && (
                          <>
                            <label className="field">
                              <span>WS Path</span>
                              <input
                                type="text"
                                value={ruleModal.draft.trojanTransportPath}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, trojanTransportPath: e.currentTarget.value } })}
                                placeholder="/"
                              />
                            </label>
                            <label className="field">
                              <span>WS Host</span>
                              <input
                                type="text"
                                value={ruleModal.draft.trojanTransportHost}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, trojanTransportHost: e.currentTarget.value } })}
                                placeholder="sni.domain.com"
                              />
                            </label>
                          </>
                        )}

                        {ruleModal.draft.trojanSecurity !== "none" && (
                          <>
                            <label className="field">
                              <span>ServerName (SNI)</span>
                              <input
                                type="text"
                                value={ruleModal.draft.trojanServerName}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, trojanServerName: e.currentTarget.value } })}
                                placeholder="domain.com"
                              />
                            </label>
                            <label className="field">
                              <span>Fingerprint</span>
                              <input
                                type="text"
                                value={ruleModal.draft.trojanFingerprint}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, trojanFingerprint: e.currentTarget.value } })}
                                placeholder="chrome"
                              />
                            </label>
                          </>
                        )}

                        {ruleModal.draft.trojanSecurity === "tls" && (
                          <label className="toggle-field wide-field">
                            <input
                              type="checkbox"
                              checked={ruleModal.draft.trojanAllowInsecure}
                              onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, trojanAllowInsecure: e.currentTarget.checked } })}
                            />
                            <span>忽略证书校验错误 (skip-cert-verify)</span>
                          </label>
                        )}

                        {ruleModal.draft.trojanSecurity === "reality" && (
                          <>
                            <label className="field wide-field">
                              <span>REALITY Public Key</span>
                              <input
                                type="text"
                                value={ruleModal.draft.trojanRealityPublicKey}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, trojanRealityPublicKey: e.currentTarget.value } })}
                                required
                              />
                            </label>
                            <label className="field">
                              <span>REALITY Short ID</span>
                              <input
                                type="text"
                                value={ruleModal.draft.trojanRealityShortId}
                                onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, trojanRealityShortId: e.currentTarget.value } })}
                              />
                            </label>
                          </>
                        )}
                      </>
                    )}

                    {/* AnyTLS specific */}
                    {ruleModal.draft.outboundProtocol === "anytls" && (
                      <>
                        <label className="field wide-field">
                          <span>连接密码 (password)</span>
                          <input
                            type="password"
                            value={ruleModal.draft.anytlsPassword}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, anytlsPassword: e.currentTarget.value } })}
                            required
                          />
                        </label>
                        <label className="field">
                          <span>ServerName (SNI)</span>
                          <input
                            type="text"
                            value={ruleModal.draft.anytlsSni}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, anytlsSni: e.currentTarget.value } })}
                            placeholder="domain.com"
                          />
                        </label>
                        <label className="field">
                          <span>Fingerprint</span>
                          <input
                            type="text"
                            value={ruleModal.draft.anytlsClientFingerprint}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, anytlsClientFingerprint: e.currentTarget.value } })}
                            placeholder="chrome"
                          />
                        </label>
                        <label className="field">
                          <span>ALPN (逗号分隔)</span>
                          <input
                            type="text"
                            value={ruleModal.draft.anytlsAlpn}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, anytlsAlpn: e.currentTarget.value } })}
                            placeholder="h2,http/1.1"
                          />
                        </label>
                        <label className="field">
                          <span>空闲连接检查间隔 (秒)</span>
                          <input
                            type="number"
                            value={ruleModal.draft.anytlsIdleSessionCheckInterval}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, anytlsIdleSessionCheckInterval: e.currentTarget.value } })}
                            placeholder="30"
                          />
                        </label>
                        <label className="field">
                          <span>空闲会话超时 (秒)</span>
                          <input
                            type="number"
                            value={ruleModal.draft.anytlsIdleSessionTimeout}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, anytlsIdleSessionTimeout: e.currentTarget.value } })}
                            placeholder="30"
                          />
                        </label>
                        <label className="field">
                          <span>最小空闲会话数</span>
                          <input
                            type="number"
                            value={ruleModal.draft.anytlsMinIdleSession}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, anytlsMinIdleSession: e.currentTarget.value } })}
                            placeholder="0"
                          />
                        </label>
                        <label className="toggle-field wide-field">
                          <input
                            type="checkbox"
                            checked={ruleModal.draft.anytlsUdp}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, anytlsUdp: e.currentTarget.checked } })}
                          />
                          <span>启用 UDP 转发</span>
                        </label>
                        <label className="toggle-field wide-field">
                          <input
                            type="checkbox"
                            checked={ruleModal.draft.anytlsSkipCertVerify}
                            onChange={(e) => setRuleModal({ ...ruleModal, draft: { ...ruleModal.draft, anytlsSkipCertVerify: e.currentTarget.checked } })}
                          />
                          <span>忽略证书校验错误 (skip-cert-verify)</span>
                        </label>
                      </>
                    )}
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

      {/* BATCH IMPORT MODAL */}
      {batchAddOpen && (
        <div className="modal-layer" role="presentation">
          <section className="rule-modal" role="dialog" aria-modal="true">
            <form onSubmit={(e) => void handleBatchAddSubmit(e)}>
              <div className="modal-header">
                <div>
                  <p className="eyebrow">Batch Importer</p>
                  <h2>批量导入代理规则</h2>
                  <p className="modal-description">一行输入一个出口链接。系统将自动生成对应的本地代理监听规则端口。</p>
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


    </main>
  );
}

export default App;
