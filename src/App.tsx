import { useEffect, useMemo, useState, useRef, type FormEvent, type ReactElement } from "react";
import { backend, type AppState, type AuthConfig, type InboundProtocol, type OutboundConfig, type OutboundProtocol, type ProxyRule, type RuntimeStatus, type VlessFlow, type XrayBinaryValidation, type XrayVersionInfo } from "./api/backend";
import { RuntimeHero } from "./features/runtime/RuntimeHero";
import type { StatusMeta } from "./features/runtime/runtime-types";
import "./App.css";

type RuleFormState = {
  remark: string;
  enabled: boolean;
  inboundProtocol: InboundProtocol;
  inboundListen: string;
  inboundPort: string;
  inboundUsername: string;
  inboundPassword: string;
  outboundProtocol: OutboundProtocol;
  outboundProxyUrl: string;
  outboundHost: string;
  outboundPort: string;
  outboundUsername: string;
  outboundPassword: string;
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
  editingRuleId: string | null;
  inboundAuthExpanded: boolean;
  draft: RuleFormState;
};

type DeleteConfirmation =
  | {
    mode: "single";
    ruleId: string;
    remark: string;
  }
  | {
    mode: "bulk";
    ruleIds: string[];
    count: number;
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
  schemaVersion: 2,
  rules: [],
};

const inboundProtocolOptions: InboundProtocol[] = ["socks", "http"];
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

const outboundConfigFieldNames: Array<keyof RuleFormState> = [
  "outboundProtocol",
  "outboundHost",
  "outboundPort",
  "outboundUsername",
  "outboundPassword",
  "vlessId",
  "vlessEncryption",
  "vlessFlow",
  "vlessLevel",
  "vlessSecurity",
  "vlessServerName",
  "vlessFingerprint",
  "vlessRealityPublicKey",
  "vlessRealityShortId",
  "vlessRealitySpiderX",
  "vlessAllowInsecure",
  "vlessTransportKind",
  "vlessTransportPath",
  "vlessTransportHost",
  "shadowsocksMethod",
  "shadowsocksPassword",
  "shadowsocksUot",
  "shadowsocksUotVersion",
  "trojanPassword",
  "trojanEmail",
  "trojanLevel",
  "trojanSecurity",
  "trojanServerName",
  "trojanFingerprint",
  "trojanRealityPublicKey",
  "trojanRealityShortId",
  "trojanRealitySpiderX",
  "trojanAllowInsecure",
  "trojanTransportKind",
  "trojanTransportPath",
  "trojanTransportHost",
];

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

function formatInboundProtocol(protocol: InboundProtocol) {
  return protocol === "socks" ? "SOCKS5" : "HTTP";
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
  if (protocol === "socks") {
    return "SOCKS5";
  }

  if (protocol === "vless") {
    return "VLESS";
  }

  if (protocol === "trojan") {
    return "Trojan";
  }

  return "Shadowsocks";
}

function getOutboundAddress(outbound: OutboundConfig) {
  return outbound.protocol === "socks" ? `${outbound.host}:${outbound.port}` : `${outbound.address}:${outbound.port}`;
}

function getOutboundImportWarnings(outbound: OutboundConfig) {
  return outbound.protocol === "socks" ? [] : outbound.importSource?.warnings ?? [];
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

function toRuleDraft(rule: ProxyRule): RuleFormState {
  const outboundAddress = rule.outbound.protocol === "socks" ? rule.outbound.host : rule.outbound.address;
  const socksAuth = rule.outbound.protocol === "socks" ? rule.outbound.auth : null;
  const vlessSecurity = rule.outbound.protocol === "vless" && rule.outbound.reality !== null ? "reality" : rule.outbound.protocol === "vless" && rule.outbound.tls !== null ? "tls" : "none";
  const trojanSecurity = rule.outbound.protocol === "trojan" && rule.outbound.reality !== null ? "reality" : rule.outbound.protocol === "trojan" && rule.outbound.tls !== null ? "tls" : "none";

  return {
    remark: rule.remark,
    enabled: rule.enabled,
    inboundProtocol: rule.inbound.protocol,
    inboundListen: rule.inbound.listen,
    inboundPort: String(rule.inbound.port),
    inboundUsername: rule.inbound.auth?.username ?? "",
    inboundPassword: rule.inbound.auth?.password ?? "",
    outboundProtocol: rule.outbound.protocol,
    outboundProxyUrl: "",
    outboundHost: outboundAddress,
    outboundPort: String(rule.outbound.port),
    outboundUsername: socksAuth?.username ?? "",
    outboundPassword: socksAuth?.password ?? "",
    vlessId: rule.outbound.protocol === "vless" ? rule.outbound.id : "",
    vlessEncryption: rule.outbound.protocol === "vless" ? rule.outbound.encryption : "none",
    vlessFlow: rule.outbound.protocol === "vless" ? rule.outbound.flow ?? "" : "",
    vlessLevel: rule.outbound.protocol === "vless" ? String(rule.outbound.level ?? "") : "",
    vlessSecurity,
    vlessServerName: rule.outbound.protocol === "vless" ? rule.outbound.reality?.serverName ?? rule.outbound.tls?.serverName ?? "" : "",
    vlessFingerprint: rule.outbound.protocol === "vless" ? rule.outbound.reality?.fingerprint ?? rule.outbound.tls?.fingerprint ?? "" : "",
    vlessRealityPublicKey: rule.outbound.protocol === "vless" ? rule.outbound.reality?.publicKey ?? "" : "",
    vlessRealityShortId: rule.outbound.protocol === "vless" ? rule.outbound.reality?.shortId ?? "" : "",
    vlessRealitySpiderX: rule.outbound.protocol === "vless" ? rule.outbound.reality?.spiderX ?? "" : "",
    vlessAllowInsecure: rule.outbound.protocol === "vless" ? !!rule.outbound.tls?.allowInsecure : false,
    vlessTransportKind: rule.outbound.protocol === "vless" ? rule.outbound.transport.kind : "tcp",
    vlessTransportPath: rule.outbound.protocol === "vless" ? rule.outbound.transport.path ?? "" : "",
    vlessTransportHost: rule.outbound.protocol === "vless" ? rule.outbound.transport.host ?? "" : "",
    shadowsocksMethod: rule.outbound.protocol === "shadowsocks" ? rule.outbound.method : shadowsocksMethodOptions[0],
    shadowsocksPassword: rule.outbound.protocol === "shadowsocks" ? rule.outbound.password : "",
    shadowsocksUot: rule.outbound.protocol === "shadowsocks" ? rule.outbound.uot : false,
    shadowsocksUotVersion: rule.outbound.protocol === "shadowsocks" ? String(rule.outbound.uotVersion ?? "") as "" | "1" | "2" : "",
    trojanPassword: rule.outbound.protocol === "trojan" ? rule.outbound.password : "",
    trojanEmail: rule.outbound.protocol === "trojan" ? rule.outbound.email ?? "" : "",
    trojanLevel: rule.outbound.protocol === "trojan" ? String(rule.outbound.level ?? "") : "",
    trojanSecurity,
    trojanServerName: rule.outbound.protocol === "trojan" ? rule.outbound.reality?.serverName ?? rule.outbound.tls?.serverName ?? "" : "",
    trojanFingerprint: rule.outbound.protocol === "trojan" ? rule.outbound.reality?.fingerprint ?? rule.outbound.tls?.fingerprint ?? "" : "",
    trojanRealityPublicKey: rule.outbound.protocol === "trojan" ? rule.outbound.reality?.publicKey ?? "" : "",
    trojanRealityShortId: rule.outbound.protocol === "trojan" ? rule.outbound.reality?.shortId ?? "" : "",
    trojanRealitySpiderX: rule.outbound.protocol === "trojan" ? rule.outbound.reality?.spiderX ?? "" : "",
    trojanAllowInsecure: rule.outbound.protocol === "trojan" ? !!rule.outbound.tls?.allowInsecure : false,
    trojanTransportKind: rule.outbound.protocol === "trojan" ? rule.outbound.transport.kind : "tcp",
    trojanTransportPath: rule.outbound.protocol === "trojan" ? rule.outbound.transport.path ?? "" : "",
    trojanTransportHost: rule.outbound.protocol === "trojan" ? rule.outbound.transport.host ?? "" : "",
    importedOutbound: rule.outbound.protocol === "socks" ? null : rule.outbound,
  };
}

function createEmptyRuleDraft(nextIndex: number): RuleFormState {
  return {
    remark: `新建规则 ${nextIndex}`,
    enabled: true,
    inboundProtocol: "socks",
    inboundListen: "127.0.0.1",
    inboundPort: "",
    inboundUsername: "",
    inboundPassword: "",
    outboundProtocol: "socks",
    outboundProxyUrl: "",
    outboundHost: "",
    outboundPort: "1080",
    outboundUsername: "",
    outboundPassword: "",
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

function parseOptionalPort(portValue: string) {
  return portValue.trim() === "" ? null : parsePort(portValue);
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

  return {
    username: trimmedUsername,
    password,
  };
}

function hasPartialAuth(username: string, password: string) {
  return (username.trim() === "") !== (password === "");
}

function buildOutboundFromDraft(draft: RuleFormState): OutboundConfig | null {
  const outboundPort = parsePort(draft.outboundPort);
  const vlessLevel = parseOptionalNonNegativeInteger(draft.vlessLevel);

  if (outboundPort === null || Number.isNaN(vlessLevel)) {
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
      address: draft.outboundHost.trim(),
      port: outboundPort,
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
      address: draft.outboundHost.trim(),
      port: outboundPort,
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
      address: draft.outboundHost.trim(),
      port: outboundPort,
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
    host: draft.outboundHost.trim(),
    port: outboundPort,
    auth: buildAuthConfig(draft.outboundUsername, draft.outboundPassword),
  };
}

function buildRuleFromDraft(id: string, draft: RuleFormState): ProxyRule | null {
  const inboundPort = parsePort(draft.inboundPort);
  const outbound = buildOutboundFromDraft(draft);

  if (inboundPort === null || outbound === null) {
    return null;
  }

  return {
    id,
    remark: draft.remark.trim(),
    enabled: draft.enabled,
    inbound: {
      protocol: draft.inboundProtocol,
      listen: draft.inboundListen.trim(),
      port: inboundPort,
      auth: buildAuthConfig(draft.inboundUsername, draft.inboundPassword),
    },
    outbound,
    ipCheck: null,
  };
}

function applyOutboundToDraft(draft: RuleFormState, outbound: OutboundConfig): RuleFormState {
  const nextDraft: RuleFormState = {
    ...draft,
    outboundProtocol: outbound.protocol,
    outboundHost: outbound.protocol === "socks" ? outbound.host : outbound.address,
    outboundPort: String(outbound.port),
    importedOutbound: outbound.protocol === "socks" ? null : outbound,
  };

  if (outbound.protocol === "socks") {
    return {
      ...nextDraft,
      outboundUsername: outbound.auth?.username ?? "",
      outboundPassword: outbound.auth?.password ?? "",
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

function isInboundProtocol(value: string): value is InboundProtocol {
  return inboundProtocolOptions.some((protocol) => protocol === value);
}

function isOutboundProtocol(value: string): value is OutboundProtocol {
  return outboundProtocolOptions.some((protocol) => protocol === value);
}

function buildInboundProxyUrl(rule: ProxyRule) {
  const scheme = rule.inbound.protocol === "socks" ? "socks5" : "http";
  const username = rule.inbound.auth?.username ?? "";
  const password = rule.inbound.auth?.password ?? "";
  const credentials = username !== "" || password !== "" ? `${encodeURIComponent(username)}:${encodeURIComponent(password)}@` : "";

  return `${scheme}://${credentials}${rule.inbound.listen}:${rule.inbound.port}`;
}

type OutboundDraftCopyState =
  | {
    disabled: false;
    title: string;
    url: string;
  }
  | {
    disabled: true;
    title: string;
    url: "";
  };

function isStraightforwardUrlHost(host: string) {
  return host !== "" && !/[\s/?#@]/.test(host);
}

function buildSocksOutboundDraftCopyState(draft: RuleFormState): OutboundDraftCopyState {
  const host = draft.outboundHost.trim();
  const port = parsePort(draft.outboundPort);

  if (!isStraightforwardUrlHost(host) || port === null) {
    return { disabled: true, title: "请填写有效的上游主机和端口后复制", url: "" };
  }

  if (hasPartialAuth(draft.outboundUsername, draft.outboundPassword)) {
    return { disabled: true, title: "用户名和密码需同时填写后复制", url: "" };
  }

  const auth = buildAuthConfig(draft.outboundUsername, draft.outboundPassword);
  const credentials = auth === null ? "" : `${encodeURIComponent(auth.username)}:${encodeURIComponent(auth.password)}@`;

  return { disabled: false, title: "复制上游出口代理链接", url: `socks5://${credentials}${host}:${port}` };
}

function buildVlessOutboundDraftCopyState(draft: RuleFormState): OutboundDraftCopyState {
  const rawUrl = draft.importedOutbound?.protocol === "vless" ? draft.importedOutbound.importSource?.rawUrl.trim() ?? "" : "";

  if (rawUrl !== "") {
    return { disabled: false, title: "复制导入的 VLESS 链接", url: rawUrl };
  }

  return { disabled: true, title: "当前协议暂不能生成链接，请从代理链接导入后复制", url: "" };
}

function buildShadowsocksOutboundDraftCopyState(draft: RuleFormState): OutboundDraftCopyState {
  const rawUrl = draft.importedOutbound?.protocol === "shadowsocks" ? draft.importedOutbound.importSource?.rawUrl.trim() ?? "" : "";

  if (rawUrl !== "") {
    return { disabled: false, title: "复制导入的 Shadowsocks 链接", url: rawUrl };
  }

  return { disabled: true, title: "当前协议暂不能生成链接，请从代理链接导入后复制", url: "" };
}

function buildTrojanOutboundDraftCopyState(draft: RuleFormState): OutboundDraftCopyState {
  const rawUrl = draft.importedOutbound?.protocol === "trojan" ? draft.importedOutbound.importSource?.rawUrl.trim() ?? "" : "";

  if (rawUrl !== "") {
    return { disabled: false, title: "复制导入的 Trojan 链接", url: rawUrl };
  }

  return { disabled: true, title: "当前协议暂不能生成链接，请从代理链接导入后复制", url: "" };
}

function getOutboundDraftCopyState(draft: RuleFormState): OutboundDraftCopyState {
  if (draft.outboundProtocol === "socks") {
    return buildSocksOutboundDraftCopyState(draft);
  }

  if (draft.outboundProtocol === "vless") {
    return buildVlessOutboundDraftCopyState(draft);
  }

  if (draft.outboundProtocol === "trojan") {
    return buildTrojanOutboundDraftCopyState(draft);
  }

  return buildShadowsocksOutboundDraftCopyState(draft);
}

function formatSpeed(bytesPerSec: number): string {
  if (bytesPerSec < 1024) {
    return `${bytesPerSec} B/s`;
  }
  const kbps = bytesPerSec / 1024;
  if (kbps < 1024) {
    return `${kbps.toFixed(1)} KB/s`;
  }
  const mbps = kbps / 1024;
  return `${mbps.toFixed(1)} MB/s`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const kb = bytes / 1024;
  if (kb < 1024) {
    return `${kb.toFixed(1)} KB`;
  }
  const mb = kb / 1024;
  if (mb < 1024) {
    return `${mb.toFixed(1)} MB`;
  }
  const gb = mb / 1024;
  return `${gb.toFixed(1)} GB`;
}

function App() {
  const [appState, setAppState] = useState<AppState>(emptyAppState);
  const [theme, setTheme] = useState<"system" | "light" | "dark">(() => {
    const saved = localStorage.getItem("xray-tools-theme");
    return (saved === "light" || saved === "dark" || saved === "system") ? saved : "system";
  });
  const [runtimeStatus, setRuntimeStatus] = useState<RuntimeStatus>({ running: false, pid: null });
  const [xrayValidation, setXrayValidation] = useState<XrayBinaryValidation | null>(null);
  const [xrayVersion, setXrayVersion] = useState<XrayVersionInfo | null>(null);
  const [selectedRuleIds, setSelectedRuleIds] = useState<string[]>([]);
  const [copiedKey, setCopiedKey] = useState<string>("");
  const [lastSavedAt, setLastSavedAt] = useState("尚未保存");
  const [ruleModal, setRuleModal] = useState<RuleModalState | null>(null);
  const [deleteConfirmation, setDeleteConfirmation] = useState<DeleteConfirmation | null>(null);
  const [ruleFormError, setRuleFormError] = useState("");
  const [toastNotification, setToastNotification] = useState<ToastNotification | null>(null);
  const [busyAction, setBusyAction] = useState<BusyAction>("startup");
  const [searchQuery, setSearchQuery] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [batchAddOpen, setBatchAddOpen] = useState(false);
  const [batchAddText, setBatchAddText] = useState("");
  const [batchAddInboundProtocol, setBatchAddInboundProtocol] = useState<InboundProtocol>("socks");
  const [batchAddInboundListen, setBatchAddInboundListen] = useState("127.0.0.1");
  const [batchAddError, setBatchAddError] = useState("");
  const [checkingRuleIds, setCheckingRuleIds] = useState<string[]>([]);
  const [trafficStats, setTrafficStats] = useState<Record<string, { uplink: number; downlink: number }>>({});
  const [trafficSpeeds, setTrafficSpeeds] = useState<Record<string, { uplinkSpeed: number; downlinkSpeed: number }>>({});
  const prevStatsRef = useRef<{ timestamp: number; stats: Record<string, { uplink: number; downlink: number }> } | null>(null);
  const [statsDetailsRule, setStatsDetailsRule] = useState<ProxyRule | null>(null);

  const openStatsDetailsModal = (rule: ProxyRule) => {
    setStatsDetailsRule(rule);
  };

  const closeStatsDetailsModal = () => {
    setStatsDetailsRule(null);
  };

  useEffect(() => {
    if (!runtimeStatus.running) {
      setTrafficStats({});
      setTrafficSpeeds({});
      prevStatsRef.current = null;
      return;
    }

    let timerId: number | null = null;
    let isRequestPending = false;

    const poll = async () => {
      if (isRequestPending || document.visibilityState !== "visible") {
        return;
      }

      isRequestPending = true;
      try {
        const status = await backend.getRuntimeStatus();
        if (!status.running) {
          setRuntimeStatus(status);
          setTrafficStats({});
          setTrafficSpeeds({});
          prevStatsRef.current = null;
          return;
        }

        const res = await backend.queryXrayStats();
        const now = Date.now();
        const currentStats: Record<string, { uplink: number; downlink: number }> = {};

        if (res.stat) {
          for (const item of res.stat) {
            const match = item.name.match(/^inbound>>>inbound-([^>]+)>>>traffic>>>(uplink|downlink)$/);
            if (match) {
              const ruleId = match[1];
              const direction = match[2] as "uplink" | "downlink";
              if (!currentStats[ruleId]) {
                currentStats[ruleId] = { uplink: 0, downlink: 0 };
              }
              currentStats[ruleId][direction] = item.value ?? 0;
            }
          }
        }

        const newSpeeds: Record<string, { uplinkSpeed: number; downlinkSpeed: number }> = {};
        if (prevStatsRef.current) {
          const timeDelta = (now - prevStatsRef.current.timestamp) / 1000;
          if (timeDelta > 0.2) {
            for (const ruleId in currentStats) {
              const current = currentStats[ruleId];
              const prev = prevStatsRef.current.stats[ruleId] || { uplink: 0, downlink: 0 };
              
              const upDelta = Math.max(0, current.uplink - prev.uplink);
              const downDelta = Math.max(0, current.downlink - prev.downlink);
              
              newSpeeds[ruleId] = {
                uplinkSpeed: Math.round(upDelta / timeDelta),
                downlinkSpeed: Math.round(downDelta / timeDelta),
              };
            }
          }
        }

        setTrafficStats(currentStats);
        if (Object.keys(newSpeeds).length > 0) {
          setTrafficSpeeds(newSpeeds);
        }
        prevStatsRef.current = { timestamp: now, stats: currentStats };
      } catch (err) {
        console.error("Failed to query Xray stats:", err);
      } finally {
        isRequestPending = false;
      }
    };

    void poll();
    timerId = window.setInterval(poll, 2000);

    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        void poll();
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      if (timerId !== null) {
        window.clearInterval(timerId);
      }
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [runtimeStatus.running]);

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
      return () => {
        mediaQuery.removeEventListener("change", handleChange);
      };
    }
  }, [theme]);

  const handleThemeChange = (nextTheme: "system" | "light" | "dark") => {
    setTheme(nextTheme);
    localStorage.setItem("xray-tools-theme", nextTheme);
  };

  const rules = appState.rules;

  const filteredRules = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) {
      return rules;
    }
    return rules.filter((rule) => {
      const matchRemark = rule.remark.toLowerCase().includes(query);
      const country = rule.ipCheck?.country?.toLowerCase() || "";
      const matchCountry = country === query;
      return matchRemark || matchCountry;
    });
  }, [rules, searchQuery]);

  const itemsPerPage = 10;
  const totalPages = Math.max(1, Math.ceil(filteredRules.length / itemsPerPage));

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery]);

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages);
    }
  }, [currentPage, totalPages]);

  const paginatedRules = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    return filteredRules.slice(startIndex, startIndex + itemsPerPage);
  }, [filteredRules, currentPage]);

  const activeRuleCount = rules.filter((rule) => rule.enabled).length;
  const allSelected = filteredRules.length > 0 && filteredRules.every((rule) => selectedRuleIds.includes(rule.id));
  const selectedCount = selectedRuleIds.length;
  const selectedRules = rules.filter((rule) => selectedRuleIds.includes(rule.id));
  const shouldEnableSelectedRules = selectedRules.length > 0 && selectedRules.every((rule) => !rule.enabled);
  const selectedToggleIcon: IconName = shouldEnableSelectedRules ? "check" : "stop";
  const isBusy = busyAction !== "";
  const outboundDraftCopyState = ruleModal === null ? null : getOutboundDraftCopyState(ruleModal.draft);

  useEffect(() => {
    let shouldUpdate = true;

    async function loadBackendState() {
      setBusyAction("startup");
      setAppError("");

      try {
        const [validation, state, status, version] = await Promise.all([
          backend.validateXrayBinary(),
          backend.loadAppState(),
          backend.getRuntimeStatus(),
          backend.getXrayVersion().catch(() => null),
        ]);

        if (!shouldUpdate) {
          return;
        }

        setXrayValidation(validation);
        setAppState(state);
        setRuntimeStatus(status);
        setXrayVersion(version);
        setLastSavedAt("已从磁盘载入");
      } catch (error) {
        if (shouldUpdate) {
          setAppError(`启动时无法读取后端状态：${getErrorMessage(error)}`);
        }
      } finally {
        if (shouldUpdate) {
          setBusyAction("");
        }
      }
    }

    void loadBackendState();

    return () => {
      shouldUpdate = false;
    };
  }, []);

  useEffect(() => {
    setSelectedRuleIds((currentIds) => currentIds.filter((currentId) => rules.some((rule) => rule.id === currentId)));
  }, [rules]);

  useEffect(() => {
    if (toastNotification === null) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setToastNotification((currentToast) => (currentToast?.id === toastNotification.id ? null : currentToast));
    }, toastAutoDismissMs);

    return () => window.clearTimeout(timeoutId);
  }, [toastNotification]);

  useEffect(() => {
    if (xrayValidation !== null && !xrayValidation.valid) {
      showToast("warning", `${xrayValidation.message}。请将 Mihomo 核心放到：${xrayValidation.path}`);
    }
  }, [xrayValidation]);

  const statusMeta = useMemo<StatusMeta>(() => {
    if (busyAction === "startup") {
      return { label: "加载中", detail: "正在读取后端状态与运行时路径", tone: "is-restarting" };
    }

    if (busyAction === "restart") {
      return { label: "重启中", detail: "正在通过后端重新启动 Mihomo", tone: "is-restarting" };
    }

    if (runtimeStatus.running) {
      const pidText = runtimeStatus.pid === null ? "" : ` PID ${runtimeStatus.pid}`;
      return { label: "运行中", detail: `核心已启动，规则路由已生效${pidText}`, tone: "is-running" };
    }

    return { label: "已停止", detail: "等待启动本地 Mihomo 核心", tone: "is-stopped" };
  }, [busyAction, runtimeStatus]);

  function isRuleSelected(ruleId: string) {
    return selectedRuleIds.includes(ruleId);
  }

  function toggleRuleSelection(ruleId: string) {
    setSelectedRuleIds((currentIds) =>
      currentIds.includes(ruleId) ? currentIds.filter((currentId) => currentId !== ruleId) : [...currentIds, ruleId],
    );
  }

  function toggleSelectAll() {
    if (allSelected) {
      const filteredIds = new Set(filteredRules.map((rule) => rule.id));
      setSelectedRuleIds((currentIds) => currentIds.filter((id) => !filteredIds.has(id)));
    } else {
      const filteredIds = filteredRules.map((rule) => rule.id);
      setSelectedRuleIds((currentIds) => {
        const nextIds = new Set([...currentIds, ...filteredIds]);
        return Array.from(nextIds);
      });
    }
  }

  function showToast(tone: ToastTone, message: string) {
    setToastNotification({ id: Date.now(), tone, message });
  }

  function clearToast() {
    setToastNotification(null);
  }

  function setAppError(message: string) {
    if (message === "") {
      clearToast();
      return;
    }

    showToast("error", message);
  }

  function setOperationMessage(message: string) {
    if (message === "") {
      clearToast();
      return;
    }

    showToast("success", message);
  }

  async function saveAndApplyState(nextState: AppState) {
    const result = await backend.saveAndApplyAppState(nextState);
    setAppState(result.state);
    setRuntimeStatus(result.status);
    setLastSavedAt(formatTime());
    setOperationMessage(result.restarted ? "配置已保存并重启运行中的 Mihomo。" : "配置已保存并写入生成文件。");
    return result.state;
  }

  async function refreshRuntimeFacts() {
    const [validation, status] = await Promise.all([backend.validateXrayBinary(), backend.getRuntimeStatus()]);
    setXrayValidation(validation);
    setRuntimeStatus(status);
    return { validation, status };
  }

  async function toggleSelectedRulesEnabled() {
    if (selectedRules.length === 0 || isBusy) {
      return;
    }

    setBusyAction("toggle");
    setAppError("");

    try {
      const nextState: AppState = {
        ...appState,
        rules: rules.map((rule) => (selectedRuleIds.includes(rule.id) ? { ...rule, enabled: shouldEnableSelectedRules } : rule)),
      };

      await saveAndApplyState(nextState);
    } catch (error) {
      setAppError(`切换规则失败：${getErrorMessage(error)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function checkRuleIp(rule: ProxyRule) {
    if (isBusy) {
      return;
    }

    setBusyAction(`ip-${rule.id}`);
    setAppError("");
    setOperationMessage("");

    try {
      const state = await backend.checkRuleIp(rule.id);
      setAppState(state);
      setLastSavedAt(formatTime());
      setOperationMessage(`${rule.remark} 的出口 IP 已更新。`);
    } catch (error) {
      setAppError(`IP 检查失败：${getErrorMessage(error)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function checkSelectedRulesIp() {
    if (isBusy) {
      return;
    }

    if (!runtimeStatus.running) {
      setAppError("请先启动 Mihomo 核心以进行 IP 检测。");
      return;
    }

    const enabledSelectedRules = rules.filter((rule) => selectedRuleIds.includes(rule.id) && rule.enabled);
    if (enabledSelectedRules.length === 0) {
      setAppError("所选规则中没有已启用的规则，无法进行 IP 检测。");
      return;
    }

    const enabledSelectedIds = enabledSelectedRules.map((rule) => rule.id);

    setBusyAction("batch-ip");
    setCheckingRuleIds(enabledSelectedIds);
    setAppError("");
    setOperationMessage("");

    try {
      const state = await backend.checkRulesIpBatch(enabledSelectedIds);
      setAppState(state);
      setLastSavedAt(formatTime());
      showToast("success", `批量 IP 检测完成！共检测了 ${enabledSelectedIds.length} 个代理出口。`);
      setOperationMessage(`已成功并行检测所选的 ${enabledSelectedIds.length} 个启用代理规则的出口 IP。`);
    } catch (error) {
      setAppError(`批量 IP 检测失败：${getErrorMessage(error)}`);
    } finally {
      setCheckingRuleIds([]);
      setBusyAction("");
    }
  }

  async function handleRuntimeAction(action: RuntimeAction) {
    if (isBusy) {
      return;
    }

    setBusyAction(action.name);
    setAppError("");
    setOperationMessage("");

    try {
      if (action.name === "save") {
        await saveAndApplyState(appState);
        return;
      }

      if (action.name === "play") {
        const validation = await backend.validateXrayBinary();
        setXrayValidation(validation);

        if (!validation.valid) {
          throw new Error(validation.message);
        }

        const portValidation = await backend.validateRulePorts(appState);

        if (!portValidation.valid) {
          throw new Error(portValidation.message);
        }

        await backend.saveAppState(appState);
        const status = await backend.startXray();
        setRuntimeStatus(status);
        setLastSavedAt(formatTime());
        setOperationMessage("Mihomo 已启动，当前磁盘状态已用于生成运行配置。");
        return;
      }

      if (action.name === "stop") {
        const status = await backend.stopXray();
        setRuntimeStatus(status);
        setOperationMessage("Mihomo 已停止。");
        return;
      }

      const status = await backend.restartXray();
      setRuntimeStatus(status);
      setOperationMessage("Mihomo 已重启并重新读取已保存状态。");
    } catch (error) {
      setAppError(`${action.label}失败：${getErrorMessage(error)}`);
      try {
        await refreshRuntimeFacts();
      } catch {
        setRuntimeStatus({ running: false, pid: null });
      }
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

  async function handleCopy(rule: ProxyRule) {
    if (isBusy) {
      return;
    }

    setBusyAction("rule");
    setAppError("");
    setOperationMessage("");

    try {
      const savedState = await backend.duplicateRule(rule.id);
      await saveAndApplyState(savedState);
      setOperationMessage(`规则 “${rule.remark}” 已成功复制，入口端口已自动配置。`);
    } catch (error) {
      setAppError(`复制规则失败：${getErrorMessage(error)}`);
    } finally {
      setBusyAction("");
    }
  }

  async function findDefaultInboundPort() {
    const enabledPorts = new Set(rules.filter((rule) => rule.enabled).map((rule) => rule.inbound.port));
    const portCount = maxAutoInboundPort - minAutoInboundPort + 1;
    const startPort = randomAutoInboundPort();
    const startOffset = startPort - minAutoInboundPort;

    for (let step = 0; step < portCount; step += 1) {
      const port = minAutoInboundPort + ((startOffset + step) % portCount);
      if (enabledPorts.has(port)) {
        continue;
      }

      const availability = await backend.checkPortAvailable(port, "127.0.0.1");
      if (availability.available) {
        return String(port);
      }
    }

    return "";
  }

  function openBatchAddModal() {
    setBatchAddError("");
    setBatchAddText("");
    setBatchAddInboundProtocol("socks");
    setBatchAddInboundListen("127.0.0.1");
    setBatchAddOpen(true);
  }

  function closeBatchAddModal() {
    setBatchAddOpen(false);
    setBatchAddError("");
  }

  async function handleBatchAddSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (isBusy) {
      return;
    }

    setBatchAddError("");
    setAppError("");

    const lines = batchAddText
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line !== "");

    if (lines.length === 0) {
      setBatchAddError("请输入至少一条有效的代理出口链接。");
      return;
    }

    setBusyAction("rule");

    try {
      // 1. Parse all links first to ensure complete atomic validation
      const parseResults: Array<{ outbound: OutboundConfig; displayName: string | null }> = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        try {
          const parsed = await backend.parseOutboundUrl(line);
          parseResults.push({
            outbound: parsed.outbound,
            displayName: parsed.displayName,
          });
        } catch (error) {
          throw new Error(`第 ${i + 1} 行解析失败：${getErrorMessage(error)}`);
        }
      }

      // 2. Allocate ports sequentially with system & existing rules check
      const usedPorts = new Set(rules.map((rule) => rule.inbound.port));
      const allocatedPorts: number[] = [];
      let currentPort = 50000;

      for (let i = 0; i < lines.length; i++) {
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
        if (!found) {
          throw new Error("没有足够的可用本地端口（范围 50000-65535）");
        }
      }

      // 3. Construct rule objects
      const newRules: ProxyRule[] = [];
      const timestamp = Date.now();
      for (let i = 0; i < lines.length; i++) {
        const { outbound, displayName } = parseResults[i];
        const port = allocatedPorts[i];

        // Name generation: extracted or random
        let remark = displayName?.trim() ?? "";
        if (remark === "") {
          const randomSuffix = Math.random().toString(36).substring(2, 6).toUpperCase();
          remark = `出口_${randomSuffix}`;
        }

        newRules.push({
          id: `rule-${timestamp}-${i}`,
          remark,
          enabled: true,
          inbound: {
            protocol: batchAddInboundProtocol,
            listen: batchAddInboundListen.trim(),
            port,
            auth: null,
          },
          outbound,
          ipCheck: null,
        });
      }

      // 4. Update state and save
      const nextState: AppState = {
        ...appState,
        rules: [...appState.rules, ...newRules],
      };

      await saveAndApplyState(nextState);
      showToast("success", `已成功批量添加 ${newRules.length} 条代理规则！`);
      closeBatchAddModal();
    } catch (error) {
      setBatchAddError(getErrorMessage(error));
    } finally {
      setBusyAction("");
    }
  }

  function openCreateRuleModal() {
    setRuleFormError("");
    setRuleModal({
      mode: "create",
      editingRuleId: null,
      inboundAuthExpanded: false,
      draft: createEmptyRuleDraft(rules.length + 1),
    });

    void findDefaultInboundPort()
      .then((port) => {
        if (port === "") {
          return;
        }

        setRuleModal((currentModal) =>
          currentModal?.mode === "create"
            ? {
              ...currentModal,
              draft: {
                ...currentModal.draft,
                inboundPort: currentModal.draft.inboundPort.trim() === "" ? port : currentModal.draft.inboundPort,
              },
            }
            : currentModal,
        );
      })
      .catch((error) => setRuleFormError(`自动选择入口端口失败：${getErrorMessage(error)}`));
  }

  function openEditRuleModal(rule: ProxyRule) {
    setRuleFormError("");
    setRuleModal({
      mode: "edit",
      editingRuleId: rule.id,
      inboundAuthExpanded: rule.inbound.auth !== null,
      draft: toRuleDraft(rule),
    });
  }

  function closeRuleModal() {
    setRuleModal(null);
    setRuleFormError("");
  }

  function updateRuleDraft<FieldName extends keyof RuleFormState>(fieldName: FieldName, value: RuleFormState[FieldName]) {
    setRuleModal((currentModal) =>
      currentModal === null
        ? currentModal
        : {
          ...currentModal,
          draft: {
            ...currentModal.draft,
            [fieldName]: value,
            importedOutbound: outboundConfigFieldNames.includes(fieldName) ? null : currentModal.draft.importedOutbound,
          },
        },
    );
  }

  function toggleInboundAuthFields() {
    setRuleModal((currentModal) =>
      currentModal === null
        ? currentModal
        : {
          ...currentModal,
          inboundAuthExpanded: !currentModal.inboundAuthExpanded,
        },
    );
  }

  async function handleOutboundProxyUrlChange(value: string) {
    setRuleFormError("");
    updateRuleDraft("outboundProxyUrl", value);

    const trimmedValue = value.trim();

    if (trimmedValue === "" || !trimmedValue.includes("://")) {
      setRuleModal((currentModal) =>
        currentModal === null
          ? currentModal
          : {
            ...currentModal,
            draft: {
              ...currentModal.draft,
              importedOutbound: null,
            },
          },
      );
      return;
    }

    try {
      const parsedProxy = await backend.parseOutboundUrl(trimmedValue);
      setRuleModal((currentModal) => {
        if (currentModal === null || currentModal.draft.outboundProxyUrl !== value) {
          return currentModal;
        }

        const shouldUseDisplayName = currentModal.draft.remark.trim() === "" && parsedProxy.displayName !== null;

        return {
          ...currentModal,
          draft: applyOutboundToDraft(
            {
              ...currentModal.draft,
              remark: shouldUseDisplayName ? parsedProxy.displayName ?? currentModal.draft.remark : currentModal.draft.remark,
            },
            parsedProxy.outbound,
          ),
        };
      });

      if (parsedProxy.warnings.length > 0) {
        setRuleFormError(`代理链接已导入，但有提示：${parsedProxy.warnings.join("；")}`);
      }
    } catch (error) {
      setRuleFormError(`代理链接解析失败：${getErrorMessage(error)}`);
    }
  }

  async function handleRuleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (ruleModal === null || isBusy) {
      return;
    }

    setRuleFormError("");
    setAppError("");

    const draft = { ...ruleModal.draft };

    const trimmedRemark = draft.remark.trim();
    const trimmedListen = draft.inboundListen.trim();
    const trimmedHost = draft.outboundHost.trim();
    const trimmedVlessId = draft.vlessId.trim();
    const trimmedVlessEncryption = draft.vlessEncryption.trim();
    const trimmedShadowsocksMethod = draft.shadowsocksMethod.trim();
    const inboundPort = ruleModal.mode === "create" ? parseOptionalPort(draft.inboundPort) : parsePort(draft.inboundPort);
    const outboundPort = parsePort(draft.outboundPort);
    const vlessLevel = parseOptionalNonNegativeInteger(draft.vlessLevel);
    const trojanLevel = parseOptionalNonNegativeInteger(draft.trojanLevel);

    if (trimmedRemark === "" || trimmedListen === "" || trimmedHost === "") {
      setRuleFormError("请填写备注、监听地址和上游主机。");
      return;
    }

    if (inboundPort === null && draft.inboundPort.trim() !== "") {
      setRuleFormError("入口端口必须是 1 到 65535 之间的整数，或在新建规则时留空自动选择。");
      return;
    }

    if (ruleModal.mode === "edit" && inboundPort === null) {
      setRuleFormError("编辑已有规则时必须填写入口端口。");
      return;
    }

    if (outboundPort === null) {
      setRuleFormError("上游端口必须是 1 到 65535 之间的整数。");
      return;
    }

    if (Number.isNaN(vlessLevel)) {
      setRuleFormError("VLESS level 必须为空或非负整数。");
      return;
    }

    if (Number.isNaN(trojanLevel)) {
      setRuleFormError("Trojan level 必须为空或非负整数。");
      return;
    }

    if (hasPartialAuth(draft.inboundUsername, draft.inboundPassword) || (draft.outboundProtocol === "socks" && hasPartialAuth(draft.outboundUsername, draft.outboundPassword))) {
      setRuleFormError("启用用户名密码认证时，用户名和密码都必须填写。");
      return;
    }

    if (draft.outboundProtocol === "vless") {
      if (trimmedVlessId === "" || trimmedVlessEncryption === "") {
        setRuleFormError("VLESS 必须填写 UUID / ID 和加密字段，普通 VLESS 使用 none。");
        return;
      }

      if (draft.vlessSecurity === "reality" && draft.vlessRealityPublicKey.trim() === "") {
        setRuleFormError("REALITY 安全层必须填写 Public Key。");
        return;
      }
    }

    if (draft.outboundProtocol === "shadowsocks") {
      if (trimmedShadowsocksMethod === "" || draft.shadowsocksPassword === "") {
        setRuleFormError("Shadowsocks 必须填写加密方法和密码。");
        return;
      }

      if (["none", "plain"].includes(trimmedShadowsocksMethod.toLowerCase())) {
        setRuleFormError("Shadowsocks 不支持 none/plain 这类明文方法。");
        return;
      }
    }

    if (draft.outboundProtocol === "trojan") {
      if (draft.trojanPassword === "") {
        setRuleFormError("Trojan 必须填写密码。");
        return;
      }

      if (draft.trojanSecurity === "reality" && draft.trojanRealityPublicKey.trim() === "") {
        setRuleFormError("REALITY 安全层必须填写 Public Key。");
        return;
      }
    }

    try {
      setBusyAction("rule");

      if (ruleModal.mode === "edit" && ruleModal.editingRuleId !== null) {
        const updatedRule = buildRuleFromDraft(ruleModal.editingRuleId, draft);

        if (updatedRule === null) {
          setRuleFormError("端口必须是 1 到 65535 之间的整数。");
          return;
        }

        const savedState = await backend.updateRule(updatedRule);
        await saveAndApplyState(savedState);
        closeRuleModal();
        return;
      }

      const outbound = buildOutboundFromDraft(draft);

      if (outbound === null) {
        setRuleFormError("上游端口必须是 1 到 65535 之间的整数。");
        return;
      }

      const savedState = await backend.addRule({
        remark: trimmedRemark,
        inboundProtocol: draft.inboundProtocol,
        inboundListen: trimmedListen,
        inboundPort,
        inboundAuth: buildAuthConfig(draft.inboundUsername, draft.inboundPassword),
        outbound,
        enabled: draft.enabled,
      });

      await saveAndApplyState(savedState);
      closeRuleModal();
    } catch (error) {
      setRuleFormError(`保存规则失败：${getErrorMessage(error)}`);
    } finally {
      setBusyAction("");
    }
  }

  function handleDelete(rule: ProxyRule) {
    setDeleteConfirmation({ mode: "single", ruleId: rule.id, remark: rule.remark });
  }

  function deleteSelectedRules() {
    const selectedExistingRuleIds = rules.filter((rule) => selectedRuleIds.includes(rule.id)).map((rule) => rule.id);

    if (selectedExistingRuleIds.length === 0) {
      return;
    }

    setDeleteConfirmation({ mode: "bulk", ruleIds: selectedExistingRuleIds, count: selectedExistingRuleIds.length });
  }

  function closeDeleteConfirmation() {
    setDeleteConfirmation(null);
  }

  async function confirmDeleteRules() {
    if (deleteConfirmation === null || isBusy) {
      return;
    }

    const targetRuleIds = deleteConfirmation.mode === "single" ? [deleteConfirmation.ruleId] : deleteConfirmation.ruleIds;
    setBusyAction("delete");
    setAppError("");

    try {
      const nextState: AppState = {
        ...appState,
        rules: appState.rules.filter((rule) => !targetRuleIds.includes(rule.id)),
      };

      await saveAndApplyState(nextState);
      setSelectedRuleIds((currentIds) => currentIds.filter((currentId) => !targetRuleIds.includes(currentId)));
      setDeleteConfirmation(null);
    } catch (error) {
      setAppError(`删除规则失败：${getErrorMessage(error)}`);
    } finally {
      setBusyAction("");
    }
  }

  return (
    <main className="app-shell">
      {toastNotification !== null ? (
        <div className="toast-layer" aria-live={toastNotification.tone === "error" ? "assertive" : "polite"} aria-atomic="true">
          <div className={`toast-card is-${toastNotification.tone}`} role={toastNotification.tone === "error" ? "alert" : "status"}>
            <span className="toast-mark" aria-hidden="true">
              <Icon name={toastNotification.tone === "success" ? "check" : toastNotification.tone === "warning" ? "scan" : "close"} />
            </span>
            <p>{toastNotification.message}</p>
            <button className="toast-close" type="button" aria-label="关闭通知" onClick={clearToast}>
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
        versionInfo={xrayVersion}
        theme={theme}
        onChangeTheme={handleThemeChange}
      />

      <section className="metrics-grid" aria-label="规则概览">
        <div className="metric-card">
          <span>{rules.length}</span>
          <p>规则总数</p>
        </div>
        <div className="metric-card">
          <span>{activeRuleCount}</span>
          <p>启用入口</p>
        </div>
        <div className="metric-card">
          <span>{selectedCount}</span>
          <p>已选择</p>
        </div>
        <div className="metric-card wide">
          <span>{lastSavedAt}</span>
          <p>上次保存配置</p>
        </div>
      </section>

      <section className="rules-panel" aria-labelledby="rules-title">
        <div className="toolbar">
          <div className="toolbar-title">
            <p className="eyebrow">Rules</p>
            <h2 id="rules-title">代理规则</h2>
          </div>

          <div className="search-bar">
            <Icon name="search" />
            <input
              type="text"
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.currentTarget.value)}
              placeholder="搜索名称或国家代码 (如: us, sg)..."
              className="search-input"
              disabled={rules.length === 0}
            />
            {searchQuery !== "" ? (
              <button
                className="clear-search-btn"
                type="button"
                aria-label="清除搜索"
                onClick={() => setSearchQuery("")}
              >
                <Icon name="close" />
              </button>
            ) : null}
          </div>

          <div className="toolbar-actions">
            <button className="ghost-button" type="button" onClick={toggleSelectAll} disabled={filteredRules.length === 0 || isBusy}>
              <Icon name="check" />
              {/* <span>{allSelected ? "取消全选" : "全选"}</span> */}
            </button>
            <button
              className="ghost-button"
              type="button"
              onClick={() => void toggleSelectedRulesEnabled()}
              disabled={selectedCount === 0 || isBusy}
            >
              <Icon name={selectedToggleIcon} />
              {/* <span>{selectedToggleLabel}</span> */}
            </button>
            <button className="ghost-button" type="button" onClick={openCreateRuleModal} disabled={isBusy} title="新建规则">
              <Icon name="plus" />
              {/* <span>新建规则</span> */}
            </button>
            <button className="ghost-button" type="button" onClick={openBatchAddModal} disabled={isBusy} title="批量添加规则">
              <Icon name="layers" />
              {/* <span>批量添加</span> */}
            </button>
            <button
              className="ghost-button"
              type="button"
              onClick={() => void checkSelectedRulesIp()}
              disabled={selectedCount === 0 || isBusy}
              title="批量检测出口 IP"
            >
              <Icon name="scan" />
              {/* <span>批量检测</span> */}
            </button>
            <button className="danger-button" type="button" onClick={deleteSelectedRules} disabled={selectedCount === 0 || isBusy}>
              <Icon name="delete" />
              {/* <span>删除所选</span> */}
            </button>
          </div>
        </div>

        {paginatedRules.length > 0 ? (
          <div className="rule-list">
            {paginatedRules.map((rule) => {
              const inboundAddress = formatLocalInboundAddress(rule.inbound.listen, rule.inbound.port);
              const outboundAddress = getOutboundAddress(rule.outbound);
              const outboundWarnings = getOutboundImportWarnings(rule.outbound);
              const inboundCopyKey = `${rule.id}-inbound`;
              const inboundProxyUrl = buildInboundProxyUrl(rule);
              const ipCheck = rule.ipCheck;
              const isCheckingIp = busyAction === `ip-${rule.id}` || checkingRuleIds.includes(rule.id);
              const speeds = trafficSpeeds[rule.id];
              const totalSpeed = (speeds?.uplinkSpeed ?? 0) + (speeds?.downlinkSpeed ?? 0);

              return (
                <article className={`rule-card ${isRuleSelected(rule.id) ? "is-selected" : ""}`} key={rule.id}>
                  <label className="select-box" aria-label={`选择 ${rule.remark}`}>
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
                          <span
                            className={`status-dot ${
                              !runtimeStatus.running || !rule.enabled
                                ? "is-inactive"
                                : totalSpeed > 0
                                ? "is-active"
                                : "is-idle"
                            }`}
                            title={
                              !runtimeStatus.running
                                ? "未运行 (核心已停止)"
                                : !rule.enabled
                                ? "已停用"
                                : totalSpeed > 0
                                ? "运行中"
                                : "已启用 (空闲)"
                            }
                            aria-label={
                              !runtimeStatus.running
                                ? "未运行 (核心已停止)"
                                : !rule.enabled
                                ? "已停用"
                                : totalSpeed > 0
                                ? "运行中"
                                : "已启用 (空闲)"
                            }
                          />
                          <h3>{rule.remark}</h3>
                        </div>
                        {rule.enabled && (
                          <div className="traffic-stats-vertical" title="实时上传/下载速度">
                            <div className="traffic-speed-item uplink">
                              <span className="arrow">↑</span>
                              <span className="value">{formatSpeed(speeds?.uplinkSpeed ?? 0)}</span>
                            </div>
                            <div className="traffic-speed-item downlink">
                              <span className="arrow">↓</span>
                              <span className="value">{formatSpeed(speeds?.downlinkSpeed ?? 0)}</span>
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="endpoint-line local">
                        <strong>{formatInboundProtocol(rule.inbound.protocol)}</strong>
                        <span>{inboundAddress}</span>
                        <button
                          className="copy-button compact-copy"
                          type="button"
                          aria-label={`复制 ${rule.remark} 本地入口代理链接`}
                          title={copiedKey === inboundCopyKey ? "已复制" : "复制链接"}
                          onClick={() => void copyToClipboard(inboundCopyKey, inboundProxyUrl)}
                          disabled={isBusy}
                        >
                          <Icon name="copy" />
                        </button>
                      </div>

                      <div className="endpoint-line outbound">
                        <strong>{formatOutboundProtocol(rule.outbound.protocol)}</strong>
                        <span>{outboundAddress}</span>
                      </div>

                      {outboundWarnings.length > 0 ? <p className="modal-description">导入提示：{outboundWarnings.join("；")}</p> : null}

                      <div className="ip-check-panel">
                        <div className="ip-check-result">
                          <span className="ip-flag">{formatCountryFlag(ipCheck?.country ?? null)}</span>
                          <span className="ip-address">{ipCheck?.ip ?? "未检查"}</span>
                        </div>
                        <button
                          className="copy-button compact-copy ip-check-button"
                          type="button"
                          onClick={() => void checkRuleIp(rule)}
                          disabled={isBusy || !rule.enabled}
                        >
                          {isCheckingIp ? "检查中" : "IP 检查"}
                        </button>
                      </div>

                      <div className="rule-actions" aria-label={`${rule.remark} 操作`}>
                        <button
                          className="small-icon-button"
                          type="button"
                          aria-label={`${rule.remark} 流量统计详情`}
                          title="流量统计详情"
                          onClick={() => openStatsDetailsModal(rule)}
                          disabled={isBusy}
                        >
                          <Icon name="info" />
                        </button>
                        <button
                          className="small-icon-button"
                          type="button"
                          aria-label={`复制 ${rule.remark}`}
                          title="复制"
                          onClick={() => void handleCopy(rule)}
                          disabled={isBusy}
                        >
                          <Icon name="copy" />
                        </button>
                        <button
                          className="small-icon-button"
                          type="button"
                          aria-label={`编辑 ${rule.remark}`}
                          title="编辑"
                          onClick={() => openEditRuleModal(rule)}
                          disabled={isBusy}
                        >
                          <Icon name="edit" />
                        </button>
                        <button
                          className="small-icon-button danger"
                          type="button"
                          aria-label={`删除 ${rule.remark}`}
                          title="删除"
                          onClick={() => handleDelete(rule)}
                          disabled={isBusy}
                        >
                          <Icon name="delete" />
                        </button>
                      </div>
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        ) : null}

        {rules.length === 0 ? (
          <div className="empty-state">
            <Icon name="scan" />
            <h3>暂无规则</h3>
            <p>点击“新建规则”添加一条代理入口，保存后会写入后端状态。</p>
          </div>
        ) : null}

        {rules.length > 0 && filteredRules.length === 0 ? (
          <div className="empty-state">
            <Icon name="search" />
            <h3>没有找到匹配的规则</h3>
            <p>尝试更换搜索关键词，或者一键清除搜索条件。</p>
            <button
              className="ghost-button"
              type="button"
              style={{ marginTop: "var(--space-3)" }}
              onClick={() => setSearchQuery("")}
            >
              清除搜索
            </button>
          </div>
        ) : null}

        {filteredRules.length > 0 && totalPages > 1 ? (
          <div className="pagination-bar">
            <div className="pagination-info">
              显示第 {(currentPage - 1) * itemsPerPage + 1} - {Math.min(currentPage * itemsPerPage, filteredRules.length)} 条，共 {filteredRules.length} 条
            </div>
            <div className="pagination-actions">
              <button
                className="ghost-button pagination-btn"
                type="button"
                onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
                disabled={currentPage === 1}
              >
                <span>上一页</span>
              </button>

              <div className="pagination-pages">
                {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => {
                  const isCurrent = page === currentPage;
                  return (
                    <button
                      key={page}
                      className={isCurrent ? "primary-button pagination-page-btn" : "ghost-button pagination-page-btn"}
                      type="button"
                      onClick={() => setCurrentPage(page)}
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

      {ruleModal !== null ? (
        <div className="modal-layer" role="presentation">
          <section
            className="rule-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="rule-modal-title"
            aria-describedby="rule-modal-description"
          >
            <form onSubmit={(event) => void handleRuleSubmit(event)}>
              <div className="modal-header">
                <div>
                  <p className="eyebrow">Rule Editor</p>
                  <h2 id="rule-modal-title">{ruleModal.mode === "create" ? "新建代理规则" : "编辑代理规则"}</h2>
                  <p id="rule-modal-description" className="modal-description">
                    在第二层面板中配置本地入口与上游出口，提交后会保存到后端状态并同步运行中的核心。
                  </p>
                </div>
                <button className="small-icon-button" type="button" aria-label="关闭规则编辑器" onClick={closeRuleModal} disabled={isBusy}>
                  <Icon name="close" />
                </button>
              </div>

              <div className="modal-body">
                <section className="form-section" aria-labelledby="basic-fields-title">
                  <div className="section-heading">
                    <h3 id="basic-fields-title">规则信息</h3>
                    <span>01</span>
                  </div>
                  <div className="form-grid">
                    <label className="field wide-field">
                      <span>备注</span>
                      <input
                        type="text"
                        value={ruleModal.draft.remark}
                        onChange={(event) => updateRuleDraft("remark", event.currentTarget.value)}
                        placeholder="例如：指纹浏览器 A / 市场调研"
                        required
                        disabled={isBusy}
                      />
                    </label>
                    <label className="toggle-field">
                      <input
                        type="checkbox"
                        checked={ruleModal.draft.enabled}
                        onChange={(event) => updateRuleDraft("enabled", event.currentTarget.checked)}
                        disabled={isBusy}
                      />
                      <span>启用规则</span>
                    </label>
                  </div>
                </section>

                <section className="form-section" aria-labelledby="inbound-fields-title">
                  <div className="section-heading">
                    <h3 id="inbound-fields-title">本地入口</h3>
                    <span>02</span>
                  </div>
                  <div className="form-grid">
                    <label className="field">
                      <span>入口协议</span>
                      <select
                        value={ruleModal.draft.inboundProtocol}
                        onChange={(event) => {
                          if (isInboundProtocol(event.currentTarget.value)) {
                            updateRuleDraft("inboundProtocol", event.currentTarget.value);
                          }
                        }}
                        disabled={isBusy}
                      >
                        {inboundProtocolOptions.map((protocol) => (
                          <option value={protocol} key={protocol}>
                            {formatInboundProtocol(protocol)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="field">
                      <span>监听地址</span>
                      <input
                        type="text"
                        value={ruleModal.draft.inboundListen}
                        onChange={(event) => updateRuleDraft("inboundListen", event.currentTarget.value)}
                        placeholder="127.0.0.1"
                        required
                        disabled={isBusy}
                      />
                    </label>
                    <label className="field">
                      <span>入口端口</span>
                      <input
                        type="number"
                        min="1"
                        max="65535"
                        value={ruleModal.draft.inboundPort}
                        onChange={(event) => updateRuleDraft("inboundPort", event.currentTarget.value)}
                        placeholder={ruleModal.mode === "create" ? "留空自动选择" : "50000"}
                        required={ruleModal.mode === "edit"}
                        disabled={isBusy}
                      />
                    </label>
                    <div className="auth-disclosure wide-field">
                      <button className="ghost-button" type="button" onClick={toggleInboundAuthFields} disabled={isBusy}>
                        {ruleModal.inboundAuthExpanded ? "收起入口认证" : "添加入口认证"}
                      </button>
                      <span>默认无认证，仅在浏览器入口需要账号密码时展开。</span>
                    </div>
                    {ruleModal.inboundAuthExpanded ? (
                      <>
                        <label className="field">
                          <span>入口用户名</span>
                          <input
                            type="text"
                            value={ruleModal.draft.inboundUsername}
                            onChange={(event) => updateRuleDraft("inboundUsername", event.currentTarget.value)}
                            placeholder="留空为无认证"
                            disabled={isBusy}
                          />
                        </label>
                        <label className="field">
                          <span>入口密码</span>
                          <input
                            type="password"
                            value={ruleModal.draft.inboundPassword}
                            onChange={(event) => updateRuleDraft("inboundPassword", event.currentTarget.value)}
                            placeholder="留空为无认证"
                            disabled={isBusy}
                          />
                        </label>
                      </>
                    ) : null}
                  </div>
                </section>

                <section className="form-section" aria-labelledby="outbound-fields-title">
                  <div className="section-heading">
                    <h3 id="outbound-fields-title">上游出口</h3>
                    <div className="section-heading-actions">
                      <button
                        className="copy-button compact-copy icon-only-copy"
                        type="button"
                        aria-label="复制上游出口代理链接"
                        title={copiedKey === "outbound-draft" && outboundDraftCopyState !== null && !outboundDraftCopyState.disabled ? "已复制" : outboundDraftCopyState?.title ?? "复制上游出口代理链接"}
                        onClick={() => {
                          if (outboundDraftCopyState !== null && !outboundDraftCopyState.disabled) {
                            void copyToClipboard("outbound-draft", outboundDraftCopyState.url);
                          }
                        }}
                        disabled={isBusy || outboundDraftCopyState === null || outboundDraftCopyState.disabled}
                      >
                        <Icon name="copy" />
                      </button>
                      <span>03</span>
                    </div>
                  </div>
                  <div className="form-grid">
                    <label className="field wide-field">
                      <span>代理链接解析</span>
                      <input
                        type="text"
                        value={ruleModal.draft.outboundProxyUrl}
                        onChange={(event) => void handleOutboundProxyUrlChange(event.currentTarget.value)}
                        placeholder="socks5://... / vless://... / ss://..."
                        disabled={isBusy}
                      />
                    </label>
                    <label className="field">
                      <span>出口协议</span>
                      <select
                        value={ruleModal.draft.outboundProtocol}
                        onChange={(event) => {
                          if (isOutboundProtocol(event.currentTarget.value)) {
                            updateRuleDraft("outboundProtocol", event.currentTarget.value);
                          }
                        }}
                        disabled={isBusy}
                      >
                        {outboundProtocolOptions.map((protocol) => (
                          <option value={protocol} key={protocol}>
                            {formatOutboundProtocol(protocol)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="field wide-field">
                      <span>{ruleModal.draft.outboundProtocol === "socks" ? "上游主机" : "服务器地址"}</span>
                      <input
                        type="text"
                        value={ruleModal.draft.outboundHost}
                        onChange={(event) => updateRuleDraft("outboundHost", event.currentTarget.value)}
                        placeholder="upstream.proxy.local"
                        required
                        disabled={isBusy}
                      />
                    </label>
                    <label className="field">
                      <span>上游端口</span>
                      <input
                        type="number"
                        min="1"
                        max="65535"
                        value={ruleModal.draft.outboundPort}
                        onChange={(event) => updateRuleDraft("outboundPort", event.currentTarget.value)}
                        required
                        disabled={isBusy}
                      />
                    </label>
                    {ruleModal.draft.outboundProtocol === "socks" ? (
                      <>
                        <label className="field">
                          <span>上游用户名</span>
                          <input
                            type="text"
                            value={ruleModal.draft.outboundUsername}
                            onChange={(event) => updateRuleDraft("outboundUsername", event.currentTarget.value)}
                            placeholder="留空为无认证"
                            disabled={isBusy}
                          />
                        </label>
                        <label className="field wide-field">
                          <span>上游密码</span>
                          <input
                            type="password"
                            value={ruleModal.draft.outboundPassword}
                            onChange={(event) => updateRuleDraft("outboundPassword", event.currentTarget.value)}
                            placeholder="留空为无认证"
                            disabled={isBusy}
                          />
                        </label>
                      </>
                    ) : null}
                    {ruleModal.draft.outboundProtocol === "vless" ? (
                      <>
                        <label className="field wide-field">
                          <span>UUID / ID</span>
                          <input type="text" value={ruleModal.draft.vlessId} onChange={(event) => updateRuleDraft("vlessId", event.currentTarget.value)} placeholder="5783a3e7-e373-51cd-8642-c83782b807c5" required disabled={isBusy} />
                        </label>
                        <label className="field">
                          <span>安全层</span>
                          <select value={ruleModal.draft.vlessSecurity} onChange={(event) => updateRuleDraft("vlessSecurity", event.currentTarget.value as RuleFormState["vlessSecurity"])} disabled={isBusy}>
                            <option value="none">无</option>
                            <option value="tls">TLS</option>
                            <option value="reality">REALITY</option>
                          </select>
                        </label>
                        <label className="field">
                          <span>Encryption</span>
                          <input type="text" value={ruleModal.draft.vlessEncryption} onChange={(event) => updateRuleDraft("vlessEncryption", event.currentTarget.value)} placeholder="none" required disabled={isBusy} />
                        </label>
                        <label className="field">
                          <span>Flow</span>
                          <select value={ruleModal.draft.vlessFlow} onChange={(event) => updateRuleDraft("vlessFlow", event.currentTarget.value as RuleFormState["vlessFlow"])} disabled={isBusy}>
                            <option value="">无</option>
                            {vlessFlowOptions.map((flow) => (
                              <option value={flow} key={flow}>{flow}</option>
                            ))}
                          </select>
                        </label>
                        <label className="field">
                          <span>Level</span>
                          <input type="number" min="0" step="1" value={ruleModal.draft.vlessLevel} onChange={(event) => updateRuleDraft("vlessLevel", event.currentTarget.value)} placeholder="默认 0" disabled={isBusy} />
                        </label>
                        <label className="field">
                          <span>传输协议</span>
                          <select value={ruleModal.draft.vlessTransportKind} onChange={(event) => updateRuleDraft("vlessTransportKind", event.currentTarget.value as "tcp" | "ws")} disabled={isBusy}>
                            <option value="tcp">TCP</option>
                            <option value="ws">WebSocket (ws)</option>
                          </select>
                        </label>
                        {ruleModal.draft.vlessTransportKind === "ws" ? (
                          <>
                            <label className="field wide-field">
                              <span>WebSocket 路径 (Path)</span>
                              <input type="text" value={ruleModal.draft.vlessTransportPath} onChange={(event) => updateRuleDraft("vlessTransportPath", event.currentTarget.value)} placeholder="/" disabled={isBusy} />
                            </label>
                            <label className="field wide-field">
                              <span>WebSocket 伪装域名 (Host)</span>
                              <input type="text" value={ruleModal.draft.vlessTransportHost} onChange={(event) => updateRuleDraft("vlessTransportHost", event.currentTarget.value)} placeholder="sni.example.com" disabled={isBusy} />
                            </label>
                          </>
                        ) : null}
                        {ruleModal.draft.vlessSecurity !== "none" ? (
                          <>
                            <label className="field wide-field">
                              <span>Server Name / SNI</span>
                              <input type="text" value={ruleModal.draft.vlessServerName} onChange={(event) => updateRuleDraft("vlessServerName", event.currentTarget.value)} placeholder="example.com" disabled={isBusy} />
                            </label>
                            <label className="field">
                              <span>Fingerprint</span>
                              <input type="text" value={ruleModal.draft.vlessFingerprint} onChange={(event) => updateRuleDraft("vlessFingerprint", event.currentTarget.value)} placeholder="chrome" disabled={isBusy} />
                            </label>
                            {ruleModal.draft.vlessSecurity === "tls" ? (
                              <label className="toggle-field">
                                <input type="checkbox" checked={ruleModal.draft.vlessAllowInsecure} onChange={(event) => updateRuleDraft("vlessAllowInsecure", event.currentTarget.checked)} disabled={isBusy} />
                                <span>允许不安全证书 (allowInsecure)</span>
                              </label>
                            ) : null}
                          </>
                        ) : null}
                        {ruleModal.draft.vlessSecurity === "reality" ? (
                          <>
                            <label className="field wide-field">
                              <span>Reality Public Key</span>
                              <input type="text" value={ruleModal.draft.vlessRealityPublicKey} onChange={(event) => updateRuleDraft("vlessRealityPublicKey", event.currentTarget.value)} required disabled={isBusy} />
                            </label>
                            <label className="field">
                              <span>Reality Short ID</span>
                              <input type="text" value={ruleModal.draft.vlessRealityShortId} onChange={(event) => updateRuleDraft("vlessRealityShortId", event.currentTarget.value)} disabled={isBusy} />
                            </label>
                            <label className="field wide-field">
                              <span>Reality Spider X</span>
                              <input type="text" value={ruleModal.draft.vlessRealitySpiderX} onChange={(event) => updateRuleDraft("vlessRealitySpiderX", event.currentTarget.value)} placeholder="/" disabled={isBusy} />
                            </label>
                          </>
                        ) : null}
                      </>
                    ) : null}
                    {ruleModal.draft.outboundProtocol === "shadowsocks" ? (
                      <>
                        <label className="field wide-field">
                          <span>加密方法</span>
                          <input list="shadowsocks-methods" type="text" value={ruleModal.draft.shadowsocksMethod} onChange={(event) => updateRuleDraft("shadowsocksMethod", event.currentTarget.value)} required disabled={isBusy} />
                          <datalist id="shadowsocks-methods">
                            {shadowsocksMethodOptions.map((method) => <option value={method} key={method} />)}
                          </datalist>
                        </label>
                        <label className="field wide-field">
                          <span>Shadowsocks 密码</span>
                          <input type="password" value={ruleModal.draft.shadowsocksPassword} onChange={(event) => updateRuleDraft("shadowsocksPassword", event.currentTarget.value)} required disabled={isBusy} />
                        </label>
                        <label className="toggle-field">
                          <input type="checkbox" checked={ruleModal.draft.shadowsocksUot} onChange={(event) => updateRuleDraft("shadowsocksUot", event.currentTarget.checked)} disabled={isBusy} />
                          <span>启用 UDP over TCP</span>
                        </label>
                        {ruleModal.draft.shadowsocksUot ? (
                          <label className="field">
                            <span>UoT Version</span>
                            <select value={ruleModal.draft.shadowsocksUotVersion} onChange={(event) => updateRuleDraft("shadowsocksUotVersion", event.currentTarget.value as RuleFormState["shadowsocksUotVersion"])} disabled={isBusy}>
                              <option value="">默认</option>
                              <option value="1">1</option>
                              <option value="2">2</option>
                            </select>
                          </label>
                        ) : null}
                      </>
                    ) : null}
                    {ruleModal.draft.outboundProtocol === "trojan" ? (
                      <>
                        <label className="field wide-field">
                          <span>Trojan 密码</span>
                          <input
                            type="password"
                            value={ruleModal.draft.trojanPassword}
                            onChange={(event) => updateRuleDraft("trojanPassword", event.currentTarget.value)}
                            placeholder="填写密码"
                            required
                            disabled={isBusy}
                          />
                        </label>
                        <label className="field">
                          <span>安全层</span>
                          <select
                            value={ruleModal.draft.trojanSecurity}
                            onChange={(event) => updateRuleDraft("trojanSecurity", event.currentTarget.value as RuleFormState["trojanSecurity"])}
                            disabled={isBusy}
                          >
                            <option value="none">无</option>
                            <option value="tls">TLS</option>
                            <option value="reality">REALITY</option>
                          </select>
                        </label>
                        <label className="field">
                          <span>Email (可选)</span>
                          <input
                            type="text"
                            value={ruleModal.draft.trojanEmail}
                            onChange={(event) => updateRuleDraft("trojanEmail", event.currentTarget.value)}
                            placeholder="user@example.com"
                            disabled={isBusy}
                          />
                        </label>
                        <label className="field">
                          <span>Level</span>
                          <input
                            type="number"
                            min="0"
                            step="1"
                            value={ruleModal.draft.trojanLevel}
                            onChange={(event) => updateRuleDraft("trojanLevel", event.currentTarget.value)}
                            placeholder="默认 0"
                            disabled={isBusy}
                          />
                        </label>
                        <label className="field">
                          <span>传输协议</span>
                          <select value={ruleModal.draft.trojanTransportKind} onChange={(event) => updateRuleDraft("trojanTransportKind", event.currentTarget.value as "tcp" | "ws")} disabled={isBusy}>
                            <option value="tcp">TCP</option>
                            <option value="ws">WebSocket (ws)</option>
                          </select>
                        </label>
                        {ruleModal.draft.trojanTransportKind === "ws" ? (
                          <>
                            <label className="field wide-field">
                              <span>WebSocket 路径 (Path)</span>
                              <input type="text" value={ruleModal.draft.trojanTransportPath} onChange={(event) => updateRuleDraft("trojanTransportPath", event.currentTarget.value)} placeholder="/" disabled={isBusy} />
                            </label>
                            <label className="field wide-field">
                              <span>WebSocket 伪装域名 (Host)</span>
                              <input type="text" value={ruleModal.draft.trojanTransportHost} onChange={(event) => updateRuleDraft("trojanTransportHost", event.currentTarget.value)} placeholder="sni.example.com" disabled={isBusy} />
                            </label>
                          </>
                        ) : null}
                        {ruleModal.draft.trojanSecurity !== "none" ? (
                          <>
                            <label className="field wide-field">
                              <span>Server Name / SNI</span>
                              <input
                                type="text"
                                value={ruleModal.draft.trojanServerName}
                                onChange={(event) => updateRuleDraft("trojanServerName", event.currentTarget.value)}
                                placeholder="example.com"
                                disabled={isBusy}
                              />
                            </label>
                            <label className="field">
                              <span>Fingerprint</span>
                              <input
                                type="text"
                                value={ruleModal.draft.trojanFingerprint}
                                onChange={(event) => updateRuleDraft("trojanFingerprint", event.currentTarget.value)}
                                placeholder="chrome"
                                disabled={isBusy}
                              />
                            </label>
                            {ruleModal.draft.trojanSecurity === "tls" ? (
                              <label className="toggle-field">
                                <input
                                  type="checkbox"
                                  checked={ruleModal.draft.trojanAllowInsecure}
                                  onChange={(event) => updateRuleDraft("trojanAllowInsecure", event.currentTarget.checked)}
                                  disabled={isBusy}
                                />
                                <span>允许不安全证书 (allowInsecure)</span>
                              </label>
                            ) : null}
                          </>
                        ) : null}
                        {ruleModal.draft.trojanSecurity === "reality" ? (
                          <>
                            <label className="field wide-field">
                              <span>Reality Public Key</span>
                              <input
                                type="text"
                                value={ruleModal.draft.trojanRealityPublicKey}
                                onChange={(event) => updateRuleDraft("trojanRealityPublicKey", event.currentTarget.value)}
                                placeholder="填写 Reality Public Key"
                                required
                                disabled={isBusy}
                              />
                            </label>
                            <label className="field">
                              <span>Reality Short ID</span>
                              <input
                                type="text"
                                value={ruleModal.draft.trojanRealityShortId}
                                onChange={(event) => updateRuleDraft("trojanRealityShortId", event.currentTarget.value)}
                                placeholder="可选"
                                disabled={isBusy}
                              />
                            </label>
                            <label className="field wide-field">
                              <span>Reality Spider X</span>
                              <input
                                type="text"
                                value={ruleModal.draft.trojanRealitySpiderX}
                                onChange={(event) => updateRuleDraft("trojanRealitySpiderX", event.currentTarget.value)}
                                placeholder="/"
                                disabled={isBusy}
                              />
                            </label>
                          </>
                        ) : null}
                      </>
                    ) : null}
                  </div>
                </section>
              </div>

              {ruleFormError !== "" ? (
                <p className="form-error" role="alert">
                  {ruleFormError}
                </p>
              ) : null}

              <div className="modal-footer">
                <button className="ghost-button" type="button" onClick={closeRuleModal} disabled={isBusy}>
                  取消
                </button>
                <button className="primary-button" type="submit" disabled={isBusy}>
                  {ruleModal.mode === "create" ? "创建规则" : "保存修改"}
                </button>
              </div>
            </form>
          </section>
        </div>
      ) : null}

      {batchAddOpen ? (
        <div className="modal-layer" role="presentation">
          <section className="rule-modal" role="dialog" aria-modal="true" aria-labelledby="batch-modal-title">
            <form onSubmit={(event) => void handleBatchAddSubmit(event)}>
              <div className="modal-header">
                <div>
                  <p className="eyebrow">Batch Importer</p>
                  <h2 id="batch-modal-title">批量添加代理规则</h2>
                  <p className="modal-description">一行输入一个出口代理链接。系统将自动提取名称，并连贯顺序分配本地空闲端口。</p>
                </div>
                <button className="small-icon-button" type="button" aria-label="关闭批量导入器" onClick={closeBatchAddModal} disabled={isBusy}>
                  <Icon name="close" />
                </button>
              </div>
              <div className="modal-body">
                <section className="form-section">
                  <div className="form-grid">
                    <label className="field">
                      <span>入口协议</span>
                      <select
                        value={batchAddInboundProtocol}
                        onChange={(event) => {
                          if (isInboundProtocol(event.currentTarget.value)) {
                            setBatchAddInboundProtocol(event.currentTarget.value);
                          }
                        }}
                        disabled={isBusy}
                      >
                        {inboundProtocolOptions.map((protocol) => (
                          <option value={protocol} key={protocol}>
                            {formatInboundProtocol(protocol)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="field">
                      <span>监听地址</span>
                      <input
                        type="text"
                        value={batchAddInboundListen}
                        onChange={(event) => setBatchAddInboundListen(event.currentTarget.value)}
                        required
                        disabled={isBusy}
                      />
                    </label>
                    <label className="field wide-field">
                      <span>批量出口链接 (每行一个)</span>
                      <textarea
                        value={batchAddText}
                        onChange={(event) => setBatchAddText(event.currentTarget.value)}
                        placeholder="socks5://host:port&#10;socks5://user:pass@host:port&#10;vless://...#可选备注"
                        required
                        disabled={isBusy}
                      />
                    </label>
                  </div>
                </section>
              </div>
              {batchAddError !== "" ? (
                <p className="form-error" role="alert" style={{ margin: "0 var(--space-5)" }}>
                  {batchAddError}
                </p>
              ) : null}
              <div className="modal-footer">
                <button className="ghost-button" type="button" onClick={closeBatchAddModal} disabled={isBusy}>
                  取消
                </button>
                <button className="primary-button" type="submit" disabled={isBusy}>
                  批量添加
                </button>
              </div>
            </form>
          </section>
        </div>
      ) : null}

      {deleteConfirmation !== null ? (
        <div className="modal-layer confirmation-layer" role="presentation">
          <section
            className="confirm-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-confirm-title"
            aria-describedby="delete-confirm-description"
          >
            <div className="confirm-header">
              <div>
                <p className="eyebrow">Delete confirmation</p>
                <h2 id="delete-confirm-title">确认删除规则</h2>
              </div>
              <button className="small-icon-button" type="button" aria-label="关闭删除确认" onClick={closeDeleteConfirmation} disabled={isBusy}>
                <Icon name="close" />
              </button>
            </div>

            <div className="confirm-body">
              {deleteConfirmation.mode === "single" ? (
                <p id="delete-confirm-description">
                  将删除规则 <strong>“{deleteConfirmation.remark}”</strong>。确认后会保存后端状态，并在核心运行中时同步应用。
                </p>
              ) : (
                <p id="delete-confirm-description">
                  将删除当前选中的 <strong>{deleteConfirmation.count}</strong> 条规则。确认后会同步清理选择状态并应用后端配置。
                </p>
              )}
            </div>

            <div className="confirm-footer">
              <button className="ghost-button" type="button" onClick={closeDeleteConfirmation} disabled={isBusy}>
                取消
              </button>
              <button className="danger-button" type="button" onClick={() => void confirmDeleteRules()} disabled={isBusy}>
                <Icon name="delete" />
                <span>确认删除</span>
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {statsDetailsRule !== null ? (
        <div className="modal-layer confirmation-layer" role="presentation">
          <section
            className="confirm-modal stats-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="stats-modal-title"
          >
            <div className="confirm-header" style={{ background: "linear-gradient(145deg, var(--color-field-strong), transparent)" }}>
              <div>
                <p className="eyebrow">Traffic Stats</p>
                <h2 id="stats-modal-title">流量统计详情</h2>
              </div>
              <button
                className="small-icon-button"
                type="button"
                aria-label="关闭统计详情"
                onClick={closeStatsDetailsModal}
              >
                <Icon name="close" />
              </button>
            </div>

            <div className="confirm-body" style={{ padding: "var(--space-6) var(--space-5)" }}>
              <p style={{ marginBottom: "var(--space-4)", color: "var(--color-ink)", fontWeight: 800, fontSize: "1.1rem" }}>
                规则：<strong>{statsDetailsRule.remark}</strong>
              </p>
              <div style={{ display: "grid", gap: "var(--space-3)" }}>
                <div className="stats-detail-row">
                  <span className="label">累计上传：</span>
                  <span className="value uplink">↑ {formatBytes(trafficStats[statsDetailsRule.id]?.uplink ?? 0)}</span>
                </div>
                <div className="stats-detail-row">
                  <span className="label">累计下载：</span>
                  <span className="value downlink">↓ {formatBytes(trafficStats[statsDetailsRule.id]?.downlink ?? 0)}</span>
                </div>
                <div className="stats-detail-divider"></div>
                <div className="stats-detail-row total">
                  <span className="label">累计总流量：</span>
                  <span className="value total">{formatBytes((trafficStats[statsDetailsRule.id]?.uplink ?? 0) + (trafficStats[statsDetailsRule.id]?.downlink ?? 0))}</span>
                </div>
              </div>
            </div>

            <div className="confirm-footer">
              <button
                className="primary-button"
                type="button"
                onClick={closeStatsDetailsModal}
              >
                <span>知道了</span>
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </main>
  );
}

export default App;
