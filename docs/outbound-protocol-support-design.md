# Outbound Protocol Support Design

This document designs support for importing and managing common VLESS and Shadowsocks outbound links in `xray-tools`.

The first implementation should optimize for common proxy-share links and a small manual editing surface. It should not expose arbitrary Xray JSON editing.

## Goals

- Add outbound protocol choices for `vless` and `shadowsocks` in addition to the existing `socks` outbound.
- Prefer importing `vless://...` and `ss://...` share links, then normalize them into typed app state.
- Keep each rule model protocol-aware so future outbound protocols can be added without rewriting persisted state again.
- Generate Xray JSON from typed state only; do not persist generated Xray fragments as source-of-truth.
- Keep the frontend form focused on required fields plus a small protocol-specific advanced section.
- Preserve existing SOCKS rules through a versioned state migration.

## Non-Goals

- Do not support full manual Xray outbound JSON editing in the first pass.
- Do not implement VLESS reverse proxy UI in the first pass.
- Do not expose every transport and security option immediately.
- Do not silently accept unknown security-sensitive link parameters.
- Do not store share links as the only persisted outbound representation.

## Current Project Constraints

The current backend model in `src-tauri/src/lib.rs` stores outbound config as a flat SOCKS-oriented shape:

```rust
pub struct OutboundConfig {
    pub protocol: OutboundProtocol,
    pub host: String,
    pub port: u16,
    pub auth: Option<AuthConfig>,
}

pub enum OutboundProtocol {
    Socks,
}
```

The frontend mirrors this in `src/api/backend.ts`:

```ts
export type OutboundProtocol = "socks";

export interface OutboundConfig {
  protocol: OutboundProtocol;
  host: string;
  port: number;
  auth: AuthConfig | null;
}
```

`src/App.tsx` also assumes a SOCKS-like outbound form: protocol, host, port, username, password, and `parseSocksOutboundUrl`.

This shape should not be stretched for VLESS or Shadowsocks. VLESS has UUID, encryption, flow, and stream settings. Shadowsocks has method, password, and optional UDP-over-TCP settings. These are not equivalent to SOCKS username/password authentication.

## Official Xray Config Notes

### VLESS Outbound

Official VLESS outbound config uses `protocol: "vless"` and protocol-specific `settings` fields like:

```json
{
  "protocol": "vless",
  "settings": {
    "address": "example.com",
    "port": 443,
    "id": "5783a3e7-e373-51cd-8642-c83782b807c5",
    "encryption": "none",
    "flow": "xtls-rprx-vision",
    "level": 0
  }
}
```

Important fields:

- `address`: server address.
- `port`: server port.
- `id`: VLESS user id. Usually a UUID.
- `encryption`: required by Xray. Use explicit `"none"` for ordinary VLESS without VLESS Encryption.
- `flow`: optional. Common values include empty/unset, `xtls-rprx-vision`, and `xtls-rprx-vision-udp443`.
- `level`: optional local policy level. Default can remain `0` or omitted unless policy support is added.

VLESS Encryption is no longer just `none`; official docs describe generated encryption strings and recommend using `xray vlessenc` for most users. In this app, treat non-`none` encryption as an advanced imported/manual string, not as a decomposed UI in the first pass.

### Shadowsocks Outbound

Official Shadowsocks outbound config uses `protocol: "shadowsocks"` with fields such as:

```json
{
  "protocol": "shadowsocks",
  "settings": {
    "address": "127.0.0.1",
    "port": 1234,
    "method": "2022-blake3-aes-128-gcm",
    "password": "Password",
    "uot": true,
    "UoTVersion": 2,
    "level": 0
  }
}
```

Important fields:

- `address`: server address.
- `port`: server port.
- `method`: encryption method.
- `password`: authentication password or pre-shared key.
- `uot`: optional UDP over TCP flag.
- `UoTVersion`: optional UoT version, currently `1` or `2`.
- `level`: optional local policy level.

Xray examples also show a `settings.servers` array shape for Shadowsocks. Before implementation, verify the installed/targeted Xray core accepts the official current shape. The design should keep the generator isolated so switching between flat settings and `servers` shape is localized if needed.

Recommended first-pass Shadowsocks methods:

- `2022-blake3-aes-128-gcm`
- `2022-blake3-aes-256-gcm`
- `2022-blake3-chacha20-poly1305`
- `aes-256-gcm`
- `aes-128-gcm`
- `chacha20-poly1305`
- `chacha20-ietf-poly1305`
- `xchacha20-poly1305`
- `xchacha20-ietf-poly1305`

Do not offer `none` in the normal UI because it sends traffic in plain text. If imported, reject it by default unless a future explicit unsafe-mode decision is made.

## Persisted State Model

Move to `schemaVersion: 2` and represent outbound config as a protocol-tagged union.

Recommended TypeScript shape:

```ts
export type OutboundProtocol = "socks" | "vless" | "shadowsocks";

export type OutboundConfig =
  | SocksOutboundConfig
  | VlessOutboundConfig
  | ShadowsocksOutboundConfig;

export interface SocksOutboundConfig {
  protocol: "socks";
  host: string;
  port: number;
  auth: AuthConfig | null;
}

export interface VlessOutboundConfig {
  protocol: "vless";
  address: string;
  port: number;
  id: string;
  encryption: string;
  flow: VlessFlow | null;
  transport: VlessTransportConfig;
  tls: VlessTlsConfig | null;
  reality: VlessRealityConfig | null;
  importSource: ImportSource | null;
}

export type VlessFlow = "xtls-rprx-vision" | "xtls-rprx-vision-udp443";

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

export interface ImportSource {
  rawUrl: string;
  importedAt: number;
  warnings: string[];
}
```

Recommended Rust shape:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum OutboundConfig {
    Socks(SocksOutboundConfig),
    Vless(VlessOutboundConfig),
    Shadowsocks(ShadowsocksOutboundConfig),
}
```

Use internally clear names like `address` for VLESS/Shadowsocks because that matches Xray docs. Keep `host` only for the existing SOCKS model unless a later migration standardizes all protocols.

### Migration

Implement a versioned loader that can deserialize both v1 and v2:

1. Read raw JSON from `data/app-state.json`.
2. Inspect `schemaVersion`.
3. If `1`, deserialize with the current v1 structs, map each rule's outbound into the new `OutboundConfig::Socks`, and return an in-memory v2 `AppState`.
4. If `2`, deserialize directly into the new structs.
5. Only write the migrated v2 file during an explicit save/apply operation, not during read-only load.

This avoids breaking existing users if the new code opens old portable data.

## Import Parsing Design

Replace `parse_socks_outbound_url` with a generic import command while keeping the old command as a compatibility wrapper if needed.

Recommended Tauri command:

```ts
parseOutboundUrl(input: string): Promise<ParseOutboundUrlResult>
```

Result shape:

```ts
export interface ParseOutboundUrlResult {
  outbound: OutboundConfig;
  displayName: string | null;
  warnings: string[];
}
```

Parser behavior:

- Trim input.
- Detect scheme: `socks`, `socks5`, `vless`, `ss`.
- Return protocol-specific typed config.
- Reject malformed required fields.
- Reject unknown critical security fields.
- Warn and ignore non-critical UI metadata, such as unsupported remarks or unknown benign query values.

### VLESS Link Import

Support common link shape:

```text
vless://uuid@host:port?type=tcp&security=tls&flow=xtls-rprx-vision&encryption=none&sni=example.com#remark
```

Map common fields:

- userinfo before `@` -> `id`.
- host -> `address`.
- port -> `port`.
- `encryption` -> `encryption`, default to `none` only if absent.
- `flow` -> `flow` if one of supported values.
- `type` -> `transport.kind`.
- `security=tls` -> `tls` config.
- `security=reality` -> `reality` config.
- `sni` -> TLS/REALITY server name.
- `pbk`, `sid`, `spx`, `fp` -> REALITY fields where applicable.
- fragment after `#` -> display name / rule remark candidate.

First-pass transport support should be intentionally narrow:

- Support `type=tcp` as the baseline.
- Support `security=tls` and `security=reality` because they are common with VLESS.
- For `type=ws`, `grpc`, `xhttp`, `httpupgrade`, or other transports, either reject with a clear message or import as unsupported with a blocking validation error. Do not generate guessed `streamSettings`.

Recommended VLESS advanced UI fields:

- Encryption string, default `none`.
- Flow select: none, `xtls-rprx-vision`, `xtls-rprx-vision-udp443`.
- Security select: none, TLS, REALITY.
- Server name/SNI.
- Fingerprint (`fp`) for TLS/REALITY, if imported.
- REALITY public key (`pbk`), short id (`sid`), spider path (`spx`) if security is REALITY.

Do not expose VLESS `reverse` in the first pass.

### Shadowsocks Link Import

Support common link shapes:

```text
ss://base64(method:password@host:port)#remark
ss://method:password@host:port#remark
ss://base64(method:password)@host:port#remark
```

Map fields:

- method -> `method`.
- password -> `password`.
- host -> `address`.
- port -> `port`.
- fragment after `#` -> display name / rule remark candidate.
- optional query `uot=1` / `uot=true` -> `uot`.
- optional query `uotVersion=1|2` or `UoTVersion=1|2` -> `uotVersion`.

Parsing notes:

- Handle URL-safe base64 and missing padding when practical.
- Percent-decode username/password sections after structural parsing.
- Reject missing method, password, host, or port.
- Reject `method=none` by default.
- Warn if query parameters are present but not supported.

Recommended Shadowsocks advanced UI fields:

- Method select, with custom method text input only if needed.
- Password.
- UoT enabled toggle.
- UoT version select shown only when UoT is enabled.

## Xray Config Generation

Keep one generator per outbound variant:

```rust
fn generate_outbound(rule: &ProxyRule, tag: &str) -> CommandResult<Value> {
    match &rule.outbound {
        OutboundConfig::Socks(config) => generate_socks_outbound(config, tag),
        OutboundConfig::Vless(config) => generate_vless_outbound(config, tag),
        OutboundConfig::Shadowsocks(config) => generate_shadowsocks_outbound(config, tag),
    }
}
```

### VLESS Generation

Baseline output:

```json
{
  "tag": "outbound-rule-id",
  "protocol": "vless",
  "settings": {
    "address": "example.com",
    "port": 443,
    "id": "uuid",
    "encryption": "none",
    "flow": "xtls-rprx-vision"
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "example.com"
    }
  }
}
```

Generation rules:

- Always include `encryption`; default imported/created value is `none`.
- Omit `flow` when no flow is selected.
- Emit `streamSettings` only when transport/security fields require it.
- Do not emit unknown query parameters.
- Do not emit `reverse` in first pass.

### Shadowsocks Generation

Prefer the official current shape first:

```json
{
  "tag": "outbound-rule-id",
  "protocol": "shadowsocks",
  "settings": {
    "address": "host",
    "port": 1234,
    "method": "2022-blake3-aes-128-gcm",
    "password": "password",
    "uot": true,
    "UoTVersion": 2
  }
}
```

Implementation must verify this shape against the target Xray core. If the core rejects it, switch only `generate_shadowsocks_outbound` to the `settings.servers` array shape used by Xray examples, without changing persisted app state.

## Backend Validation

Validation should happen before saving state and before generating config.

Shared validation:

- Rule id is non-empty and unique.
- Enabled inbound ports do not conflict.
- Outbound address/host is non-empty.
- Outbound port is `1..=65535`.

VLESS validation:

- `id` is non-empty. Prefer UUID validation for common links; allow custom strings under 30 bytes only if we intentionally support official non-UUID IDs.
- `encryption` is non-empty. Use `none` for normal VLESS.
- `flow`, if set, must be one of supported flow values.
- If REALITY security is selected, required imported fields such as public key must be present.
- Unsupported transport kind should block saving or config generation.

Shadowsocks validation:

- `method` is non-empty and in the supported list unless custom method support is explicitly enabled.
- `password` is non-empty.
- Reject `none` / `plain` methods in first pass.
- `UoTVersion`, if set, must be `1` or `2`.
- If UoT is disabled, omit `UoTVersion` from generated JSON.

## Frontend Design

Keep the rule editor's `上游出口` section, but make it protocol-aware.

Recommended layout:

1. `代理链接解析` input at the top. When the link is recognized, populate protocol-specific fields and show import warnings.
2. `出口协议` select: SOCKS5, VLESS, Shadowsocks.
3. Protocol-specific form body.
4. A collapsed `高级选项` panel for VLESS flow/encryption/security or Shadowsocks UoT.

SOCKS body:

- Host.
- Port.
- Optional username/password.

VLESS body:

- Address.
- Port.
- UUID / ID.
- Security summary.
- Advanced: encryption, flow, TLS/REALITY fields.

Shadowsocks body:

- Address.
- Port.
- Method.
- Password.
- Advanced: UoT, UoT version.

When parsing a link, use the fragment/remark only as a suggested rule remark if the current remark is empty. Do not overwrite a user-edited remark.

## API Changes

Add:

```ts
parseOutboundUrl(input: string): Promise<ParseOutboundUrlResult>
```

Keep during transition:

```ts
parseSocksOutboundUrl(input: string): Promise<OutboundConfig>
```

`parseSocksOutboundUrl` can call the generic parser and return only if the result is `protocol: "socks"`.

Update existing commands that accept `AppState`, `NewRuleRequest`, or `UpdateRuleRequest` to use the new union shape. No separate command is needed per protocol.

## Implementation Sequence

1. Add v1/v2 state structs and migration tests in Rust.
2. Convert backend `OutboundConfig` to a tagged enum.
3. Add validation per outbound protocol.
4. Add generic outbound URL parser with tests for SOCKS, VLESS, and Shadowsocks links.
5. Split Xray config generation into protocol-specific functions with snapshot-style unit tests.
6. Update TypeScript API types to tagged unions.
7. Refactor `RuleFormState` into protocol-specific draft state or a discriminated union.
8. Update the rule editor UI to render protocol-specific fields.
9. Replace frontend parse flow with `parseOutboundUrl` and warning display.
10. Run `cargo check`, `pnpm build`, and targeted parser/generator tests.

## Test Cases

Backend parser tests:

- `socks5://host:1080`
- `socks5://user:pass@host:1080`
- `vless://uuid@example.com:443?encryption=none&type=tcp&security=tls&sni=example.com#Example`
- `vless://uuid@example.com:443?encryption=none&type=tcp&security=reality&pbk=key&sid=short&fp=chrome#Reality`
- `vless://uuid@example.com:443?flow=xtls-rprx-vision&encryption=none`
- `ss://base64(method:password@host:port)#Example`
- `ss://method:password@host:port#Example`
- malformed/missing port links.
- unsupported VLESS transport links.
- Shadowsocks `none` method rejection.

Config generator tests:

- v1 SOCKS rule migrated then generated identically to current behavior.
- VLESS TCP+TLS generated with `streamSettings`.
- VLESS TCP+REALITY generated with required reality fields.
- VLESS without flow omits `flow`.
- Shadowsocks generated with required method/password/address/port.
- Shadowsocks with UoT disabled omits `UoTVersion`.

Frontend build checks:

- `pnpm build` should pass strict TypeScript checks.
- Existing create/edit flows should still work for SOCKS.
- Imported VLESS and Shadowsocks links should populate only their own protocol fields.

## Open Decisions Before Implementation

These should be confirmed or tested before coding the full implementation:

1. Target Xray core version: needed to confirm Shadowsocks flat `settings` versus `settings.servers` generator shape.
2. VLESS ID strictness: should the UI require UUID only, or allow official custom strings under 30 bytes?
3. First-pass VLESS transport support: this design recommends TCP + TLS/REALITY only. WebSocket/gRPC/XHTTP links should be rejected initially unless you want broader import support.
4. Unsafe Shadowsocks methods: this design rejects `none` / `plain` by default.
5. Whether imported raw links should be persisted in `importSource.rawUrl`. This helps diagnostics but stores credentials in the same state file that already stores passwords.

## Recommended First-Pass Product Behavior

- Accept common `vless://`, `ss://`, `socks://`, and `socks5://` imports.
- Show clear errors for unsupported transports or unsafe methods.
- Store normalized typed outbound state.
- Preserve one inbound, one outbound, and one routing rule per app rule.
- Keep advanced fields small and protocol-specific.
- Use schema migration so existing SOCKS rules continue to work.
