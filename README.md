# mihomo-tools

`mihomo-tools` 是一个基于 **Tauri 2 + React 19 + Rust** 构建的本地轻量化代理管理器，旨在为 **Mihomo (Clash.Meta) 内核** 提供进程生命周期控制与多入站端口分流配置管理。

本项目非常适合搭配 **指纹浏览器（Fingerprint Browsers）** 使用。它允许您在本地创建多个不同的代理入口（Inbound Ports），并将每个入口流量独立路由到不同的上游代理节点（Outbounds），从而让每个浏览器配置文件使用完全独立的代理出站。

---

## 🌟 核心特性

- 🚀 **内核管理**：支持一键启动、停止、重启本地 Mihomo 内核进程，支持配置文件的无感热重载（Hot Reload）。
- 🔌 **多入站分流 (Multi-Inbound Routing)**：
  - 动态为每个规则分配独立的本地监听端口（支持 SOCKS5 / HTTP / Mixed 混合协议）。
  - 支持配置可选的入站账号密码认证，保障本地端口安全。
  - 为每个本地端口独立分配一个对应的上游代理节点，流量互不干扰。
- ✈️ **主流协议支持**：
  - 默认支持 **SOCKS5**、**Shadowsocks (SS)**。
  - 深度支持 **VLESS** (支持 Reality、TLS、TCP/WS 传输层协议)。
  - 深度支持 **Trojan** (支持 Reality、TLS、TCP/WS 传输层协议)。
  - 支持 **AnyTLS** 协议。
- 📋 **剪贴板一键导入**：支持一键从剪贴板粘贴并自动解析主流的代理格式链接（如 `ss://`, `vless://`, `trojan://`, `anytls://`），秒级完成配置。
- 🔍 **出口 GeoIP 检测**：提供一键检测功能，通过特定的本地入站端口请求 `ipinfo.io`，实时验证出口 IP 地址、国家/地区和速度。
- 📊 **实时流量监控**：实时轮询 Mihomo 控制接口，呈现每个入站端口的当前连接数、瞬时上传/下载速率以及累计上传/下载流量。
- 📦 **绿色免安装**：程序完全绿色便携。配置文件与 Mihomo 内核直接存放在程序运行目录下的 `./data/` 和 `./mihomo/` 文件夹中，解压即用。

---

## 🛠️ 项目架构

项目采用前后端解耦架构设计：
- **前端 (React 19 + TypeScript + Vite)**: 采用现代玻璃面（Glassmorphism）极客风设计，纯 Vanilla CSS 变量主题控制，微动效体验优秀。
- **后端 (Tauri 2 + Rust)**: 处理系统级底层操作，包括：
  - Mihomo 子进程生命周期监控。
  - 基于 Rust 安全生成符合 Mihomo 规范的 `generated-config.yaml` 配置文件。
  - 支持多配置的本地 JSON 数据库存储与版本平滑迁移。

---

## 🚀 快速开始

### 前提条件

- 安装 [Node.js](https://nodejs.org/) (推荐 v20+)
- 安装 [Rust 编译环境](https://www.rust-lang.org/tools/install)
- 包管理器推荐使用 `pnpm`

### 1. 克隆项目并安装依赖

```bash
git clone https://github.com/lengmoX/mihomo-tools.git
cd mihomo-tools
pnpm install
```

### 2. 下载 Mihomo 内核

在项目根目录下创建 `mihomo` 目录，将适用于您的系统的 `mihomo.exe` (Clash.Meta 核心编译版本) 放入该目录中。
> *注：您也可以使用内置的下载脚本或通过修改 scripts 的配置自动获取内核。*

### 3. 开发模式运行

```bash
pnpm tauri dev
```

### 4. 构建便携版可执行程序

```bash
pnpm tauri build --no-bundle
```
构建出的 `mihomo-tools.exe` 位于 `src-tauri/target/release/` 下。

---

## 📂 目录结构

```text
mihomo-tools/
├── data/                       # 运行时动态生成的本地配置文件夹
│   ├── app-state.json          # 保存的用户代理规则配置
│   └── generated-config.yaml   # 动态生成的 Mihomo YAML 配置文件
├── mihomo/                     # 本地 Mihomo 内核文件夹
│   └── mihomo.exe              # Mihomo 内核可执行二进制文件
├── src-tauri/                  # 后端代码 (Tauri + Rust)
│   ├── src/
│   │   ├── commands.rs         # Tauri IPC 命令通道
│   │   ├── config.rs           # Mihomo YAML 配置文件编译器
│   │   ├── models.rs           # 数据结构定义与版本迁移逻辑
│   │   ├── parser.rs           # 订阅链接与节点 URL 剪贴板解析器
│   │   ├── process.rs          # 核心进程管理控制
│   │   └── utils.rs            # 路径解析、端口可用性检测等辅助函数
│   └── Cargo.toml
└── src/                        # 前端代码 (React + TS)
    ├── api/backend.ts          # 后端 IPC 的 TS 类型定义与绑定
    ├── features/runtime/       # 监控组件与磁贴
    └── App.tsx                 # 主看板仪表盘与规则编辑器
```

---

## 📝 许可证

本项目基于 [MIT License](LICENSE) 开源。仅供学习与本地开发测试使用，请勿用于非法用途。

