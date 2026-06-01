# mihomo-tools

<p align="center">
  <strong>一个基于 Tauri 2 + React 19 + Rust 构建的本地轻量化 Mihomo 代理管理器</strong>
</p>

<p align="center">
  <a href="#-核心特性">核心特性</a> •
  <a href="#-快速开始">快速开始</a> •
  <a href="#-使用教程">使用教程</a> •
  <a href="#-开发指南">开发指南</a> •
  <a href="#-打包发布">打包发布</a>
</p>

---

## 📖 简介

`mihomo-tools` 旨在为 **Mihomo (Clash.Meta) 内核** 提供一个现代化的本地 GUI 管理界面，支持进程生命周期控制与多入站端口分流配置管理。

**主要应用场景：** 搭配 **指纹浏览器（Fingerprint Browsers）** 使用。您可以在本地创建多个不同的代理入口端口（Inbounds），并将每个入口的流量独立路由到不同的上游代理节点（Outbounds），让每个浏览器配置文件使用完全独立的代理出口 IP。

---

## 🌟 核心特性

| 功能 | 说明 |
|------|------|
| 🚀 **内核管理** | 一键启动、停止、重启本地 Mihomo 内核进程，支持配置热重载 |
| 🔌 **多入站分流** | 每个规则独立本地监听端口（SOCKS5 / HTTP / Mixed），可选入站认证 |
| ✈️ **主流协议** | SOCKS5、Shadowsocks、VLESS、Trojan、AnyTLS、Hysteria2 |
| 📋 **一键导入** | 从剪贴板粘贴 `ss://`、`vless://`、`trojan://`、`anytls://`、`hy2://` 链接自动解析 |
| 📋 **YAML 导入** | 支持直接粘贴 Mihomo/Clash YAML 格式的节点配置 |
| 🔍 **GeoIP 检测** | 通过本地入站端口请求 `ipinfo.io`，实时验证出口 IP 与地区 |
| 📊 **实时流量** | 实时显示每个端口的连接数、上传/下载速率和累计流量 |
| 📦 **绿色免安装** | 解压即用，配置存放在程序目录下 `./data/` 和 `./mihomo/` |

---

## 🚀 快速开始

### 方式一：下载预编译版本（推荐）

1. 前往 [Releases](https://github.com/lengmoX/mihomo-tools/releases) 页面
2. 下载适合您系统的压缩包：

   | 平台 | 文件 |
   |------|------|
   | Windows x64 | `mihomo-tools-windows-x64-v*.zip` |
   | macOS Apple Silicon | `mihomo-tools-macos-arm64-v*.zip` |
   | macOS Intel | `mihomo-tools-macos-x64-v*.zip` |

3. 解压到任意目录
4. 运行程序：
   - **Windows**：双击 `mihomo-tools.exe`
   - **macOS**：终端中执行 `./mihomo-tools`

> **💡 提示：** 预编译版本已内置最新 Mihomo 内核，解压后即可直接使用，无需额外下载。

### 方式二：从源码构建

请参考下方 [开发指南](#-开发指南) 部分。

---

## 📘 使用教程

### 第一步：启动程序

解压后的目录结构如下：

```
mihomo-tools-portable/
├── mihomo-tools.exe          # 主程序 (Windows) 或 mihomo-tools (macOS)
├── mihomo/
│   └── mihomo.exe            # Mihomo 内核 (macOS 下为 mihomo)
└── data/                     # 配置数据目录（首次运行自动创建）
    ├── app-state.json        # 用户规则配置
    └── generated-config.yaml # 自动生成的 Mihomo 配置
```

启动主程序后，界面会自动检测 `mihomo/` 目录下的内核文件。

### 第二步：添加代理规则

每个"规则"代表一个 **本地端口 → 上游代理** 的映射关系。

#### 方法 A：剪贴板一键导入

1. 复制你的代理链接，支持以下格式：
   ```
   socks5://user:pass@host:port
   ss://method:password@host:port
   vless://uuid@host:port?security=reality&...
   trojan://password@host:port?security=tls&...
   anytls://password@host:port?sni=example.com
   hy2://password@host:port?sni=example.com
   ```
2. 在应用中点击 **「添加规则」** 按钮
3. 在编辑面板中点击 **「从剪贴板粘贴」** 按钮
4. 程序会自动解析链接并填充所有字段

#### 方法 B：粘贴 Mihomo YAML 配置

支持直接粘贴 Mihomo/Clash 格式的节点 YAML：
```yaml
- name: "我的节点"
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: my-password
```

#### 方法 C：手动配置

在编辑面板中手动填写：
- **入站配置**：选择协议类型（SOCKS5/HTTP/Mixed）、指定本地端口、设置认证（可选）
- **出站配置**：选择上游代理协议和对应的服务器信息

### 第三步：启动内核

1. 配置完所有规则后，点击界面上方的 **「启动」** 按钮
2. 状态指示灯变绿即表示 Mihomo 内核已运行
3. 修改规则后点击 **「重启」** 或使用热重载即可生效

### 第四步：在浏览器中使用

在指纹浏览器或其他需要代理的程序中，将代理设置指向对应规则的本地端口：

```
代理类型：SOCKS5 / HTTP（取决于入站配置）
代理地址：127.0.0.1
代理端口：<你在规则中配置的端口>
用户名/密码：<如果配置了入站认证则填写>
```

### 第五步：验证连接

点击规则卡片上的 **「IP 检测」** 按钮，程序会通过该端口请求 `ipinfo.io`，显示：
- 出口 IP 地址
- 所在国家/地区
- 请求耗时

---

## 🛠️ 开发指南

### 前提条件

| 工具 | 版本要求 | 安装链接 |
|------|---------|---------|
| Node.js | v20+ | [nodejs.org](https://nodejs.org/) |
| pnpm | v9+ | `npm install -g pnpm` |
| Rust | stable | [rustup.rs](https://rustup.rs/) |
| Tauri CLI | v2 | 已包含在 devDependencies 中 |

### 1. 克隆项目

```bash
git clone https://github.com/lengmoX/mihomo-tools.git
cd mihomo-tools
```

### 2. 安装依赖

```bash
pnpm install
```

### 3. 下载 Mihomo 内核

运行内置的下载脚本，会自动从 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 拉取最新的 Release 版本：

```bash
pnpm run download-mihomo
```

> 脚本会根据当前操作系统自动选择对应平台的内核二进制，下载到 `mihomo/` 目录。

### 4. 开发模式运行

```bash
pnpm tauri dev
```

这将同时启动 Vite 前端开发服务器和 Tauri 后端，支持前端热更新。

### 5. 本地构建

```bash
pnpm tauri build --no-bundle
```

构建产物位于 `src-tauri/target/release/mihomo-tools.exe`（Windows）或 `src-tauri/target/release/mihomo-tools`（macOS）。

---

## 📦 打包发布

### 自动打包（GitHub Actions）

项目已配置 GitHub Actions 自动打包流程。推送版本标签即可触发自动构建，产出 Windows x64、macOS arm64、macOS x64 三个平台的便携压缩包。

#### 发布步骤

**第一步：更新版本号**

编辑 `version.txt` 文件，写入新版本号（SemVer 格式）：

```
0.2.0
```

**第二步：运行发布脚本**

```bash
pnpm run release
```

此脚本会自动完成以下操作：
1. 读取 `version.txt` 中的版本号
2. 同步更新 `package.json` 和 `src-tauri/tauri.conf.json` 的版本字段
3. 提交版本变更 (`git commit`)
4. 创建 Git 标签 `v0.2.0`
5. 推送 commit 和 tag 到 GitHub
6. GitHub Actions 自动触发 → 并行构建 3 个平台 → 创建 Release 并上传压缩包

> **💡 测试发布（不实际执行）：**
> ```bash
> pnpm run release -- --dry-run
> ```
> 使用 `--dry-run` 标志可预览所有操作而不实际执行任何 git 命令。

#### 手动触发打包

也可以在 GitHub 仓库页面手动触发：

1. 进入仓库 → **Actions** → **Release Portable Package**
2. 点击 **Run workflow**
3. 可选填写 `version_override` 覆盖版本号
4. 点击 **Run workflow** 按钮

#### CI 打包流程详解

```
推送 v* 标签
    ↓
┌─────────────────────────────────────────────────┐
│  并行构建 3 个 Matrix Job                        │
│                                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌───────────┐│
│  │ Windows x64  │ │ macOS arm64  │ │ macOS x64 ││
│  │ (latest)     │ │ (latest)     │ │ (13)      ││
│  └──────┬───────┘ └──────┬───────┘ └─────┬─────┘│
│         │                │               │       │
│    ┌────┴────────────────┴───────────────┴──┐   │
│    │  每个 Job 独立完成:                      │   │
│    │  1. 安装 Node + pnpm + Rust            │   │
│    │  2. 自动拉取最新 Mihomo 内核             │   │
│    │  3. pnpm tauri build --no-bundle       │   │
│    │  4. 打包为 .zip 压缩包                  │   │
│    │  5. 上传 Artifact                      │   │
│    └────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────┘
                      ↓
          ┌───────────────────────┐
          │  publish-release Job  │
          │  下载全部 Artifact     │
          │  创建 GitHub Release  │
          │  上传 3 个 .zip 文件   │
          └───────────────────────┘
```

每个压缩包内部结构：
```
mihomo-tools-portable/
├── mihomo-tools.exe          # 主程序
├── mihomo/
│   └── mihomo.exe            # 自动拉取的最新 Mihomo 内核
└── data/                     # 空目录，运行时自动写入配置
```

---

## 🏗️ 项目架构

```
mihomo-tools/
├── .github/workflows/         # CI/CD 自动打包配置
│   └── release.yml
├── scripts/                   # 构建辅助脚本
│   ├── download-mihomo.js     # 自动下载最新 Mihomo 内核
│   └── release.js             # 版本发布自动化脚本
├── src-tauri/                 # 后端 (Tauri 2 + Rust)
│   └── src/
│       ├── commands.rs        # Tauri IPC 命令路由层
│       ├── config.rs          # Mihomo YAML 配置编译器
│       ├── models.rs          # 数据结构定义与版本迁移
│       ├── process.rs         # 内核子进程生命周期管理
│       ├── ip_check.rs        # 代理出口 GeoIP 检测
│       ├── utils.rs           # 路径解析、端口检测工具
│       ├── parser.rs          # URL/YAML 解析入口
│       └── parser/            # 协议解析子模块
│           ├── socks.rs       # SOCKS5 链接解析
│           ├── shadowsocks.rs # SS 链接解析
│           ├── vless.rs       # VLESS 链接解析
│           ├── trojan.rs      # Trojan 链接解析
│           ├── anytls.rs      # AnyTLS 链接解析
│           ├── hysteria2.rs   # Hysteria2 链接解析
│           └── mihomo_yaml.rs # Mihomo YAML 格式解析
└── src/                       # 前端 (React 19 + TypeScript + Vite)
    ├── api/backend.ts         # Tauri IPC TypeScript 绑定
    ├── features/runtime/      # 运行时状态组件
    ├── App.tsx                # 主界面仪表盘
    ├── App.css                # 暗色玻璃拟态设计样式表
    └── main.tsx               # React 入口
```

---

## ❓ 常见问题

### Q: macOS 提示「无法打开，因为无法验证开发者」？

由于程序未进行 Apple 签名，首次打开时可能被 Gatekeeper 阻止。解决方法：

```bash
# 移除文件的隔离属性
xattr -cr ./mihomo-tools
xattr -cr ./mihomo/mihomo
```

或者在 **系统设置 → 隐私与安全性** 中点击「仍要打开」。

### Q: 端口被占用怎么办？

程序在启动前会自动检测端口可用性。如果提示端口冲突：
1. 修改规则中的本地端口为其他未占用的端口
2. 或关闭占用该端口的其他程序

### Q: 如何更新 Mihomo 内核？

运行以下命令重新下载最新版本：
```bash
pnpm run download-mihomo
```
或手动从 [MetaCubeX/mihomo Releases](https://github.com/MetaCubeX/mihomo/releases) 下载并替换 `mihomo/` 目录下的二进制文件。

### Q: 配置文件在哪里？

所有配置数据都保存在程序运行目录下的 `data/` 文件夹中：
- `data/app-state.json` — 用户规则与应用设置
- `data/generated-config.yaml` — 自动生成的 Mihomo 运行配置

---

## 📝 许可证

本项目基于 [MIT License](LICENSE) 开源。仅供学习与本地开发测试使用，请勿用于非法用途。
