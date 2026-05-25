import type { RuntimeStatus } from "../../api/backend";

export type IconName =
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
  | "sun"
  | "moon"
  | "system"
  | "info";

export type RuntimeActionName = "play" | "stop" | "restart" | "save";

export type RuntimeAction = {
  name: RuntimeActionName;
  label: string;
  title: string;
};

export type BusyAction = RuntimeActionName | "startup" | "toggle" | "delete" | "rule" | `ip-${string}` | "";

export type StatusMeta = {
  label: string;
  detail: string;
  tone: "is-running" | "is-stopped" | "is-restarting";
};

export function getStatusMeta(busyAction: BusyAction, runtimeStatus: RuntimeStatus): StatusMeta {
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
}

export const runtimeActions: RuntimeAction[] = [
  { name: "play", label: "启动 Mihomo", title: "启动" },
  { name: "stop", label: "停止 Mihomo", title: "停止" },
  { name: "restart", label: "重启 Mihomo", title: "重启" },
  { name: "save", label: "保存配置", title: "保存配置" },
];
