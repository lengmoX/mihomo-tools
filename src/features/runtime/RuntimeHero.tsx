import type { XrayVersionInfo } from "../../api/backend";
import { Icon } from "./RuntimeIcon";
import type { RuntimeAction, StatusMeta } from "./runtime-types";

type RuntimeHeroProps = {
  isBusy: boolean;
  onAction: (action: RuntimeAction) => void;
  runtimeActions: RuntimeAction[];
  statusMeta: StatusMeta;
  versionInfo: XrayVersionInfo | null;
  theme: "system" | "light" | "dark";
  onChangeTheme: (nextTheme: "system" | "light" | "dark") => void;
};

export function RuntimeHero({ isBusy, onAction, runtimeActions, statusMeta, versionInfo, theme, onChangeTheme }: RuntimeHeroProps) {
  const versionLabel = versionInfo === null ? "版本读取中" : `版本 ${versionInfo.version}`;
  const versionTitle = versionInfo?.displayText ?? "正在通过后端读取 Mihomo 版本";

  const themeIconMap = {
    system: "system" as const,
    light: "sun" as const,
    dark: "moon" as const,
  };

  const themeTitleMap = {
    system: "主题: 跟随系统 (点击切换为浅色模式)",
    light: "主题: 浅色模式 (点击切换为暗色模式)",
    dark: "主题: 暗色模式 (点击切换为跟随系统)",
  };

  const handleThemeCycle = () => {
    if (theme === "system") {
      onChangeTheme("light");
    } else if (theme === "light") {
      onChangeTheme("dark");
    } else {
      onChangeTheme("system");
    }
  };

  return (
    <section className="hero-panel" aria-labelledby="app-title">
      <div className="status-card">
        <div className="status-orb" aria-hidden="true">
          <span className={statusMeta.tone}></span>
        </div>
        <div>
          <p className="eyebrow">Mihomo Core</p>
          <h1 id="app-title">mihomo-tools</h1>
          <p className="status-line">
            <span className={`status-pill ${statusMeta.tone}`}>{statusMeta.label}</span>
            <span title={versionTitle}>{versionLabel}</span>
          </p>
          <p className="muted-text">{statusMeta.detail}</p>
        </div>
      </div>

      <div className="runtime-actions" aria-label="运行时控制与主题">
        <button
          className="icon-button theme-toggle-btn"
          type="button"
          aria-label={themeTitleMap[theme]}
          title={themeTitleMap[theme]}
          onClick={handleThemeCycle}
        >
          <Icon name={themeIconMap[theme]} />
        </button>

        {runtimeActions.map((action) => (
          <button
            className="icon-button"
            type="button"
            key={action.name}
            aria-label={action.label}
            title={action.title}
            onClick={() => onAction(action)}
            disabled={isBusy}
          >
            <Icon name={action.name} />
          </button>
        ))}
      </div>
    </section>
  );
}
