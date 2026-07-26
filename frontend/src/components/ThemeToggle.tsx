import { useTheme } from "../theme/ThemeProvider";

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  const darkModeEnabled = theme === "dark";
  const title = darkModeEnabled ? "切换到浅色模式" : "切换到深色模式";
  const accessibleLabel = darkModeEnabled
    ? "深色模式已开启，切换到浅色模式"
    : "深色模式已关闭，切换到深色模式";

  return (
    <button
      type="button"
      className="theme-toggle"
      aria-label={accessibleLabel}
      aria-pressed={darkModeEnabled}
      title={title}
      onClick={toggleTheme}
    >
      {darkModeEnabled ? (
        <svg aria-hidden="true" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="3.75" />
          <path d="M12 2.25v2M12 19.75v2M4.4 4.4l1.4 1.4M18.2 18.2l1.4 1.4M2.25 12h2M19.75 12h2M4.4 19.6l1.4-1.4M18.2 5.8l1.4-1.4" />
        </svg>
      ) : (
        <svg aria-hidden="true" viewBox="0 0 24 24">
          <path d="M20.25 15.2A8.3 8.3 0 0 1 8.8 3.75 8.5 8.5 0 1 0 20.25 15.2Z" />
        </svg>
      )}
    </button>
  );
}
