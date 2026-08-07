import { Component, Fragment } from "react";
import type { ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
  name: string;
  resetKey?: string;
  fallback?: ReactNode;
  fullscreen?: boolean;
}

interface State {
  error: Error | null;
  generation: number;
}

function storeRuntimeError(name: string, error: Error, info: ErrorInfo): void {
  try {
    sessionStorage.setItem("deephole_ui_last_error", JSON.stringify({
      name,
      message: error.message,
      timestamp: new Date().toISOString(),
      componentStack: info.componentStack?.slice(0, 4000) ?? "",
    }));
  } catch {
    // Error reporting must never cause another rendering failure.
  }
}

function DefaultFallback({ fullscreen = false }: { fullscreen?: boolean }) {
  return (
    <div className={fullscreen
      ? "min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6 text-slate-300"
      : "rounded-lg border border-amber-500/30 bg-amber-500/10 p-5 text-sm text-amber-100"
    }>
      <div className={fullscreen ? "mx-auto mt-20 max-w-xl rounded-lg border border-amber-500/30 bg-slate-900/80 p-5" : ""}>
        界面暂时无法完成渲染，异常区域已被自动隔离。
      </div>
    </div>
  );
}

export default class RuntimeErrorBoundary extends Component<Props, State> {
  state: State = { error: null, generation: 0 };

  private recoveryAttempts = 0;
  private recoveryTimer: number | null = null;

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error(`界面渲染失败: ${this.props.name}`, error, info);
    storeRuntimeError(this.props.name, error, info);
    if (this.recoveryAttempts >= 2 || this.recoveryTimer != null) return;
    this.recoveryAttempts += 1;
    this.recoveryTimer = window.setTimeout(() => {
      this.recoveryTimer = null;
      this.setState((previous) => ({
        error: null,
        generation: previous.generation + 1,
      }));
    }, 150 * this.recoveryAttempts);
  }

  componentDidUpdate(previousProps: Props): void {
    if (previousProps.resetKey === this.props.resetKey) return;
    this.recoveryAttempts = 0;
    if (this.state.error) {
      this.setState((previous) => ({
        error: null,
        generation: previous.generation + 1,
      }));
    }
  }

  componentWillUnmount(): void {
    if (this.recoveryTimer != null) window.clearTimeout(this.recoveryTimer);
  }

  render() {
    if (this.state.error) {
      return this.props.fallback ?? <DefaultFallback fullscreen={this.props.fullscreen} />;
    }
    return <Fragment key={this.state.generation}>{this.props.children}</Fragment>;
  }
}
