import type { ReactNode } from "react";

interface Props {
  title: string;
  onBack: () => void;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
}

export default function PageHeader({ title, onBack, description, actions, children }: Props) {
  return (
    <header className="border-b border-slate-700 bg-slate-800/80 px-4 py-4 backdrop-blur sm:px-6">
      <div className="mx-auto max-w-7xl">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-4">
            <button type="button" onClick={onBack} className="flex h-10 shrink-0 items-center rounded text-sm text-slate-400 transition-colors hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-blue-400">
              ← 返回
            </button>
            <div className="min-w-0">
              <h1 className="flex min-h-10 items-center break-words text-lg font-bold text-white">{title}</h1>
              {description && <p className="mt-0.5 text-sm text-slate-400">{description}</p>}
            </div>
          </div>
          {actions && <div className="ml-auto flex min-h-10 max-w-full min-w-0 flex-wrap items-center justify-end gap-2 sm:gap-3">{actions}</div>}
        </div>
        {children}
      </div>
    </header>
  );
}
