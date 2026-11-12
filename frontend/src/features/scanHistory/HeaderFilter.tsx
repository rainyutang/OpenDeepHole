import { ALL_FILTER, HeaderFilterOption } from './historyModel';

export function FilterIcon({ active }: { active: boolean }) {
  return (
    <svg

      className={`h-3.5 w-3.5 ${active ? "text-blue-300" : "text-slate-500"}`}

      fill="none"

      stroke="currentColor"

      viewBox="0 0 24 24"

      aria-hidden="true"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M3 5h18M6 12h12M10 19h4"
      />
    </svg>
  );
}

export function HeaderFilter({
  id,
  label,
  value,
  options,
  open,
  onOpenChange,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  options: HeaderFilterOption[];
  open: boolean;
  onOpenChange: (id: string | null) => void;
  onChange: (value: string) => void;
}) {
  const active = value !== ALL_FILTER;
  const activeOption = options.find((option) => option.value === value);
  const displayValue = activeOption?.label ?? value;

  return (
    <div

      className="relative inline-flex min-w-[7.5rem] max-w-[14rem] flex-col items-start gap-1 normal-case tracking-normal"

      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
          onOpenChange(null);
        }
      }}
    >
      <button

        type="button"

        onClick={() => onOpenChange(open ? null : id)}

        className={`inline-flex max-w-full items-center gap-1.5 rounded-md px-1.5 py-1 text-xs font-semibold transition-colors ${active
            ? "bg-blue-500/10 text-blue-300 hover:bg-blue-500/15"
            : "text-slate-400 hover:bg-slate-700/60 hover:text-slate-200"
          }`}

        aria-label={`${label}筛选`}

        aria-expanded={open}
      >
        <span className="truncate uppercase tracking-wider">{label}</span>
        <FilterIcon active={active} />
      </button>
      {active && (
        <span className="max-w-full truncate text-[11px] font-medium text-blue-300/80" title={displayValue}>
          {displayValue}
        </span>
      )}
      {open && (
        <div className="absolute left-0 top-full z-40 mt-2 w-56 overflow-hidden rounded-lg border border-slate-600 bg-slate-900 shadow-xl shadow-black/30">
          <button

            type="button"

            onMouseDown={(e) => e.preventDefault()}

            onClick={() => {
              onChange(ALL_FILTER);
              onOpenChange(null);
            }}

            className={`flex w-full items-center justify-between px-3 py-2 text-left text-xs transition-colors ${value === ALL_FILTER ? "bg-blue-500/15 text-blue-200" : "text-slate-300 hover:bg-slate-800"
              }`}
          >
            <span>全部</span>
            {value === ALL_FILTER && <span className="text-blue-300">✓</span>}
          </button>
          <div className="max-h-64 overflow-y-auto border-t border-slate-700/70 py-1">
            {options.map((option) => (
              <button

                key={option.value}

                type="button"

                title={option.label}

                onMouseDown={(e) => e.preventDefault()}

                onClick={() => {
                  onChange(option.value);
                  onOpenChange(null);
                }}

                className={`flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-xs transition-colors ${value === option.value ? "bg-blue-500/15 text-blue-200" : "text-slate-300 hover:bg-slate-800"
                  }`}
              >
                <span className="min-w-0 truncate">{option.label}</span>
                {value === option.value && <span className="shrink-0 text-blue-300">✓</span>}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
