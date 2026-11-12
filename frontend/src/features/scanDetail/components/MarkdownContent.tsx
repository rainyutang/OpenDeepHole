import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export function MarkdownContent({ content }: { content: string; }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h1: ({ children }) => <h1 className="mb-4 text-xl font-semibold text-white">{children}</h1>,
        h2: ({ children }) => <h2 className="mt-6 mb-2 text-base font-semibold text-purple-100">{children}</h2>,
        h3: ({ children }) => <h3 className="mt-4 mb-2 text-sm font-semibold text-slate-100">{children}</h3>,
        p: ({ children }) => <p className="my-2 whitespace-pre-wrap text-sm leading-7 text-slate-300">{children}</p>,
        ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5 text-sm leading-relaxed text-slate-300 marker:text-purple-400">{children}</ul>,
        ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-5 text-sm leading-relaxed text-slate-300 marker:text-purple-400">{children}</ol>,
        li: ({ children }) => <li>{children}</li>,
        table: ({ children }) => (
          <div className="my-3 overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full min-w-max text-sm">{children}</table>
          </div>
        ),
        thead: ({ children }) => <thead className="bg-slate-950">{children}</thead>,
        th: ({ children }) => <th className="border-b border-slate-800 px-3 py-2 text-left text-xs font-semibold text-slate-400">{children}</th>,
        tr: ({ children }) => <tr className="border-t border-slate-800/70 first:border-t-0">{children}</tr>,
        td: ({ children }) => <td className="px-3 py-2 text-slate-300">{children}</td>,
        pre: ({ children }) => (
          <pre className="my-3 overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-4 text-xs leading-relaxed text-slate-300 [&_code]:border-0 [&_code]:bg-transparent [&_code]:p-0 [&_code]:text-slate-300">
            {children}
          </pre>
        ),
        code: ({ className, children }) => (
          <code className={`${className ?? ""} rounded border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-[0.85em] text-purple-200`}>
            {children}
          </code>
        ),
        strong: ({ children }) => <strong className="font-semibold text-slate-100">{children}</strong>,
      }}
    >
      {content}
    </ReactMarkdown>
  );
}
