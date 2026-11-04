interface Props {
  paths: string[];
  onChange: (paths: string[]) => void;
}

export default function ScanPathList({ paths, onChange }: Props) {
  return <fieldset className="min-w-0 space-y-2">
    <legend className="mb-2 text-sm font-medium text-slate-300">扫描模块路径（绝对路径）</legend>
    <p className="text-xs text-slate-500">可添加多个目录或文件；全部留空扫描项目总路径。</p>
    {paths.map((path, index) => <div key={index} className="flex items-center gap-2">
      <input
        className="min-w-0 flex-1 rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-blue-500"
        aria-label={`扫描路径 ${index + 1}`}
        value={path}
        placeholder="目录或文件的绝对路径"
        onChange={(event) => onChange(paths.map((value, position) => position === index ? event.target.value : value))}
      />
      {paths.length > 1 && <button type="button" aria-label={`删除扫描路径 ${index + 1}`} onClick={() => onChange(paths.filter((_, position) => position !== index))} className="shrink-0 text-xs text-red-300 hover:text-red-200">删除</button>}
    </div>)}
    <button type="button" onClick={() => onChange([...paths, ""])} className="rounded border border-blue-400/40 px-3 py-1.5 text-xs text-blue-200">添加路径</button>
  </fieldset>;
}
