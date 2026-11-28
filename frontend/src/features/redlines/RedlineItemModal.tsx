import { useEffect, useState } from "react";
import type { RedlineItem, RedlineItemInput } from "../../types/redlines";
import { emptyRedlineInput, redlineInputFromItem, validateRedlineInput } from "./redlinesModel";

interface Props {
  open: boolean;
  editingItem: RedlineItem | null;
  saving: boolean;
  error: string;
  onClose: () => void;
  onSave: (input: RedlineItemInput) => Promise<void>;
}

const inputCls =
  "w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none transition-colors focus:border-blue-500";

export function RedlineItemModal({ open, editingItem, saving, error, onClose, onSave }: Props) {
  const [form, setForm] = useState<RedlineItemInput>(emptyRedlineInput);
  const [localError, setLocalError] = useState("");

  useEffect(() => {
    if (!open) return;
    setForm(editingItem ? redlineInputFromItem(editingItem) : emptyRedlineInput());
    setLocalError("");
  }, [open, editingItem]);

  if (!open) return null;

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const validation = validateRedlineInput(form);
    if (validation) {
      setLocalError(validation);
      return;
    }
    setLocalError("");
    await onSave({
      code: form.code.trim(),
      security_attribute: form.security_attribute.trim(),
      attribute_description: form.attribute_description.trim(),
      requirement: form.requirement.trim(),
      category: form.category.trim(),
      guidance: form.guidance.trim(),
      remark: form.remark.trim(),
      enabled: form.enabled ?? true,
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="redline-modal-title"
        className="flex max-h-[90vh] w-full max-w-2xl flex-col rounded-xl border border-slate-700 bg-slate-800 shadow-2xl"
      >
        <div className="flex items-center justify-between border-b border-slate-700 px-5 py-4">
          <h2 id="redline-modal-title" className="text-base font-semibold text-white">
            {editingItem ? "编辑红线条目" : "新增红线条目"}
          </h2>
          <button
            type="button"
            onClick={onClose}
            disabled={saving}
            className="text-sm text-slate-400 hover:text-white disabled:opacity-50"
          >
            关闭
          </button>
        </div>
        <form onSubmit={handleSubmit} className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-slate-300">编号 *</span>
              <input
                className={inputCls}
                value={form.code}
                placeholder="例如 5.2.2"
                onChange={(e) => setForm((prev) => ({ ...prev, code: e.target.value }))}
              />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-slate-300">分类</span>
              <input
                className={inputCls}
                value={form.category}
                placeholder="例如 A1"
                onChange={(e) => setForm((prev) => ({ ...prev, category: e.target.value }))}
              />
            </label>
          </div>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-300">安全属性 *</span>
            <input
              className={inputCls}
              value={form.security_attribute}
              placeholder="例如 产品开发、发布和安装安全"
              onChange={(e) => setForm((prev) => ({ ...prev, security_attribute: e.target.value }))}
            />
          </label>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-300">属性描述 *</span>
            <textarea
              rows={2}
              className={inputCls}
              value={form.attribute_description}
              placeholder="例如 禁止恶意软件。"
              onChange={(e) => setForm((prev) => ({ ...prev, attribute_description: e.target.value }))}
            />
          </label>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-300">
              红线要求 * <span className="font-normal text-slate-500">（不含编号前缀，报告会自动拼装编号）</span>
            </span>
            <textarea
              rows={3}
              className={inputCls}
              value={form.requirement}
              placeholder="例如 产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。"
              onChange={(e) => setForm((prev) => ({ ...prev, requirement: e.target.value }))}
            />
          </label>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-300">解读及指导</span>
            <textarea
              rows={3}
              className={inputCls}
              value={form.guidance}
              placeholder="可选：排查关注点、常见违规场景或实现指导"
              onChange={(e) => setForm((prev) => ({ ...prev, guidance: e.target.value }))}
            />
          </label>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-300">备注</span>
            <textarea
              rows={2}
              className={inputCls}
              value={form.remark}
              placeholder="可选备注信息"
              onChange={(e) => setForm((prev) => ({ ...prev, remark: e.target.value }))}
            />
          </label>
          <label className="flex items-center gap-2.5 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={form.enabled ?? true}
              onChange={(e) => setForm((prev) => ({ ...prev, enabled: e.target.checked }))}
            />
            <span>启用该条红线（勾选后将在「DeepHole网络安全红线排查引擎」扫描时参与排查）</span>
          </label>

          {(localError || error) && (
            <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
              {localError || error}
            </div>
          )}

          <div className="flex justify-end gap-2 border-t border-slate-700 pt-4">
            <button
              type="button"
              onClick={onClose}
              disabled={saving}
              className="rounded-lg bg-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-600 disabled:opacity-50"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={saving}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
            >
              {saving ? "保存中..." : "保存"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
