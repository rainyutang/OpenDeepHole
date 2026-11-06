import { useId, useState } from "react";
import "./BaselineAuditLabel.css";

export function BaselineAuditLabel() {
  const id = useId();
  const [open, setOpen] = useState(false);
  return <span className="baseline-audit-label" tabIndex={0}
    aria-describedby={open ? id : undefined}
    onFocus={() => setOpen(true)} onBlur={() => setOpen(false)}
    onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}
    onKeyDown={(event) => { if (event.key === "Escape") setOpen(false); }}>
    固定审计
    {open && <span className="baseline-audit-label__tooltip" id={id} role="tooltip">
      系统补充的审计范围，是否存在问题由审计确认。
    </span>}
  </span>;
}
