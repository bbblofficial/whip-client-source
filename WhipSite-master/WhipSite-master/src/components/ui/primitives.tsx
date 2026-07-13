"use client";
// ════════════════════════════════════════════════════════════════════
//  WhipSite · small UI atoms (ported 1:1 from the prototype)
// ════════════════════════════════════════════════════════════════════
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Check, Copy, Minus, ArrowUpRight } from "lucide-react";
import { cn } from "@/lib/utils";
import type {
  LicenseStatus,
  MachineStatus,
  SessionStatus,
  Grade,
} from "@/lib/types";

export function Avatar({
  name = "?",
  color = "#2563eb",
  size = 34,
}: {
  name?: string;
  color?: string;
  size?: number;
}) {
  const init = name.replace(/[^a-zA-Z0-9]/g, "").slice(0, 1).toUpperCase() || "?";
  return (
    <span
      className="whip-avatar"
      style={{
        width: size,
        height: size,
        background: color + "22",
        color,
        border: `1px solid ${color}44`,
        fontSize: size * 0.42,
      }}
    >
      {init}
    </span>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="whip-kbd">{children}</kbd>;
}

export function Mono({
  children,
  className,
  dim,
}: {
  children: ReactNode;
  className?: string;
  dim?: boolean;
}) {
  return <span className={cn("whip-mono", dim && "whip-mono--dim", className)}>{children}</span>;
}

export function IconButton({
  icon,
  title,
  tone = "default",
  onClick,
  disabled,
}: {
  icon: ReactNode;
  title: string;
  tone?: "default" | "danger" | "success" | "info";
  onClick?: (e: React.MouseEvent) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      className={cn("whip-iconbtn", `whip-iconbtn--${tone}`)}
      title={title}
      aria-label={title}
      disabled={disabled}
      onClick={(e) => {
        e.stopPropagation();
        onClick?.(e);
      }}
    >
      {icon}
    </button>
  );
}

const STATUS_MAP: Record<string, { cls: string; label: string }> = {
  active: { cls: "active", label: "active" },
  actif: { cls: "active", label: "actif" },
  revoked: { cls: "revoked", label: "révoqué" },
  expired: { cls: "expired", label: "expiré" },
  suspended: { cls: "suspended", label: "suspendu" },
  ended: { cls: "neutral", label: "terminée" },
  stale: { cls: "expired", label: "stale" },
  banned: { cls: "revoked", label: "banni" },
};
export const SEV_COLOR: Record<string, string> = {
  success: "var(--whip-success)",
  danger: "var(--whip-danger)",
  info: "var(--whip-primary-bright)",
  caution: "var(--whip-caution)",
  warning: "var(--whip-warning)",
  neutral: "var(--whip-fg-subtle)",
};

export function StatusBadge({
  status,
  dot = true,
  label,
}: {
  status: LicenseStatus | MachineStatus | SessionStatus | string;
  dot?: boolean;
  label?: string;
}) {
  const m = STATUS_MAP[status] || { cls: "neutral", label: status };
  return (
    <span className={cn("abs-badge", `abs-badge--${m.cls}`)}>
      {dot && <span className="abs-badge__dot" />}
      {label || m.label}
    </span>
  );
}

export function GradeBadge({ grade }: { grade: Grade }) {
  const label = grade;
  const cls =
    grade === "owner" || grade === "admin" ? "admin" : grade === "reseller" ? "brand" : "neutral";
  return <span className={cn("abs-badge", `abs-badge--${cls}`)}>{label}</span>;
}

export function Copyable({ value, display }: { value: string; display?: ReactNode }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="whip-copy"
      title="Copier"
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard?.writeText(value);
        setDone(true);
        setTimeout(() => setDone(false), 1100);
      }}
    >
      <span className="whip-mono">{display || value}</span>
      {done ? <Check size={13} className="whip-copy__ok" /> : <Copy size={13} className="whip-copy__ic" />}
    </button>
  );
}

export function Checkbox({
  checked,
  indeterminate,
  onChange,
  ariaLabel,
}: {
  checked?: boolean;
  indeterminate?: boolean;
  onChange?: (v: boolean) => void;
  ariaLabel?: string;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = !!indeterminate;
  }, [indeterminate]);
  return (
    <label className="whip-check" onClick={(e) => e.stopPropagation()}>
      <input
        ref={ref}
        type="checkbox"
        checked={!!checked}
        aria-label={ariaLabel}
        onChange={(e) => onChange?.(e.target.checked)}
      />
      <span className="whip-check__box">
        {checked && !indeterminate && <Check size={12} />}
        {indeterminate && <Minus size={12} />}
      </span>
    </label>
  );
}

export function Trend({ value }: { value: number }) {
  const up = value >= 0;
  return (
    <span className={cn("whip-trend", up ? "whip-trend--up" : "whip-trend--down")}>
      {up ? (
        <ArrowUpRight size={12} />
      ) : (
        <span style={{ transform: "rotate(90deg)", display: "inline-flex" }}>
          <ArrowUpRight size={12} />
        </span>
      )}
      {up ? "+" : ""}
      {value}%
    </span>
  );
}

export function EmptyState({
  icon,
  title,
  hint,
  action,
}: {
  icon?: ReactNode;
  title: ReactNode;
  hint?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="whip-empty">
      {icon && <span className="whip-empty__icon">{icon}</span>}
      <div className="whip-empty__title">{title}</div>
      {hint && <div className="whip-empty__hint">{hint}</div>}
      {action && <div className="whip-empty__action">{action}</div>}
    </div>
  );
}

export function PageHeader({
  title,
  eyebrow,
  actions,
  danger,
}: {
  title: ReactNode;
  eyebrow?: ReactNode;
  actions?: ReactNode;
  danger?: boolean;
}) {
  return (
    <header className="whip-pagehead">
      <div>
        <h1 className="whip-pagehead__title">{title}</h1>
        {eyebrow && (
          <p className={cn("whip-pagehead__eyebrow", danger && "whip-pagehead__eyebrow--danger")}>
            {eyebrow}
          </p>
        )}
      </div>
      {actions && <div className="whip-pagehead__actions">{actions}</div>}
    </header>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: { value: T; label: ReactNode; icon?: ReactNode }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="whip-segmented">
      {options.map((o) => (
        <button
          key={o.value}
          className={cn("whip-segmented__btn", value === o.value && "whip-segmented__btn--active")}
          onClick={() => onChange(o.value)}
        >
          {o.icon}
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Field({ label, children, mono }: { label: ReactNode; children: ReactNode; mono?: boolean }) {
  return (
    <div className="whip-field">
      <div className="whip-field__label">{label}</div>
      <div className={cn("whip-field__value", mono && "whip-mono")}>{children}</div>
    </div>
  );
}

export function FormRow({ label, hint, children }: { label: ReactNode; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="whip-formrow">
      <span className="whip-formrow__label">{label}</span>
      {children}
      {hint && <span className="whip-formrow__hint">{hint}</span>}
    </label>
  );
}

export function Switch({ on, onClick }: { on: boolean; onClick: () => void }) {
  return (
    <button type="button" className={cn("whip-switch", on && "whip-switch--on")} onClick={onClick}>
      <span className="whip-switch__knob" />
    </button>
  );
}
