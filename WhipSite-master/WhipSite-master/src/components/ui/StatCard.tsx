"use client";
// ════════════════════════════════════════════════════════════════════
//  WhipSite · StatCard + Panel + DrawerSection helpers
// ════════════════════════════════════════════════════════════════════
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Trend } from "./primitives";

export function StatCard({
  icon,
  label,
  value,
  trend,
  spark,
  live,
  tone = "primary",
  onClick,
}: {
  icon: ReactNode;
  label: ReactNode;
  value: ReactNode;
  trend?: number;
  spark?: ReactNode;
  live?: boolean;
  tone?: "primary" | "success" | "danger" | "warning" | "purple";
  onClick?: () => void;
}) {
  return (
    <div className={cn("whip-stat", onClick && "whip-stat--clickable")} onClick={onClick}>
      <div className="whip-stat__top">
        <span className={cn("whip-stat__icon", `whip-stat__icon--${tone}`)}>{icon}</span>
        <div className="whip-stat__meta">
          {trend != null && <Trend value={trend} />}
          {live && (
            <span className="whip-stat__live">
              <span className="whip-stat__live-dot" />
              live
            </span>
          )}
        </div>
      </div>
      <div className="whip-stat__label">{label}</div>
      <div className="whip-stat__row">
        <div className="whip-stat__value">{value}</div>
        {spark && <div className="whip-stat__spark">{spark}</div>}
      </div>
    </div>
  );
}

export function Panel({
  title,
  hint,
  action,
  children,
  bodyPad,
}: {
  title?: ReactNode;
  hint?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  bodyPad?: number | string;
}) {
  return (
    <div className="whip-panel">
      {(title || action || hint) && (
        <div className="whip-panel__head">
          {title && <h3 className="whip-panel__title">{title}</h3>}
          {hint && <span className="whip-panel__hint">{hint}</span>}
          {action}
        </div>
      )}
      <div className="whip-panel__body" style={bodyPad != null ? { padding: bodyPad } : undefined}>
        {children}
      </div>
    </div>
  );
}

export function DrawerSection({
  title,
  count,
  onAll,
  children,
}: {
  title: ReactNode;
  count?: number;
  onAll?: () => void;
  children: ReactNode;
}) {
  return (
    <section className="whip-drawersec">
      <div className="whip-drawersec__head">
        <h4>
          {title}
          {count != null && <span className="whip-drawersec__count">{count}</span>}
        </h4>
        {onAll && (
          <button className="whip-link" onClick={onAll}>
            Tout voir
          </button>
        )}
      </div>
      <div className="whip-drawersec__body">{children}</div>
    </section>
  );
}
