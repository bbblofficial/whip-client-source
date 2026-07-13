"use client";
import { useState } from "react";
import {
  Bell,
  Sliders,
  Check,
  X,
  ShieldAlert,
  Clock,
  CreditCard,
  Fingerprint,
  ShieldCheck,
  Settings,
  Plus,
  Minus,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { Alert } from "@/lib/alerts";
import type { AntiShareRules } from "@/lib/types";
import { Modal } from "@/components/ui/overlays";
import { FormRow, Switch } from "@/components/ui/primitives";

const ALERT_ICON = { share: ShieldAlert, expire: Clock, billing: CreditCard, leak: Fingerprint };
const SEV: Record<string, string> = {
  danger: "var(--whip-danger)",
  warning: "var(--whip-warning)",
  info: "var(--whip-primary-bright)",
  neutral: "var(--whip-fg-subtle)",
};

export function AlertsPanel({
  alerts,
  rules,
  onClose,
  onDismiss,
  onDismissAll,
  onAction,
  onOpenRules,
  timeAgo,
}: {
  alerts: Alert[];
  rules: AntiShareRules;
  onClose: () => void;
  onDismiss: (id: string) => void;
  onDismissAll: () => void;
  onAction: (a: Alert, type: string) => void;
  onOpenRules: () => void;
  timeAgo: (d: Date) => string;
}) {
  return (
    <div className="whip-alertscrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="whip-alertspanel" role="dialog" aria-label="Centre d'alertes">
        <div className="whip-alertspanel__head">
          <div className="whip-alertspanel__title">
            <Bell size={16} />
            Alertes<span className="whip-alertspanel__count">{alerts.length}</span>
          </div>
          <div className="whip-alertspanel__tools">
            <button className="whip-alertspanel__tool" title="Règles anti-partage" onClick={onOpenRules}>
              <Sliders size={15} />
            </button>
            {alerts.length > 0 && (
              <button className="whip-alertspanel__tool" title="Tout ignorer" onClick={onDismissAll}>
                <Check size={15} />
              </button>
            )}
            <button className="whip-alertspanel__tool" onClick={onClose}>
              <X size={16} />
            </button>
          </div>
        </div>
        <div className="whip-alertspanel__rules" onClick={onOpenRules}>
          <ShieldAlert size={13} />
          Seuils : <strong>{rules.maxHwid}</strong> HWID · <strong>{rules.maxIp}</strong> IP{" "}
          {rules.autoSuspend && <span className="whip-alertspanel__auto">· auto-suspension ON</span>}
          <Settings size={13} style={{ marginLeft: "auto" }} />
        </div>
        <div className="whip-alertspanel__list">
          {alerts.length === 0 ? (
            <div className="whip-alertempty">
              <ShieldCheck size={28} />
              <span>Aucune alerte</span>
              <small>Tout est sous contrôle.</small>
            </div>
          ) : (
            alerts.map((a) => {
              const I = ALERT_ICON[a.icon] || Bell;
              return (
                <div key={a.id} className="whip-alertitem">
                  <span className="whip-alertitem__sev" style={{ background: SEV[a.sev] }} />
                  <span className="whip-alertitem__icon" style={{ color: SEV[a.sev] }}>
                    <I size={15} />
                  </span>
                  <div className="whip-alertitem__body">
                    <div className="whip-alertitem__top">
                      <span className="whip-alertitem__title">{a.title}</span>
                      <span className="whip-alertitem__time">{timeAgo(a.ts)}</span>
                    </div>
                    <div className="whip-alertitem__desc">{a.desc}</div>
                    <div className="whip-alertitem__actions">
                      {a.actions.map((act) => (
                        <button
                          key={act.type}
                          className={cn("whip-alertbtn", act.tone === "danger" && "whip-alertbtn--danger")}
                          onClick={() => onAction(a, act.type)}
                        >
                          {act.label}
                        </button>
                      ))}
                      <button className="whip-alertbtn whip-alertbtn--ghost" onClick={() => onDismiss(a.id)}>
                        Ignorer
                      </button>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

export function AntiShareModal({
  rules,
  onClose,
  onApply,
  sharedCount,
}: {
  rules: AntiShareRules;
  onClose: () => void;
  onApply: (r: AntiShareRules) => void;
  sharedCount: (r: AntiShareRules) => number;
}) {
  const [f, setF] = useState(rules);
  const step = (k: "maxHwid" | "maxIp", d: number, min: number) => () =>
    setF((s) => ({ ...s, [k]: Math.max(min, s[k] + d) }));
  return (
    <Modal
      eyebrow="règle automatique"
      title="Anti-partage"
      onClose={onClose}
      size="md"
      footer={
        <>
          <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={onClose}>
            Annuler
          </button>
          <button
            className="abs-btn abs-btn--primary abs-btn--md"
            onClick={() => {
              onApply(f);
              onClose();
            }}
          >
            <ShieldCheck size={15} />
            Appliquer la règle
          </button>
        </>
      }
    >
      <p className="whip-rule-intro">
        Une licence est signalée comme <strong>partagée</strong> dès qu&apos;elle dépasse l&apos;un de ces seuils. Tu
        peux suspendre automatiquement les licences fautives.
      </p>
      <div className="whip-stepper">
        <div>
          <div className="whip-stepper__lbl">HWID max par licence</div>
          <div className="whip-stepper__hint">machines distinctes autorisées</div>
        </div>
        <div className="whip-stepper__ctrl">
          <button onClick={step("maxHwid", -1, 1)}>
            <Minus size={14} />
          </button>
          <span>{f.maxHwid}</span>
          <button onClick={step("maxHwid", 1, 1)}>
            <Plus size={14} />
          </button>
        </div>
      </div>
      <div className="whip-stepper">
        <div>
          <div className="whip-stepper__lbl">IP max par licence</div>
          <div className="whip-stepper__hint">adresses distinctes autorisées</div>
        </div>
        <div className="whip-stepper__ctrl">
          <button onClick={step("maxIp", -1, 1)}>
            <Minus size={14} />
          </button>
          <span>{f.maxIp}</span>
          <button onClick={step("maxIp", 1, 1)}>
            <Plus size={14} />
          </button>
        </div>
      </div>
      <div className="whip-formtoggle" style={{ padding: "14px 0 4px" }}>
        <div>
          <div className="whip-stepper__lbl" style={{ textTransform: "none", letterSpacing: 0, fontSize: 13, color: "var(--whip-fg)" }}>
            Suspension automatique
          </div>
          <div className="whip-stepper__hint">suspendre les licences au-delà du seuil à l&apos;application</div>
        </div>
        <Switch on={f.autoSuspend} onClick={() => setF((s) => ({ ...s, autoSuspend: !s.autoSuspend }))} />
      </div>
      <div className="whip-rule-preview">
        <ShieldAlert size={15} />
        <strong>{sharedCount(f)}</strong> licence(s) dépasseront ces seuils{f.autoSuspend ? " et seront suspendues." : "."}
      </div>
    </Modal>
  );
}

export { FormRow };
