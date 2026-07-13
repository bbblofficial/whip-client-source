"use client";
// ════════════════════════════════════════════════════════════════════
//  WhipSite · overlays — Modal, Drawer, Toaster, ConfirmDialog
//  Framer Motion entrance/exit; scrims close on backdrop + Escape.
// ════════════════════════════════════════════════════════════════════
import { useEffect, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { X, AlertTriangle, CheckCircle, XCircle, Bell } from "lucide-react";
import { cn } from "@/lib/utils";

const EASE = [0.16, 1, 0.3, 1] as const;

export function Modal({
  title,
  eyebrow,
  onClose,
  children,
  footer,
  size = "md",
  danger,
}: {
  title: ReactNode;
  eyebrow?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg" | "xl";
  danger?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return createPortal(
    <motion.div
      className="whip-scrim"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.18 }}
    >
      <motion.div
        className={cn("whip-modal", `whip-modal--${size}`)}
        role="dialog"
        aria-modal="true"
        initial={{ opacity: 0, scale: 0.96, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.96, y: 8 }}
        transition={{ duration: 0.22, ease: EASE }}
      >
        <div className="whip-modal__head">
          <div>
            {eyebrow && <div className={cn("whip-modal__eyebrow", danger && "whip-modal__eyebrow--danger")}>{eyebrow}</div>}
            <h2 className="whip-modal__title">{title}</h2>
          </div>
          <button className="whip-modal__close" onClick={onClose} aria-label="Fermer">
            <X size={18} />
          </button>
        </div>
        <div className="whip-modal__body">{children}</div>
        {footer && <div className="whip-modal__foot">{footer}</div>}
      </motion.div>
    </motion.div>,
    document.body,
  );
}

export function Drawer({
  title,
  eyebrow,
  onClose,
  children,
  width = 460,
  footer,
}: {
  title: ReactNode;
  eyebrow?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  width?: number;
  footer?: ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return createPortal(
    <motion.div
      className="whip-scrim whip-scrim--drawer"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.18 }}
    >
      <motion.aside
        className="whip-drawer"
        style={{ width }}
        role="dialog"
        aria-modal="true"
        initial={{ x: 40, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        exit={{ x: 40, opacity: 0 }}
        transition={{ duration: 0.26, ease: EASE }}
      >
        <div className="whip-drawer__head">
          <div>
            {eyebrow && <div className="whip-drawer__eyebrow">{eyebrow}</div>}
            <h2 className="whip-drawer__title">{title}</h2>
          </div>
          <button className="whip-modal__close" onClick={onClose} aria-label="Fermer">
            <X size={18} />
          </button>
        </div>
        <div className="whip-drawer__body">{children}</div>
        {footer && <div className="whip-drawer__foot">{footer}</div>}
      </motion.aside>
    </motion.div>,
    document.body,
  );
}

export interface Toast {
  id: number;
  tone?: "success" | "danger" | "info" | "warning";
  title: string;
  desc?: string;
  undo?: () => void;
  sticky?: boolean;
  duration?: number;
}

export function Toaster({ toasts, dismiss }: { toasts: Toast[]; dismiss: (id: number) => void }) {
  const iconFor = { success: CheckCircle, danger: XCircle, info: Bell, warning: AlertTriangle };
  return createPortal(
    <div className="whip-toasts">
      <AnimatePresence>
        {toasts.map((t) => {
          const I = iconFor[t.tone || "info"] || Bell;
          return (
            <motion.div
              key={t.id}
              className={cn("whip-toast", `whip-toast--${t.tone || "info"}`)}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.28, ease: EASE }}
              layout
            >
              <span className="whip-toast__ic">
                <I size={17} />
              </span>
              <div className="whip-toast__body">
                <div className="whip-toast__title">{t.title}</div>
                {t.desc && <div className="whip-toast__desc">{t.desc}</div>}
              </div>
              {t.undo && (
                <button
                  className="whip-toast__undo"
                  onClick={() => {
                    t.undo?.();
                    dismiss(t.id);
                  }}
                >
                  Annuler
                </button>
              )}
              <button className="whip-toast__close" onClick={() => dismiss(t.id)}>
                <X size={14} />
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>,
    document.body,
  );
}

export interface ConfirmOptions {
  title: ReactNode;
  message: ReactNode;
  confirmLabel?: string;
  tone?: "danger" | "primary";
  icon?: ReactNode;
}

export function ConfirmDialog({ data, onResolve }: { data: ConfirmOptions | null; onResolve: (v: boolean) => void }) {
  return (
    <AnimatePresence>
      {data && (
        <Modal
          title={data.title}
          eyebrow={data.tone === "primary" ? "confirmation" : "action destructrice"}
          danger={data.tone !== "primary"}
          size="sm"
          onClose={() => onResolve(false)}
          footer={
            <>
              <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={() => onResolve(false)}>
                Annuler
              </button>
              <button
                className={cn("abs-btn abs-btn--md", data.tone === "primary" ? "abs-btn--primary" : "whip-btn-destructive")}
                onClick={() => onResolve(true)}
              >
                {data.confirmLabel || "Confirmer"}
              </button>
            </>
          }
        >
          <div className="whip-confirm">
            <span className={cn("whip-confirm__icon", `whip-confirm__icon--${data.tone === "primary" ? "primary" : "danger"}`)}>
              {data.icon || <AlertTriangle size={22} />}
            </span>
            <p className="whip-confirm__msg">{data.message}</p>
          </div>
        </Modal>
      )}
    </AnimatePresence>
  );
}
