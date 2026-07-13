"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { Search, User as UserIcon, KeyRound, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { Kbd } from "@/components/ui/primitives";
import { NAV_FLAT } from "./nav";
import { useApp } from "@/components/app-provider";

interface PaletteAction {
  id: string;
  label: string;
  icon: LucideIcon;
  run: () => void;
}
interface Item {
  type: "nav" | "action" | "user" | "license";
  id: string;
  label: string;
  icon: LucideIcon;
  hint: string;
  run?: () => void;
  href?: string;
}

export function CommandPalette({
  open,
  onClose,
  actions,
}: {
  open: boolean;
  onClose: () => void;
  actions: PaletteAction[];
}) {
  const router = useRouter();
  const { data } = useApp();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQ("");
      setSel(0);
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  const groups = useMemo(() => {
    const ql = q.trim().toLowerCase();
    const navCmds: Item[] = NAV_FLAT.filter((n) => !ql || n.label.toLowerCase().includes(ql)).map((n) => ({
      type: "nav",
      id: n.id,
      label: n.label,
      icon: n.icon,
      hint: "Aller à",
      href: n.href,
    }));
    const actCmds: Item[] = actions
      .filter((a) => !ql || a.label.toLowerCase().includes(ql))
      .map((a) => ({ type: "action", id: a.id, label: a.label, icon: a.icon, hint: "Action", run: a.run }));
    let userHits: Item[] = [];
    let licHits: Item[] = [];
    if (ql) {
      userHits = data.users
        .filter((u) => u.username.toLowerCase().includes(ql) || u.discordId.includes(ql))
        .slice(0, 4)
        .map((u) => ({ type: "user", id: u.id, label: u.username, icon: UserIcon, hint: "Utilisateur · " + u.grade, href: `/users?focus=${u.username}` }));
      licHits = data.licenses
        .filter((l) => l.key.toLowerCase().includes(ql) || (l.username && l.username.toLowerCase().includes(ql)))
        .slice(0, 4)
        .map((l) => ({ type: "license", id: l.id, label: l.key, icon: KeyRound, hint: "Licence · " + (l.username || "non assignée"), href: `/licenses?focus=${l.id}` }));
    }
    const out: { name: string; items: Item[] }[] = [];
    if (navCmds.length) out.push({ name: "Navigation", items: navCmds });
    if (actCmds.length) out.push({ name: "Actions rapides", items: actCmds });
    if (userHits.length) out.push({ name: "Utilisateurs", items: userHits });
    if (licHits.length) out.push({ name: "Licences", items: licHits });
    return out;
  }, [q, actions, data]);

  const flat = useMemo(() => groups.flatMap((g) => g.items), [groups]);
  useEffect(() => {
    if (sel >= flat.length) setSel(0);
  }, [flat.length, sel]);

  const run = (item: Item) => {
    onClose();
    if (item.run) item.run();
    else if (item.href) router.push(item.href);
  };

  return createPortal(
    <AnimatePresence>
      {open && (
        <motion.div
          className="whip-scrim whip-scrim--palette"
          onMouseDown={(e) => e.target === e.currentTarget && onClose()}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
        >
          <motion.div
            className="whip-palette"
            role="dialog"
            aria-modal="true"
            initial={{ opacity: 0, scale: 0.97, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: 8 }}
            transition={{ duration: 0.18 }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setSel((s) => Math.min(flat.length - 1, s + 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setSel((s) => Math.max(0, s - 1));
              } else if (e.key === "Enter") {
                e.preventDefault();
                flat[sel] && run(flat[sel]);
              } else if (e.key === "Escape") onClose();
            }}
          >
            <div className="whip-palette__search">
              <Search size={18} />
              <input
                ref={inputRef}
                value={q}
                onChange={(e) => {
                  setQ(e.target.value);
                  setSel(0);
                }}
                placeholder="Tape une commande, un pseudo, une clé de licence…"
              />
              <Kbd>esc</Kbd>
            </div>
            <div className="whip-palette__results">
              {flat.length === 0 && <div className="whip-palette__empty">Aucune correspondance pour “{q}”.</div>}
              {groups.map((g) => (
                <div key={g.name} className="whip-palette__group">
                  <div className="whip-palette__grouplabel">{g.name}</div>
                  {g.items.map((item) => {
                    const idx = flat.indexOf(item);
                    const Icon = item.icon;
                    return (
                      <button
                        key={item.type + item.id}
                        className={cn("whip-palette__item", idx === sel && "whip-palette__item--active")}
                        onMouseEnter={() => setSel(idx)}
                        onClick={() => run(item)}
                      >
                        <Icon size={16} className="whip-palette__itemicon" />
                        <span className="whip-palette__itemlabel">{item.label}</span>
                        <span className="whip-palette__itemhint">{item.hint}</span>
                      </button>
                    );
                  })}
                </div>
              ))}
            </div>
            <div className="whip-palette__foot">
              <span>
                <Kbd>↑</Kbd>
                <Kbd>↓</Kbd> naviguer
              </span>
              <span>
                <Kbd>↵</Kbd> ouvrir
              </span>
              <span>
                <Kbd>⌘</Kbd>
                <Kbd>K</Kbd> basculer
              </span>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  );
}
