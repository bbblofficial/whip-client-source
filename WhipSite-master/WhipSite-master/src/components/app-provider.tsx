"use client";
// ════════════════════════════════════════════════════════════════════
//  WhipSite · global app state (client context)
//  Holds the live dataset (seeded from the DB by the (panel) layout) +
//  every domain action. Each action calls the real server action, then —
//  on success — updates local state optimistically, logs to the audit
//  journal and fires a toast. Actions with no backend wiring yet show a
//  TODO toast instead of doing nothing.
// ════════════════════════════════════════════════════════════════════
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import * as srv from "@/lib/server/panel-actions";
import type {
  License,
  User,
  Machine,
  Session,
  Download,
  Config,
  BlacklistEntry,
  AuditEntry,
  AntiShareRules,
  AuditCategory,
  AuditSeverity,
  Product,
} from "@/lib/types";
import { Toaster, ConfirmDialog, type Toast, type ConfirmOptions } from "@/components/ui/overlays";

let toastSeq = 0;
const DAY = 86_400_000;

export interface SessionUser {
  username: string;
  grade: "owner" | "admin" | "reseller" | "user";
}

export interface InitialData {
  licenses: License[];
  users: User[];
  machines: Machine[];
  sessions: Session[];
  downloads: Download[];
  configs: Config[];
  blacklist: BlacklistEntry[];
  audit: AuditEntry[];
  products: Product[];
}

interface AuditDraft {
  action: string;
  label: string;
  cat: AuditCategory;
  sev: AuditSeverity;
  target: string;
  targetType: string;
}

interface AppContextValue {
  user: SessionUser;
  data: {
    licenses: License[];
    users: User[];
    machines: Machine[];
    sessions: Session[];
    downloads: Download[];
    configs: Config[];
    blacklist: BlacklistEntry[];
    audit: AuditEntry[];
    products: Product[];
  };
  rules: AntiShareRules;
  setRules: (r: AntiShareRules) => void;
  toast: (t: Omit<Toast, "id">) => number;
  confirm: (o: ConfirmOptions) => Promise<boolean>;
  pushAudit: (d: AuditDraft) => void;
  /** Re-pull the whole dataset from the DB without a page reload. */
  refresh: () => Promise<void>;
  refreshing: boolean;
  actions: Actions;
}

interface Actions {
  revokeLicense: (l: License) => void;
  restoreLicense: (l: License) => void;
  deleteLicense: (l: License) => void;
  bulkRevokeLicenses: (rows: License[], clear: () => void) => void;
  extendLicense: (l: License, days: number) => void;
  suspendLicense: (l: License) => void;
  generateLicense: (d: { username: string | null; productCode: string; lifetime: boolean; expiresAt: Date | null }) => void;
  blacklistUser: (e: { username: string; reason: string; expiresAt: Date | null }) => void;
  unblacklist: (b: BlacklistEntry) => void;
  banMachine: (m: Machine) => void;
  unbanMachine: (m: Machine) => void;
  resetHwid: (m: Machine) => void;
  resetPassword: (u: User) => void;
  deleteMachine: (m: Machine) => void;
  saveMachine: (m: Machine, d: Partial<Machine>) => void;
  killSession: (s: Session) => void;
  crashSession: (s: Session) => void;
  revokeDownload: (d: Download, reason: string) => void;
  unrevokeDownload: (d: Download) => void;
  deleteDownload: (d: Download) => void;
  saveUser: (u: User | null, d: Partial<User> & { password?: string }, isNew: boolean) => void;
  deleteUser: (u: User) => void;
  saveProduct: (p: Product | null, d: { name: string; code?: string; description?: string }, isNew: boolean) => void;
  saveConfig: (c: Config | null, d: { name?: string; description?: string; public?: boolean; data?: string }, isNew: boolean) => void;
  deleteConfig: (c: Config) => void;
  runScan: (label: string) => void;
  applyAntiShare: (r: AntiShareRules) => void;
}

const AppContext = createContext<AppContextValue | null>(null);
export const useApp = () => {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be used inside <AppProvider>");
  return ctx;
};

const DEFAULT_RULES: AntiShareRules = { maxHwid: 2, maxIp: 4, autoSuspend: false };
export function isShared(l: License, r: AntiShareRules) {
  return l.status === "active" && (l.distinctMachines > r.maxHwid || l.distinctIps > r.maxIp);
}

export function AppProvider({ user, initial, children }: { user: SessionUser; initial: InitialData; children: ReactNode }) {
  const [licenses, setLicenses] = useState(initial.licenses);
  const [users, setUsers] = useState(initial.users);
  const [machines, setMachines] = useState(initial.machines);
  const [sessions, setSessions] = useState(initial.sessions);
  const [downloads, setDownloads] = useState(initial.downloads);
  const [configs, setConfigs] = useState(initial.configs);
  const [blacklist, setBlacklist] = useState(initial.blacklist);
  const [audit, setAudit] = useState(initial.audit);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [confirmState, setConfirmState] = useState<ConfirmOptions | null>(null);
  const [rules, setRules] = useState<AntiShareRules>(DEFAULT_RULES);
  const [products, setProducts] = useState(initial.products);
  const [refreshing, setRefreshing] = useState(false);
  const confirmResolver = useRef<((v: boolean) => void) | null>(null);

  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const toast = useCallback(
    (opts: Omit<Toast, "id">) => {
      const id = ++toastSeq;
      setToasts((t) => [...t, { id, ...opts }]);
      if (!opts.sticky) setTimeout(() => dismissToast(id), opts.duration || 4200);
      return id;
    },
    [dismissToast],
  );

  const confirm = useCallback(
    (opts: ConfirmOptions) =>
      new Promise<boolean>((resolve) => {
        setConfirmState(opts);
        confirmResolver.current = resolve;
      }),
    [],
  );
  const resolveConfirm = useCallback((v: boolean) => {
    setConfirmState(null);
    confirmResolver.current?.(v);
    confirmResolver.current = null;
  }, []);

  const pushAudit = useCallback(
    (entry: AuditDraft) => {
      const e: AuditEntry = {
        id: "aud_" + Math.random().toString(16).slice(2, 12),
        ts: new Date(),
        actor: user.username,
        ip: "",
        ...entry,
      };
      setAudit((a) => [e, ...a]);
    },
    [user.username],
  );

  // Re-pull every dataset from the DB and swap it into local state in one
  // shot — a live refresh of audit/users/licenses/machines/sessions/configs/
  // downloads/products without reloading the page.
  const refresh = useCallback(async () => {
    setRefreshing(true);
    try {
      const d = await srv.refreshPanelData();
      setLicenses(d.licenses);
      setUsers(d.users);
      setMachines(d.machines);
      setSessions(d.sessions);
      setDownloads(d.downloads);
      setConfigs(d.configs);
      setBlacklist(d.blacklist);
      setAudit(d.audit);
      setProducts(d.products);
    } catch (e) {
      toast({ tone: "danger", title: "Actualisation échouée", desc: e instanceof Error ? e.message : String(e) });
    } finally {
      setRefreshing(false);
    }
  }, [toast]);

  // Run a server action; apply the optimistic UI update + toast/audit only
  // when it succeeds, otherwise surface the error as a danger toast.
  const run = useCallback(
    async (fn: () => Promise<unknown>, onSuccess: () => void) => {
      try {
        await fn();
        onSuccess();
      } catch (e) {
        toast({ tone: "danger", title: "Action échouée", desc: e instanceof Error ? e.message : String(e) });
      }
    },
    [toast],
  );
  const actions: Actions = useMemo(
    () => ({
      revokeLicense: (l) =>
        void run(
          () => srv.srvRevokeLicense(l.id, l.key),
          () => {
            setLicenses((ls) => ls.map((x) => (x.id === l.id ? { ...x, status: "revoked", flagged: false } : x)));
            pushAudit({ action: "license.revoke", label: "Licence révoquée", cat: "license", sev: "danger", target: l.key, targetType: "license" });
            toast({ tone: "danger", title: "Licence révoquée", desc: l.key });
          },
        ),
      restoreLicense: (l) =>
        void run(
          () => srv.srvRestoreLicense(l.id, l.key),
          () => {
            setLicenses((ls) => ls.map((x) => (x.id === l.id ? { ...x, status: "active" } : x)));
            pushAudit({ action: "license.restore", label: "Licence réactivée", cat: "license", sev: "success", target: l.key, targetType: "license" });
            toast({ tone: "success", title: "Licence réactivée", desc: l.key });
          },
        ),
      deleteLicense: (l) =>
        void run(
          () => srv.srvDeleteLicense(l.id, l.key),
          () => {
            setLicenses((ls) => ls.filter((x) => x.id !== l.id));
            pushAudit({ action: "license.delete", label: "Licence supprimée", cat: "license", sev: "danger", target: l.key, targetType: "license" });
            toast({ tone: "danger", title: "Licence supprimée", desc: l.key });
          },
        ),
      bulkRevokeLicenses: (rows, clear) =>
        void run(
          () => Promise.all(rows.map((r) => srv.srvRevokeLicense(r.id, r.key))),
          () => {
            const ids = new Set(rows.map((r) => r.id));
            setLicenses((ls) => ls.map((x) => (ids.has(x.id) ? { ...x, status: "revoked", flagged: false } : x)));
            pushAudit({ action: "license.revoke", label: `${rows.length} licences révoquées (bulk)`, cat: "license", sev: "danger", target: `${rows.length} licences`, targetType: "license" });
            toast({ tone: "danger", title: `${rows.length} licences révoquées` });
            clear();
          },
        ),
      extendLicense: (l, days) =>
        void run(
          () => srv.srvExtendLicense(l.id, l.key, days),
          () => {
            setLicenses((ls) => ls.map((x) => (x.id === l.id ? { ...x, status: "active", expiresAt: new Date(Date.now() + days * DAY) } : x)));
            pushAudit({ action: "license.extend", label: `Licence prolongée (+${days}j)`, cat: "license", sev: "info", target: l.key, targetType: "license" });
            toast({ tone: "success", title: "Licence prolongée", desc: `${l.key} · +${days} jours` });
          },
        ),
      suspendLicense: (l) =>
        void run(
          () => srv.srvSuspendLicense(l.id, l.key),
          () => {
            setLicenses((ls) => ls.map((x) => (x.id === l.id ? { ...x, status: "suspended" } : x)));
            pushAudit({ action: "license.suspend", label: "Licence suspendue (anti-partage)", cat: "license", sev: "caution", target: l.key, targetType: "license" });
            toast({ tone: "warning", title: "Licence suspendue", desc: `${l.key} · partage suspecté` });
          },
        ),
      generateLicense: (d) =>
        void run(
          () => srv.srvGenerateLicense({ username: d.username, productCode: d.productCode, lifetime: d.lifetime, expiresAt: d.expiresAt ? d.expiresAt.toISOString() : null }),
          () => {
            const prod = products.find((p) => p.code === d.productCode);
            const key = "WHIP-" + Array.from({ length: 3 }, () => Array.from({ length: 4 }, () => "0123456789ABCDEF"[Math.floor(Math.random() * 16)]).join("")).join("-");
            const lic: License = {
              id: "lic_" + Math.random().toString(16).slice(2, 10),
              key,
              username: d.username || null,
              productCode: d.productCode,
              productName: prod?.name ?? d.productCode,
              status: "active",
              lifetime: d.lifetime,
              expiresAt: d.lifetime ? null : d.expiresAt,
              sessions: 0,
              createdAt: new Date(),
              distinctMachines: 0,
              distinctIps: 0,
              flagged: false,
            };
            setLicenses((ls) => [lic, ...ls]);
            pushAudit({ action: "license.generate", label: "Licence générée", cat: "license", sev: "success", target: key, targetType: "license" });
            toast({ tone: "success", title: "Licence générée", desc: key });
          },
        ),
      blacklistUser: (entry) =>
        void run(
          () => srv.srvBlacklistUser({ username: entry.username, reason: entry.reason, expiresAt: entry.expiresAt ? entry.expiresAt.toISOString() : null }),
          () => {
            const e: BlacklistEntry = { id: "bl_" + Math.random().toString(16).slice(2, 10), by: user.username, blacklistedAt: new Date(), ...entry };
            setBlacklist((b) => [e, ...b]);
            pushAudit({ action: "user.blacklist", label: "Utilisateur blacklisté", cat: "security", sev: "danger", target: entry.username, targetType: "user" });
            toast({ tone: "danger", title: "Utilisateur blacklisté", desc: entry.username });
          },
        ),
      unblacklist: (b) =>
        void run(
          () => srv.srvUnblacklist(b.id, b.username),
          () => {
            setBlacklist((bl) => bl.filter((x) => x.id !== b.id));
            pushAudit({ action: "user.unblacklist", label: "Blacklist levée", cat: "security", sev: "success", target: b.username, targetType: "user" });
            toast({ tone: "success", title: "Blacklist levée", desc: b.username });
          },
        ),
      banMachine: (m) =>
        void run(
          () => srv.srvBanMachine(m.id, m.pcName),
          () => {
            setMachines((ms) => ms.map((x) => (x.id === m.id ? { ...x, status: "banned" } : x)));
            pushAudit({ action: "machine.ban", label: "Machine bannie", cat: "machine", sev: "danger", target: m.pcName, targetType: "machine" });
            toast({ tone: "danger", title: "Machine bannie", desc: m.pcName });
          },
        ),
      unbanMachine: (m) =>
        void run(
          () => srv.srvUnbanMachine(m.id, m.pcName),
          () => {
            setMachines((ms) => ms.map((x) => (x.id === m.id ? { ...x, status: "active" } : x)));
            pushAudit({ action: "machine.unban", label: "Machine réautorisée", cat: "machine", sev: "success", target: m.pcName, targetType: "machine" });
            toast({ tone: "success", title: "Machine réautorisée", desc: m.pcName });
          },
        ),
      // Reset HWID: drops the machine binding; the bot DMs the user to redownload.
      resetHwid: (m) =>
        void run(
          () => srv.srvResetHwid(m.id, m.pcName),
          () => {
            setMachines((ms) => ms.filter((x) => x.id !== m.id));
            pushAudit({ action: "machine.reset_hwid", label: "HWID réinitialisé", cat: "machine", sev: "caution", target: m.pcName, targetType: "machine" });
            toast({ tone: "warning", title: "HWID réinitialisé", desc: `${m.pcName} · l'utilisateur va être prévenu` });
          },
        ),
      // Resets are done by the user via a Discord DM (button + modal). We just
      // ping the bot through Postgres NOTIFY; the bot sends the DM.
      resetPassword: (u) => {
        if (!u.discordId) {
          toast({ tone: "danger", title: "Discord requis", desc: `${u.username} n'a pas de Discord lié.` });
          return;
        }
        void run(
          () => srv.srvResetPasswordRequest(u.id, u.username),
          () => {
            pushAudit({ action: "user.reset_password_request", label: "Demande de reset mot de passe", cat: "user", sev: "caution", target: u.username, targetType: "user" });
            toast({ tone: "success", title: "Demande envoyée", desc: `${u.username} va recevoir un DM Discord` });
          },
        );
      },
      deleteMachine: (m) =>
        void run(
          () => srv.srvDeleteMachine(m.id, m.pcName),
          () => {
            setMachines((ms) => ms.filter((x) => x.id !== m.id));
            pushAudit({ action: "machine.delete", label: "Machine supprimée", cat: "machine", sev: "danger", target: m.pcName, targetType: "machine" });
            toast({ tone: "danger", title: "Machine supprimée", desc: m.pcName });
          },
        ),
      saveMachine: (m, d) =>
        void run(
          () => srv.srvSaveMachine(m.id, { pcName: d.pcName, os: d.os, hwid: d.hwid }),
          () => {
            setMachines((ms) => ms.map((x) => (x.id === m.id ? { ...x, ...d } : x)));
            pushAudit({ action: "machine.edit", label: "Machine modifiée", cat: "machine", sev: "info", target: d.pcName || m.pcName, targetType: "machine" });
            toast({ tone: "success", title: "Machine sauvegardée", desc: d.pcName || m.pcName });
          },
        ),
      killSession: (s) =>
        void run(
          () => srv.srvKillSession(s.id, s.pcName),
          () => {
            setSessions((ss) => ss.map((x) => (x.id === s.id ? { ...x, status: "ended" } : x)));
            pushAudit({ action: "session.kill", label: "Session terminée", cat: "session", sev: "caution", target: s.pcName, targetType: "session" });
            toast({ tone: "warning", title: "Session terminée", desc: `${s.username} · ${s.pcName}` });
          },
        ),
      crashSession: (s) =>
        void run(
          () => srv.srvCrashSession(s.id, s.pcName),
          () => {
            setSessions((ss) => ss.map((x) => (x.id === s.id ? { ...x, status: "ended" } : x)));
            pushAudit({ action: "session.crash", label: "Session crashée (remote)", cat: "session", sev: "danger", target: s.pcName, targetType: "session" });
            toast({ tone: "danger", title: "Session crashée", desc: `${s.username} · ${s.pcName}` });
          },
        ),
      revokeDownload: (d, reason) =>
        void run(
          () => srv.srvRevokeDownload(d.id, reason),
          () => {
            setDownloads((ds) => ds.map((x) => (x.id === d.id ? { ...x, status: "revoked" } : x)));
            pushAudit({ action: "download.revoke", label: "Téléchargement révoqué", cat: "download", sev: "danger", target: d.id.slice(0, 12), targetType: "download" });
            toast({ tone: "danger", title: "Téléchargement révoqué" });
          },
        ),
      unrevokeDownload: (d) =>
        void run(
          () => srv.srvUnrevokeDownload(d.id),
          () => {
            setDownloads((ds) => ds.map((x) => (x.id === d.id ? { ...x, status: "active" } : x)));
            pushAudit({ action: "download.activate", label: "Téléchargement réactivé", cat: "download", sev: "success", target: d.id.slice(0, 12), targetType: "download" });
            toast({ tone: "success", title: "Téléchargement réactivé" });
          },
        ),
      deleteDownload: (d) =>
        void run(
          () => srv.srvDeleteDownload(d.id),
          () => {
            setDownloads((ds) => ds.filter((x) => x.id !== d.id));
            pushAudit({ action: "download.delete", label: "Téléchargement supprimé", cat: "download", sev: "danger", target: d.id.slice(0, 12), targetType: "download" });
            toast({ tone: "danger", title: "Téléchargement supprimé" });
          },
        ),
      saveUser: (u, d, isNew) =>
        void run(
          () => srv.srvSaveUser({ id: u?.id, username: (d.username ?? u?.username) || "", discordId: d.discordId, grade: d.grade, password: d.password }, isNew),
          () => {
            if (isNew) {
              const nu: User = { id: "usr_" + Math.random().toString(16).slice(2, 10), createdAt: new Date(), avatar: "#2563eb", licenseCount: 0, machineCount: 0, lastSeen: new Date(), discordId: "", username: "", grade: "user", ...d } as User;
              setUsers((us) => [nu, ...us]);
              pushAudit({ action: "user.create", label: "Utilisateur créé", cat: "user", sev: "success", target: d.username || "", targetType: "user" });
              toast({ tone: "success", title: "Utilisateur créé", desc: d.username });
            } else if (u) {
              setUsers((us) => us.map((x) => (x.id === u.id ? { ...x, ...d } : x)));
              pushAudit({ action: "user.edit", label: "Utilisateur modifié", cat: "user", sev: "info", target: d.username || u.username, targetType: "user" });
              toast({ tone: "success", title: "Utilisateur sauvegardé", desc: d.username || u.username });
            }
          },
        ),
      deleteUser: (u) =>
        void run(
          () => srv.srvDeleteUser(u.id, u.username),
          () => {
            setUsers((us) => us.filter((x) => x.id !== u.id));
            pushAudit({ action: "user.delete", label: "Utilisateur supprimé", cat: "user", sev: "danger", target: u.username, targetType: "user" });
            toast({ tone: "danger", title: "Utilisateur supprimé", desc: u.username });
          },
        ),
      saveProduct: (p, d, isNew) =>
        void run(
          () => srv.srvSaveProduct({ id: p?.id, code: d.code ?? p?.code ?? "", name: d.name, description: d.description ?? p?.description }, isNew),
          () => {
            pushAudit({ action: isNew ? "product.create" : "product.edit", label: isNew ? "Produit créé" : "Produit modifié", cat: "product", sev: isNew ? "success" : "info", target: d.name, targetType: "product" });
            toast({ tone: "success", title: isNew ? "Produit créé" : "Produit sauvegardé", desc: d.name });
          },
        ),
      saveConfig: (c, d, isNew) =>
        void run(
          () => srv.srvSaveConfig({ id: c?.id, name: (d.name ?? c?.name) || "", description: d.description ?? c?.description, isPublic: d.public ?? c?.public ?? false, data: d.data }, isNew),
          () => {
            if (isNew) {
              const nc: Config = { id: Math.random().toString(16).slice(2, 10).toUpperCase(), createdAt: new Date(), version: "v2.0", enabledCount: 0, name: d.name || "", owner: user.username, description: d.description || "", public: d.public ?? false };
              setConfigs((cs) => [nc, ...cs]);
              pushAudit({ action: "config.create", label: "Configuration créée", cat: "config", sev: "success", target: d.name || "", targetType: "config" });
              toast({ tone: "success", title: "Configuration créée", desc: d.name });
            } else if (c) {
              setConfigs((cs) => cs.map((x) => (x.id === c.id ? { ...x, name: d.name ?? x.name, description: d.description ?? x.description, public: d.public ?? x.public } : x)));
              pushAudit({ action: "config.edit", label: "Configuration modifiée", cat: "config", sev: "info", target: d.name || c.name, targetType: "config" });
              toast({ tone: "success", title: "Configuration sauvegardée", desc: d.name || c.name });
            }
          },
        ),
      deleteConfig: (c) =>
        void run(
          () => srv.srvDeleteConfig(c.id, c.name),
          () => {
            setConfigs((cs) => cs.filter((x) => x.id !== c.id));
            pushAudit({ action: "config.delete", label: "Configuration supprimée", cat: "config", sev: "danger", target: c.name, targetType: "config" });
            toast({ tone: "danger", title: "Configuration supprimée", desc: c.name });
          },
        ),
      runScan: (label) => {
        void srv.srvLogScan(label).catch(() => {});
        pushAudit({ action: "scan.run", label: "Scan leak exécuté", cat: "security", sev: "info", target: label, targetType: "security" });
      },
      applyAntiShare: (newRules) => {
        // TODO: anti-share thresholds are runtime-only (not persisted server-side yet).
        let suspended = 0;
        setLicenses((ls) =>
          ls.map((x) => {
            const shared = isShared(x, newRules);
            if (shared && newRules.autoSuspend) {
              suspended++;
              return { ...x, flagged: true, status: "suspended" as const };
            }
            return { ...x, flagged: shared };
          }),
        );
        const label = `Règle anti-partage appliquée (${newRules.maxHwid} HWID / ${newRules.maxIp} IP${newRules.autoSuspend ? ", auto-suspension" : ""})`;
        void srv.srvLogAntiShare(label).catch(() => {});
        pushAudit({ action: "rule.antishare", label, cat: "security", sev: newRules.autoSuspend ? "caution" : "info", target: "global", targetType: "security" });
        toast({ tone: newRules.autoSuspend ? "warning" : "success", title: "Règle anti-partage appliquée", desc: newRules.autoSuspend && suspended ? `${suspended} licence(s) suspendue(s)` : "Seuils mis à jour" });
      },
    }),
    [run, pushAudit, toast, user.username, products],
  );

  const value: AppContextValue = {
    user,
    data: { licenses, users, machines, sessions, downloads, configs, blacklist, audit, products },
    rules,
    setRules,
    toast,
    confirm,
    pushAudit,
    refresh,
    refreshing,
    actions,
  };

  return (
    <AppContext.Provider value={value}>
      {children}
      <Toaster toasts={toasts} dismiss={dismissToast} />
      <ConfirmDialog data={confirmState} onResolve={resolveConfirm} />
    </AppContext.Provider>
  );
}
