"use client";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { KeyRound, UserPlus, Shield, FileCode, Fingerprint, ScrollText, Bell, Sliders } from "lucide-react";
import { useApp, isShared } from "@/components/app-provider";
import { Constellation } from "./Constellation";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { CommandPalette } from "./CommandPalette";
import { AlertsPanel, AntiShareModal } from "./AlertsPanel";
import { computeAlerts, type Alert } from "@/lib/alerts";
import { NOW, DAY, timeAgo } from "@/lib/utils";

export function Shell({ children }: { children: ReactNode }) {
  const router = useRouter();
  const { data, actions, rules, setRules } = useApp();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [alertsOpen, setAlertsOpen] = useState(false);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [dismissed, setDismissed] = useState<Set<string>>(() => new Set());

  const seededAlerts = useMemo<Alert[]>(() => {
    const cb = data.users.find((u) => u.username === "singerieGOAT") ?? data.users[5];
    const leakDl = data.downloads.find((d) => d.status === "revoked") ?? data.downloads[0];
    const alerts: Alert[] = [];
    if (cb) alerts.push({
      id: "bill_1",
      sev: "danger",
      icon: "billing",
      kind: "billing",
      username: cb.username,
      ts: new Date(NOW.getTime() - 42 * 60000),
      title: "Chargeback Stripe",
      desc: `${cb.username} · 24,99 € contestés — licence Whip Client`,
      actions: [
        { label: "Révoquer licence", type: "cb_revoke", tone: "danger" },
        { label: "Blacklister", type: "cb_blacklist", tone: "danger" },
      ],
    });
    if (leakDl) alerts.push({
      id: "leak_1",
      sev: "danger",
      icon: "leak",
      kind: "leak",
      username: leakDl.username,
      download: leakDl,
      ts: new Date(NOW.getTime() - 3 * 3600 * 1000),
      title: "Leak détecté (scan watermark)",
      desc: `Source identifiée : ${leakDl.username} · ${leakDl.productName}`,
      actions: [
        { label: "Blacklister", type: "leak_blacklist", tone: "danger" },
        { label: "Scan Leak", type: "leak_view" },
      ],
    });
    return alerts;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const alerts = useMemo(
    () => computeAlerts(data, rules, dismissed, seededAlerts),
    [data, rules, dismissed, seededAlerts],
  );
  const dismissAlert = useCallback((id: string) => setDismissed((d) => new Set(d).add(id)), []);
  const dismissAllAlerts = useCallback(
    () => setDismissed((d) => new Set([...d, ...alerts.map((a) => a.id)])),
    [alerts],
  );
  const sharedCount = useCallback((r: typeof rules) => data.licenses.filter((l) => isShared(l, r)).length, [data.licenses]);

  const handleAlertAction = useCallback(
    (a: Alert, type: string) => {
      if (type === "view" && a.license) {
        setAlertsOpen(false);
        router.push(`/licenses?focus=${a.license.id}`);
      } else if (type === "suspend" && a.license) {
        actions.suspendLicense(a.license);
        dismissAlert(a.id);
      } else if (type === "extend" && a.license) {
        actions.extendLicense(a.license, 30);
        dismissAlert(a.id);
      } else if (type === "cb_revoke" && a.username) {
        const l = data.licenses.find((x) => x.username === a.username && x.status === "active");
        if (l) actions.revokeLicense(l);
        dismissAlert(a.id);
      } else if ((type === "cb_blacklist" || type === "leak_blacklist") && a.username) {
        actions.blacklistUser({
          username: a.username,
          reason: type === "leak_blacklist" ? "Leak du client (alerte)" : "Chargeback Stripe",
          expiresAt: null,
        });
        dismissAlert(a.id);
      } else if (type === "leak_view") {
        setAlertsOpen(false);
        router.push("/scanleak");
      }
    },
    [actions, data.licenses, router, dismissAlert],
  );

  const paletteActions = useMemo(
    () => [
      { id: "gen-lic", label: "Générer une licence", icon: KeyRound, run: () => router.push("/licenses?action=create") },
      { id: "add-user", label: "Ajouter un utilisateur", icon: UserPlus, run: () => router.push("/users?action=create") },
      { id: "blacklist", label: "Blacklister un utilisateur", icon: Shield, run: () => router.push("/blacklist?action=create") },
      { id: "new-config", label: "Nouvelle configuration", icon: FileCode, run: () => router.push("/configs?action=create") },
      { id: "scan", label: "Lancer un scan leak", icon: Fingerprint, run: () => router.push("/scanleak") },
      { id: "antishare", label: "Régler l'anti-partage", icon: Sliders, run: () => setRulesOpen(true) },
      { id: "alerts", label: "Ouvrir le centre d'alertes", icon: Bell, run: () => setAlertsOpen(true) },
      { id: "audit", label: "Ouvrir le journal d'audit", icon: ScrollText, run: () => router.push("/audit") },
    ],
    [router],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const counts = useMemo(() => {
    const dayAgo = Date.now() - 24 * 3600 * 1000;
    return {
      sessions: data.sessions.filter((s) => s.status === "active").length,
      audit: data.audit.filter((e) => new Date(e.ts).getTime() >= dayAgo).length,
    };
  }, [data.sessions, data.audit]);
  const expiringSoon = data.licenses.filter(
    (l) => !l.lifetime && l.expiresAt && new Date(l.expiresAt) > NOW && new Date(l.expiresAt).getTime() - NOW.getTime() < 14 * DAY,
  ).length;
  const notifCount = expiringSoon + data.licenses.filter((l) => l.flagged).length;

  return (
    <div className="whip-app">
      <Constellation />
      <Sidebar counts={counts} />
      <main className="whip-main">
        <Topbar onOpenPalette={() => setPaletteOpen(true)} notifCount={notifCount} onBell={() => setAlertsOpen(true)} />
        <div className="whip-content">
          <div className="whip-page">{children}</div>
        </div>
      </main>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} actions={paletteActions} />
      {alertsOpen && (
        <AlertsPanel
          alerts={alerts}
          rules={rules}
          timeAgo={timeAgo}
          onClose={() => setAlertsOpen(false)}
          onDismiss={dismissAlert}
          onDismissAll={dismissAllAlerts}
          onAction={handleAlertAction}
          onOpenRules={() => {
            setAlertsOpen(false);
            setRulesOpen(true);
          }}
        />
      )}
      {rulesOpen && (
        <AntiShareModal
          rules={rules}
          sharedCount={sharedCount}
          onClose={() => setRulesOpen(false)}
          onApply={(r) => {
            setRules(r);
            actions.applyAntiShare(r);
          }}
        />
      )}
    </div>
  );
}
