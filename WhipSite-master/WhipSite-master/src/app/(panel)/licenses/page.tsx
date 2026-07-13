"use client";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Plus, Ban, Check, Clock, Trash2 as Trash, KeyRound, ShieldAlert, Filter, X, Download } from "lucide-react";
import { useApp } from "@/components/app-provider";
import { PageHeader, IconButton, StatusBadge, Copyable, Field } from "@/components/ui/primitives";
import { RefreshButton } from "@/components/ui/RefreshButton";
import { DataTable, type Column, type Filter as TFilter, type BulkAction } from "@/components/ui/DataTable";
import { Drawer } from "@/components/ui/overlays";
import { DrawerSection } from "@/components/ui/StatCard";
import { GenerateModal } from "@/components/shared-modals";
import { exportCsv } from "@/lib/csv";
import { fmtDate, fmtNum, timeAgo, NOW, DAY } from "@/lib/utils";
import type { License } from "@/lib/types";

// Anti-share / "partage suspecté" surfaces are parked for now. The flagged
// data + logic stay in place — flip to true to bring the UI back.
const SHOW_ANTISHARE = false;

function LicenseDrawer({ lic, onClose }: { lic: License; onClose: () => void }) {
  const { data, actions, confirm } = useApp();
  const ses = data.sessions.filter((s) => s.licenseKey === lic.key).slice(0, 5);
  return (
    <Drawer eyebrow="Licence" title={lic.key} onClose={onClose} width={480}
      footer={<>
        {lic.status === "active"
          ? <button className="abs-btn abs-btn--danger abs-btn--md" onClick={async () => { if (await confirm({ title: "Révoquer la licence ?", message: <>La clé <strong>{lic.key}</strong> cessera de valider les sessions immédiatement.</>, confirmLabel: "Révoquer" })) { actions.revokeLicense(lic); onClose(); } }}><Ban size={15} />Révoquer</button>
          : <button className="abs-btn abs-btn--primary abs-btn--md" onClick={() => { actions.restoreLicense(lic); onClose(); }}><Check size={15} />Réactiver</button>}
        <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={() => actions.extendLicense(lic, 30)}><Clock size={15} />+30j</button>
      </>}>
      {SHOW_ANTISHARE && lic.flagged && (
        <div className="whip-warnbox">
          <ShieldAlert size={17} />
          <div><strong>Partage suspecté</strong><span>Cette clé est utilisée sur {lic.distinctMachines} machines et {lic.distinctIps} adresses IP distinctes.</span></div>
        </div>
      )}
      <div className="whip-keyblock"><KeyRound size={16} /><span className="whip-mono">{lic.key}</span><Copyable value={lic.key} display={<KeyRound size={14} />} /></div>
      <div className="whip-fieldgrid whip-fieldgrid--2">
        <Field label="Statut"><StatusBadge status={lic.status} /></Field>
        <Field label="Produit">{lic.productName}</Field>
        <Field label="Utilisateur">{lic.username || <span className="whip-muted">non assignée</span>}</Field>
        <Field label="Expiration">{lic.lifetime ? <span className="abs-badge abs-badge--brand">illimité</span> : fmtDate(lic.expiresAt)}</Field>
        <Field label="Sessions cumulées">{fmtNum(lic.sessions)}</Field>
        <Field label="Machines liées">{lic.distinctMachines}</Field>
        <Field label="IP distinctes">{lic.distinctIps}</Field>
        <Field label="Créée le">{fmtDate(lic.createdAt)}</Field>
      </div>
      <DrawerSection title="Sessions récentes" count={ses.length}>
        {ses.length === 0 ? <p className="whip-muted">Aucune session.</p> : ses.map((s) => <div key={s.id} className="whip-minirow"><span>{s.pcName}</span><span className="whip-mono whip-mono--dim">{timeAgo(s.startedAt)}</span></div>)}
      </DrawerSection>
    </Drawer>
  );
}

function LicensesInner() {
  const { data, actions, confirm } = useApp();
  const params = useSearchParams();
  const [gen, setGen] = useState(false);
  const [drawer, setDrawer] = useState<License | null>(null);
  const [preset, setPreset] = useState<string | null>(null);

  useEffect(() => {
    if (params.get("action") === "create") setGen(true);
    const focus = params.get("focus");
    if (focus) { const l = data.licenses.find((x) => x.id === focus); if (l) setDrawer(l); }
    const p = params.get("preset");
    if (p) setPreset(p);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  let rows = data.licenses;
  if (preset === "flagged") rows = rows.filter((l) => l.flagged);
  else if (preset?.startsWith("user:")) rows = rows.filter((l) => l.username === preset.slice(5));

  const columns: Column<License>[] = [
    { key: "key", label: "Clé de licence", sortable: true, render: (r) => <span className="whip-keycell"><span className="whip-keycell__icon"><KeyRound size={14} /></span><Copyable value={r.key} />{SHOW_ANTISHARE && r.flagged && <span className="whip-flag" title="Partage suspecté"><ShieldAlert size={13} /></span>}</span> },
    { key: "username", label: "Utilisateur / Produit", render: (r) => <span className="whip-twoline"><span className="whip-twoline__a">{r.username || "NON ASSIGNÉ"}</span><span className="whip-twoline__b">{r.productName}</span></span> },
    { key: "status", label: "Statut", width: 110, render: (r) => <StatusBadge status={r.status} /> },
    { key: "expiresAt", label: "Expiration", width: 130, sortable: true, sortValue: (r) => (r.lifetime ? Infinity : new Date(r.expiresAt || 0).getTime()), render: (r) => r.lifetime ? <span className="whip-illimite"><Clock size={12} />illimité</span> : <span className="whip-mono whip-mono--dim" style={{ fontSize: 12 }}>{fmtDate(r.expiresAt)}</span> },
    { key: "sessions", label: "Sessions", align: "center", width: 100, sortable: true, render: (r) => <span className="whip-countpill whip-countpill--muted">{fmtNum(r.sessions)}</span> },
  ];
  const filters: TFilter<License>[] = [
    { key: "status", label: "Statut", options: [["active", "Active"], ["revoked", "Révoquée"], ["expired", "Expirée"], ["suspended", "Suspendue"]].map(([value, label]) => ({ value, label })) },
    { key: "productCode", label: "Produit", options: data.products.map((p) => ({ value: p.code, label: p.name })) },
    // Parked: "Anti-partage" filter — see SHOW_ANTISHARE.
    ...(SHOW_ANTISHARE ? [{ key: "flagged", label: "Anti-partage", options: [{ value: "yes", label: "Partage suspecté" }], match: (r: License, v: string) => (v === "yes" ? r.flagged : true) }] : []),
  ];
  const rowActions = (r: License) => (
    <>
      {r.status === "active"
        ? <IconButton tone="danger" title="Révoquer" icon={<Ban size={15} />} onClick={async () => { if (await confirm({ title: "Révoquer la licence ?", message: <>La clé <strong>{r.key}</strong> cessera de valider les sessions.</>, confirmLabel: "Révoquer" })) actions.revokeLicense(r); }} />
        : <IconButton tone="success" title="Réactiver" icon={<Check size={15} />} onClick={() => actions.restoreLicense(r)} />}
      <IconButton tone="info" title="Prolonger +30j" icon={<Clock size={15} />} onClick={() => actions.extendLicense(r, 30)} />
      <IconButton tone="danger" title="Supprimer" icon={<Trash size={15} />} onClick={async () => { if (await confirm({ title: "Supprimer la licence ?", message: <>La clé <strong>{r.key}</strong> sera supprimée définitivement.</>, confirmLabel: "Supprimer" })) actions.deleteLicense(r); }} />
    </>
  );
  const bulkActions: BulkAction<License>[] = [
    { label: "Révoquer", icon: <Ban size={14} />, tone: "danger", onClick: async (sel, clear) => { if (await confirm({ title: `Révoquer ${sel.length} licences ?`, message: "Toutes les sessions associées seront invalidées.", confirmLabel: "Révoquer" })) actions.bulkRevokeLicenses(sel, clear); } },
    { label: "Exporter CSV", icon: <Download size={14} />, onClick: (sel) => exportCsv(sel, "licences") },
  ];

  return (
    <>
      <PageHeader title="Licences" eyebrow="Whip or get whipped" actions={<><RefreshButton /><button className="abs-btn abs-btn--primary abs-btn--md" onClick={() => setGen(true)}><Plus size={16} />Générer</button></>} />
      {preset && (
        <div className="whip-presetbar">
          <Filter size={14} />Filtre : <strong>{preset === "flagged" ? "partage suspecté" : preset.replace("user:", "utilisateur ")}</strong>
          <button onClick={() => setPreset(null)}><X size={13} />Retirer</button>
        </div>
      )}
      <DataTable columns={columns} rows={rows} rowKey="id" searchKeys={["key", "username", "productName"]} searchPlaceholder="Rechercher par clé, utilisateur ou produit…" filters={filters} rowActions={rowActions} bulkActions={bulkActions} onRowClick={(r) => setDrawer(r)} pageSize={11} defaultSort={{ key: "expiresAt", dir: 1 }} />
      {gen && <GenerateModal onClose={() => setGen(false)} />}
      {drawer && <LicenseDrawer lic={drawer} onClose={() => setDrawer(null)} />}
    </>
  );
}

export default function LicensesPage() {
  return (
    <Suspense fallback={null}>
      <LicensesInner />
    </Suspense>
  );
}
