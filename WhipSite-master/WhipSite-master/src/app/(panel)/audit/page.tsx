"use client";
import { useMemo, useState } from "react";
import { ScrollText, AlertTriangle, User as UserIcon } from "lucide-react";
import { useApp } from "@/components/app-provider";
import { PageHeader, Avatar, Field } from "@/components/ui/primitives";
import { RefreshButton } from "@/components/ui/RefreshButton";
import { StatCard } from "@/components/ui/StatCard";
import { DataTable, type Column, type Filter as TFilter } from "@/components/ui/DataTable";
import { Drawer } from "@/components/ui/overlays";
import { AUDIT_CAT, SEV_COLOR } from "@/components/blocks";
import { fmtNum, fmtDateTime, NOW, DAY } from "@/lib/utils";
import type { AuditEntry, AuditCategory } from "@/lib/types";

export default function AuditPage() {
  const { data } = useApp();
  const [detail, setDetail] = useState<AuditEntry | null>(null);
  const todayCount = data.audit.filter((e) => NOW.getTime() - new Date(e.ts).getTime() < DAY).length;
  const destructive = data.audit.filter((e) => e.sev === "danger").length;
  const actorCount = useMemo(() => {
    const m: Record<string, number> = {};
    data.audit.forEach((e) => (m[e.actor] = (m[e.actor] || 0) + 1));
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [data.audit]);

  const columns: Column<AuditEntry>[] = [
    { key: "ts", label: "Horodatage", sortable: true, width: 168, sortValue: (r) => new Date(r.ts).getTime(), render: (r) => <span className="whip-mono whip-mono--dim" style={{ fontSize: 12 }}>{fmtDateTime(r.ts)}</span> },
    { key: "actor", label: "Acteur", sortable: true, width: 150, render: (r) => <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><Avatar name={r.actor} size={24} />{r.actor}</span> },
    { key: "label", label: "Action", render: (r) => <span className="whip-auditcell"><span className="whip-auditcell__dot" style={{ background: SEV_COLOR[r.sev] }} />{r.label}</span> },
    { key: "cat", label: "Catégorie", width: 130, render: (r) => { const m = AUDIT_CAT[r.cat]; const I = m.icon; return <span className="whip-catpill"><I size={12} />{m.label}</span>; } },
    { key: "target", label: "Cible", width: 220, render: (r) => <span className="whip-mono" style={{ fontSize: 12 }}>{r.target}</span> },
    { key: "ip", label: "IP", width: 130, render: (r) => <span className="whip-mono whip-mono--dim" style={{ fontSize: 12 }}>{r.ip}</span> },
  ];
  const filters: TFilter<AuditEntry>[] = [
    { key: "cat", label: "Catégorie", options: (Object.entries(AUDIT_CAT) as [AuditCategory, { label: string }][]).map(([k, v]) => ({ value: k, label: v.label })) },
    { key: "sev", label: "Sévérité", options: [["danger", "Destructive"], ["caution", "Attention"], ["warning", "Avertissement"], ["success", "Succès"], ["info", "Info"], ["neutral", "Neutre"]].map(([value, label]) => ({ value, label })) },
    { key: "actor", label: "Acteur", options: actorCount.map(([a]) => ({ value: a, label: a })) },
  ];

  return (
    <>
      <PageHeader title="Journal d'audit" eyebrow="Traçabilité · qui a fait quoi" actions={<RefreshButton />} />
      <div className="whip-statgrid whip-statgrid--3" style={{ marginBottom: 18 }}>
        <StatCard icon={<ScrollText size={20} />} label="Événements (24h)" value={fmtNum(todayCount)} tone="primary" />
        <StatCard icon={<AlertTriangle size={20} />} label="Actions destructrices" value={fmtNum(destructive)} tone="danger" />
        <StatCard icon={<UserIcon size={20} />} label="Acteur le plus actif" value={actorCount[0]?.[0] || "—"} tone="purple" />
      </div>
      <DataTable
        columns={columns}
        rows={data.audit}
        rowKey="id"
        searchKeys={["actor", "label", "note", "target", "ip", "cat"]}
        searchPlaceholder="Rechercher par acteur, action, cible, IP…"
        filters={filters}
        pageSize={14}
        dense
        defaultSort={{ key: "ts", dir: -1 }}
        onRowClick={(r) => setDetail(r)}
      />
      {detail && (
        <Drawer eyebrow="Événement d'audit" title={detail.label} onClose={() => setDetail(null)} width={440}>
          <div className="whip-fieldgrid">
            <Field label="Action (code)" mono>{detail.action}</Field>
            {detail.note && <Field label="Détails">{detail.note}</Field>}
            <Field label="Sévérité"><span className="whip-auditcell"><span className="whip-auditcell__dot" style={{ background: SEV_COLOR[detail.sev] }} />{detail.sev}</span></Field>
            <Field label="Acteur"><span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><Avatar name={detail.actor} size={24} />{detail.actor}</span></Field>
            <Field label="Catégorie">{AUDIT_CAT[detail.cat].label}</Field>
            <Field label="Cible" mono>{detail.target}</Field>
            <Field label="Adresse IP" mono>{detail.ip}</Field>
            <Field label="Horodatage" mono>{fmtDateTime(detail.ts)}</Field>
            <Field label="ID événement" mono>{detail.id}</Field>
          </div>
        </Drawer>
      )}
    </>
  );
}
