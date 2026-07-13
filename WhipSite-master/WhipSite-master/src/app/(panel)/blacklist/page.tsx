"use client";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Plus, RotateCcw, Shield, ShieldCheck } from "lucide-react";
import { useApp } from "@/components/app-provider";
import { PageHeader, IconButton, Avatar } from "@/components/ui/primitives";
import { RefreshButton } from "@/components/ui/RefreshButton";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { BlacklistModal } from "@/components/shared-modals";
import { fmtDate } from "@/lib/utils";
import type { BlacklistEntry } from "@/lib/types";

function BlacklistInner() {
  const { data, actions, confirm } = useApp();
  const params = useSearchParams();
  const [create, setCreate] = useState(false);
  useEffect(() => {
    if (params.get("action") === "create") setCreate(true);
  }, [params]);

  const columns: Column<BlacklistEntry>[] = [
    { key: "username", label: "Utilisateur", sortable: true, render: (r) => <span className="whip-usercell"><Avatar name={r.username} size={28} color="#f87171" /><span className="whip-usercell__name">{r.username}</span></span> },
    { key: "reason", label: "Raison", render: (r) => <span style={{ color: "var(--whip-fg-muted)" }}>{r.reason}</span> },
    { key: "blacklistedAt", label: "Blacklisté le", width: 150, sortable: true, sortValue: (r) => new Date(r.blacklistedAt).getTime(), render: (r) => <span className="whip-mono whip-mono--dim" style={{ fontSize: 12 }}>{fmtDate(r.blacklistedAt)}</span> },
    { key: "expiresAt", label: "Expiration", width: 140, render: (r) => (r.expiresAt ? <span className="whip-mono" style={{ fontSize: 12 }}>{fmtDate(r.expiresAt)}</span> : <span className="abs-badge abs-badge--revoked">permanent</span>) },
    { key: "by", label: "Par", width: 140, render: (r) => <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}><Avatar name={r.by} size={22} /><span style={{ fontSize: 12 }}>{r.by}</span></span> },
  ];
  const rowActions = (r: BlacklistEntry) => (
    <IconButton tone="success" title="Lever le blacklist" icon={<RotateCcw size={15} />} onClick={async () => { if (await confirm({ title: "Lever le blacklist ?", message: <>L&apos;utilisateur <strong>{r.username}</strong> retrouvera l&apos;accès au client.</>, confirmLabel: "Lever", tone: "primary" })) actions.unblacklist(r); }} />
  );
  return (
    <>
      <PageHeader title="Blacklist" eyebrow="Gestion des utilisateurs bannis" danger
        actions={<>
          <RefreshButton />
          <button className="abs-btn abs-btn--md whip-btn-destructive" onClick={() => setCreate(true)}><Plus size={16} />Blacklister</button>
        </>} />
      <DataTable
        columns={columns}
        rows={data.blacklist}
        rowKey="id"
        searchKeys={["username", "reason", "by"]}
        searchPlaceholder="Rechercher par utilisateur, raison ou auteur…"
        rowActions={rowActions}
        pageSize={12}
        defaultSort={{ key: "blacklistedAt", dir: -1 }}
        emptyState={{ icon: <ShieldCheck size={24} />, title: "Aucun utilisateur blacklisté", hint: "La liste est vide — personne n'est banni actuellement.", action: <button className="abs-btn abs-btn--md whip-btn-destructive" onClick={() => setCreate(true)}><Plus size={16} />Blacklister un utilisateur</button> }}
      />
      {create && <BlacklistModal onClose={() => setCreate(false)} />}
    </>
  );
}

export default function BlacklistPage() {
  return (
    <Suspense fallback={null}>
      <BlacklistInner />
    </Suspense>
  );
}
