"use client";
import { useState } from "react";
import { Pencil, Ban, Check, Trash2 as Trash, Cpu, RefreshCw, Monitor, User as UserIcon, Clock, Download } from "lucide-react";
import { useApp } from "@/components/app-provider";
import { PageHeader, IconButton, StatusBadge, Copyable, FormRow } from "@/components/ui/primitives";
import { RefreshButton } from "@/components/ui/RefreshButton";
import { DataTable, type Column, type Filter as TFilter, type BulkAction } from "@/components/ui/DataTable";
import { Modal } from "@/components/ui/overlays";
import { Dropdown } from "@/components/ui/inputs";
import { SpecsView } from "@/components/shared-modals";
import { exportCsv } from "@/lib/csv";
import { fmtDateTime, shortHwid, NOW, DAY } from "@/lib/utils";
import type { Machine } from "@/lib/types";

function MachineModal({ machine, onClose }: { machine: Machine; onClose: () => void }) {
  const { data, actions } = useApp();
  const [f, setF] = useState({ pcName: machine.pcName, hwid: machine.hwid, username: machine.username, os: machine.os });
  return (
    <Modal eyebrow="machine" title="Modifier la machine" onClose={onClose} size="md"
      footer={<>
        <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={onClose}>Annuler</button>
        <button className="abs-btn abs-btn--primary abs-btn--md" onClick={() => { actions.saveMachine(machine, f); onClose(); }}>Sauvegarder</button>
      </>}>
      <div className="whip-form">
        <FormRow label="Nom du PC"><input className="abs-input abs-input--mono" value={f.pcName} onChange={(e) => setF((s) => ({ ...s, pcName: e.target.value }))} /></FormRow>
        <FormRow label="HWID (Hardware ID)"><input className="abs-input abs-input--mono" value={f.hwid} onChange={(e) => setF((s) => ({ ...s, hwid: e.target.value }))} /></FormRow>
        <FormRow label="Utilisateur"><Dropdown value={f.username} onChange={(v) => setF((s) => ({ ...s, username: v }))} options={data.users.map((u) => ({ value: u.username, label: u.username, icon: <UserIcon size={15} /> }))} /></FormRow>
        <FormRow label="Système d'exploitation"><input className="abs-input abs-input--mono" value={f.os} onChange={(e) => setF((s) => ({ ...s, os: e.target.value }))} /></FormRow>
      </div>
    </Modal>
  );
}

export default function MachinesPage() {
  const { data, actions, confirm } = useApp();
  const [modal, setModal] = useState<Machine | null>(null);
  const [specs, setSpecs] = useState<Machine | null>(null);

  const columns: Column<Machine>[] = [
    { key: "pcName", label: "Appareil (PC Name)", sortable: true, render: (r) => <span className="whip-usercell"><span className="whip-machicon"><Monitor size={16} /></span><span className="whip-usercell__name whip-mono">{r.pcName}</span></span> },
    { key: "username", label: "Utilisateur", width: 160, render: (r) => <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}><UserIcon size={13} style={{ color: "var(--whip-fg-subtle)" }} />{r.username}</span> },
    { key: "hwid", label: "ID matériel (HWID)", width: 160, render: (r) => <Copyable value={r.hwid} display={shortHwid(r.hwid)} /> },
    { key: "os", label: "OS", width: 150, render: (r) => <span className="whip-ospill">{r.os}</span> },
    { key: "lastActivity", label: "Dernière activité", width: 150, sortable: true, sortValue: (r) => new Date(r.lastActivity).getTime(), render: (r) => { const old = NOW.getTime() - new Date(r.lastActivity).getTime() > 3 * DAY; return <span className="whip-mono" style={{ fontSize: 12, color: old ? "var(--whip-fg-subtle)" : "var(--whip-fg-muted)" }}><Clock size={11} style={{ marginRight: 5, verticalAlign: -1 }} />{fmtDateTime(r.lastActivity)}</span>; } },
    { key: "status", label: "Statut", width: 100, render: (r) => <StatusBadge status={r.status} /> },
  ];
  const filters: TFilter<Machine>[] = [
    { key: "status", label: "Statut", options: [["active", "Active"], ["banned", "Bannie"]].map(([value, label]) => ({ value, label })) },
    { key: "os", label: "OS", options: [...new Set(data.machines.map((m) => m.os))].map((o) => ({ value: o, label: o.replace("Windows ", "Win ") })) },
  ];
  const rowActions = (r: Machine) => (
    <>
      <IconButton tone="info" title="Specs du PC" icon={<Cpu size={15} />} onClick={() => setSpecs(r)} />
      <IconButton title="Éditer" icon={<Pencil size={15} />} onClick={() => setModal(r)} />
      {r.status === "active"
        ? <IconButton tone="danger" title="Bannir" icon={<Ban size={15} />} onClick={async () => { if (await confirm({ title: "Bannir la machine ?", message: <>Le HWID <strong>{shortHwid(r.hwid)}</strong> sera bloqué et ne pourra plus lancer le client.</>, confirmLabel: "Bannir" })) actions.banMachine(r); }} />
        : <IconButton tone="success" title="Réautoriser" icon={<Check size={15} />} onClick={() => actions.unbanMachine(r)} />}
      <IconButton tone="info" title="Reset HWID" icon={<RefreshCw size={15} />} onClick={async () => { if (await confirm({ title: "Réinitialiser le HWID ?", message: <>Le HWID de <strong>{r.pcName}</strong> sera réinitialisé.</>, confirmLabel: "Réinitialiser", tone: "danger" })) actions.resetHwid(r); }} />
      <IconButton tone="danger" title="Supprimer" icon={<Trash size={15} />} onClick={async () => { if (await confirm({ title: "Supprimer la machine ?", message: <>L&apos;enregistrement <strong>{r.pcName}</strong> sera supprimé.</>, confirmLabel: "Supprimer" })) actions.deleteMachine(r); }} />
    </>
  );
  const bulkActions: BulkAction<Machine>[] = [
    { label: "Bannir", icon: <Ban size={14} />, tone: "danger", onClick: async (sel, clear) => { if (await confirm({ title: `Bannir ${sel.length} machines ?`, message: "Les HWID seront bloqués.", confirmLabel: "Bannir" })) { sel.forEach((m) => actions.banMachine(m)); clear(); } } },
    { label: "Exporter CSV", icon: <Download size={14} />, onClick: (sel) => exportCsv(sel, "machines") },
  ];

  return (
    <>
      <PageHeader title="Machines" eyebrow="Whip or get whipped" actions={<RefreshButton />} />
      <DataTable columns={columns} rows={data.machines} rowKey="id" searchKeys={["pcName", "hwid", "username"]} searchPlaceholder="Rechercher par PC Name, HWID ou utilisateur…" filters={filters} rowActions={rowActions} bulkActions={bulkActions} onRowClick={(r) => setSpecs(r)} pageSize={11} defaultSort={{ key: "lastActivity", dir: -1 }} />
      {modal && <MachineModal machine={modal} onClose={() => setModal(null)} />}
      {specs && <SpecsView machine={specs} onClose={() => setSpecs(null)} />}
    </>
  );
}
