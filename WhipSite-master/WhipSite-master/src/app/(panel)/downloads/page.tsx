"use client";
import { useRef, useState, useCallback } from "react";
import { Ban, Trash2 as Trash, Download as DownloadIcon, ShieldCheck, User as UserIcon, Package, ArrowDownToLine, ShieldPlus, Upload, CheckCircle2, UserPlus } from "lucide-react";
import { useApp } from "@/components/app-provider";
import { srvCreateDownload } from "@/lib/server/panel-actions";
import { PageHeader, IconButton, Copyable } from "@/components/ui/primitives";
import { RefreshButton } from "@/components/ui/RefreshButton";
import { DataTable, type Column, type Filter as TFilter, type BulkAction } from "@/components/ui/DataTable";
import { exportCsv } from "@/lib/csv";
import { fmtDateTime } from "@/lib/utils";
import type { Download } from "@/lib/types";

const REVOKE_REASONS = [
  { value: "", label: "Erreur standard (Error #11)" },
  { value: "Please update the loader", label: "Mise à jour requise" },
];

function RevokeReasonSelect({ reasonRef }: { reasonRef: React.MutableRefObject<string> }) {
  return (
    <select
      className="whip-filter"
      style={{ width: "100%" }}
      defaultValue={reasonRef.current}
      onChange={(e) => { reasonRef.current = e.target.value; }}
    >
      {REVOKE_REASONS.map((r) => (
        <option key={r.value} value={r.value}>{r.label}</option>
      ))}
    </select>
  );
}

type UploadState = "idle" | "dragging" | "uploading" | "done" | "error";

function LoaderDropZone({ onDone }: { onDone: (revoked: number) => void }) {
  const [state, setState] = useState<UploadState>("idle");
  const [info, setInfo] = useState<{ revoked: number; bytes: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const upload = useCallback(async (file: File) => {
    if (!file.name.endsWith(".exe")) {
      setError("Le fichier doit être un .exe");
      setState("error");
      setTimeout(() => setState("idle"), 3000);
      return;
    }
    setState("uploading");
    setError(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await fetch("/api/admin/upload-loader", { method: "POST", body: fd });
      const data = await res.json() as { success?: boolean; revoked?: number; bytes?: number; error?: string };
      if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
      setInfo({ revoked: data.revoked ?? 0, bytes: data.bytes ?? 0 });
      setState("done");
      onDone(data.revoked ?? 0);
      setTimeout(() => { setState("idle"); setInfo(null); }, 5000);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setState("error");
      setTimeout(() => setState("idle"), 4000);
    }
  }, [onDone]);

  const onDragOver = (e: React.DragEvent) => { e.preventDefault(); if (state === "idle") setState("dragging"); };
  const onDragLeave = () => { if (state === "dragging") setState("idle"); };
  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) upload(file);
  };

  const active = state === "dragging";
  const busy = state === "uploading";
  const done = state === "done";
  const err = state === "error";

  return (
    <div
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
      onClick={() => !busy && inputRef.current?.click()}
      style={{
        border: `2px dashed ${done ? "var(--whip-success)" : err ? "var(--whip-danger)" : active ? "var(--whip-primary-bright)" : "var(--whip-border-strong)"}`,
        borderRadius: 12,
        padding: "18px 24px",
        display: "flex",
        alignItems: "center",
        gap: 14,
        cursor: busy ? "default" : "pointer",
        background: done ? "rgba(52,211,153,.06)" : err ? "rgba(248,113,113,.06)" : active ? "var(--whip-primary-soft)" : "var(--whip-card)",
        transition: "all 0.15s",
        userSelect: "none",
        marginBottom: 16,
      }}
    >
      <input ref={inputRef} type="file" accept=".exe" style={{ display: "none" }} onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); e.target.value = ""; }} />

      <div style={{
        width: 38, height: 38, borderRadius: 10,
        background: done ? "rgba(52,211,153,.15)" : err ? "rgba(248,113,113,.15)" : active ? "var(--whip-primary-soft)" : "var(--whip-input)",
        display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
        color: done ? "var(--whip-success)" : err ? "var(--whip-danger)" : active ? "var(--whip-primary-bright)" : "var(--whip-fg-subtle)",
      }}>
        {done ? <CheckCircle2 size={18} /> : busy ? (
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ animation: "whipSpin 0.7s linear infinite" }}>
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
        ) : <Upload size={18} />}
      </div>

      <div style={{ flex: 1 }}>
        {done && info ? (
          <>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--whip-success)" }}>Loader déployé</div>
            <div style={{ fontSize: 12, color: "var(--whip-fg-subtle)", marginTop: 2 }}>
              {(info.bytes / 1024).toFixed(0)} Ko • {info.revoked} téléchargement{info.revoked !== 1 ? "s" : ""} révoqué{info.revoked !== 1 ? "s" : ""}
            </div>
          </>
        ) : err ? (
          <>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--whip-danger)" }}>Erreur de déploiement</div>
            <div style={{ fontSize: 12, color: "var(--whip-fg-subtle)", marginTop: 2 }}>{error}</div>
          </>
        ) : busy ? (
          <>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--whip-fg)" }}>Déploiement en cours…</div>
            <div style={{ fontSize: 12, color: "var(--whip-fg-subtle)", marginTop: 2 }}>Upload + révocation de tous les downloads</div>
          </>
        ) : (
          <>
            <div style={{ fontSize: 13, fontWeight: 600, color: active ? "var(--whip-primary-bright)" : "var(--whip-fg)" }}>
              {active ? "Relâcher pour déployer" : "Glisser le nouveau WhipLoader.exe ici"}
            </div>
            <div style={{ fontSize: 12, color: "var(--whip-fg-subtle)", marginTop: 2 }}>
              Remplace le loader en production • révoque automatiquement tous les downloads actifs
            </div>
          </>
        )}
      </div>

      {!busy && !done && !err && (
        <span style={{ fontSize: 11, color: "var(--whip-fg-muted)", background: "var(--whip-input)", border: "1px solid var(--whip-border)", borderRadius: 6, padding: "3px 8px" }}>
          .exe
        </span>
      )}
    </div>
  );
}

type RowActionsProps = {
  r: Download;
  confirm: ReturnType<typeof useApp>["confirm"];
  toast: ReturnType<typeof useApp>["toast"];
  actions: ReturnType<typeof useApp>["actions"];
};

function DownloadRowActions({ r, confirm, toast, actions }: RowActionsProps) {
  const reasonRef = useRef(REVOKE_REASONS[0].value);
  return (
    <>
      {r.status === "active" && (
        <IconButton
          tone="default"
          title="Télécharger le .exe"
          icon={<ArrowDownToLine size={15} />}
          onClick={async () => {
            try {
              const res = await fetch(`/api/download/${r.id}`);
              if (!res.ok) {
                const d = await res.json().catch(() => ({})) as { error?: string };
                toast({ tone: "danger", title: "Erreur", desc: d.error ?? `HTTP ${res.status}` });
                return;
              }
              const blob = await res.blob();
              const cd = res.headers.get("Content-Disposition") ?? "";
              const filename = cd.match(/filename="([^"]+)"/)?.[1] ?? "loader.exe";
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = filename;
              a.click();
              URL.revokeObjectURL(url);
            } catch (e) {
              toast({ tone: "danger", title: "Erreur", desc: e instanceof Error ? e.message : String(e) });
            }
          }}
        />
      )}
      {r.status === "active" && (
        <IconButton
          tone="danger"
          title="Révoquer le lien"
          icon={<Ban size={15} />}
          onClick={async () => {
            reasonRef.current = REVOKE_REASONS[0].value;
            if (await confirm({
              title: "Révoquer ce téléchargement ?",
              message: (
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  <span style={{ fontSize: 13, color: "var(--whip-fg-subtle)" }}>
                    Lien <span className="whip-mono">{r.id.slice(0, 16)}…</span> sera invalidé.
                  </span>
                  <RevokeReasonSelect reasonRef={reasonRef} />
                </div>
              ),
              confirmLabel: "Révoquer",
            })) actions.revokeDownload(r, reasonRef.current);
          }}
        />
      )}
      {r.status === "revoked" && (
        <IconButton
          tone="success"
          title="Réactiver le téléchargement"
          icon={<ShieldPlus size={15} />}
          onClick={async () => {
            if (await confirm({ title: "Réactiver ce téléchargement ?", message: <>Le lien <span className="whip-mono">{r.id.slice(0, 16)}…</span> sera de nouveau valide.</>, confirmLabel: "Réactiver" }))
              actions.unrevokeDownload(r);
          }}
        />
      )}
      <IconButton
        tone="danger"
        title="Supprimer"
        icon={<Trash size={15} />}
        onClick={async () => {
          if (await confirm({ title: "Supprimer l'entrée ?", message: "L'enregistrement de téléchargement sera supprimé.", confirmLabel: "Supprimer" }))
            actions.deleteDownload(r);
        }}
      />
    </>
  );
}

export default function DownloadsPage() {
  const { data, actions, confirm, toast, refresh } = useApp();

  const handleDeployDone = useCallback(async (revoked: number) => {
    await refresh();
    toast({ tone: "success", title: "Loader déployé", desc: `${revoked} download${revoked !== 1 ? "s" : ""} révoqué${revoked !== 1 ? "s" : ""} — mise à jour requise` });
  }, [refresh, toast]);

  const generateRef = useRef<{ userId: string; productId: string }>({ userId: "", productId: "" });
  const handleGenerate = useCallback(async () => {
    generateRef.current = { userId: data.users[0]?.id ?? "", productId: "" };
    const ok = await confirm({
      title: "Générer un download",
      message: (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <select
            className="whip-filter"
            style={{ width: "100%" }}
            defaultValue={data.users[0]?.id ?? ""}
            onChange={(e) => { generateRef.current.userId = e.target.value; }}
          >
            {data.users.map((u) => (
              <option key={u.id} value={u.id}>{u.username}</option>
            ))}
          </select>
          <select
            className="whip-filter"
            style={{ width: "100%" }}
            defaultValue=""
            onChange={(e) => { generateRef.current.productId = e.target.value; }}
          >
            <option value="">Aucun produit</option>
            {data.products.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        </div>
      ),
      confirmLabel: "Générer",
    });
    if (!ok || !generateRef.current.userId) return;
    try {
      const result = await srvCreateDownload(generateRef.current.userId, generateRef.current.productId || null);
      await refresh();
      toast({ tone: "success", title: "Download généré", desc: result.downloadId, sticky: true });
    } catch (e) {
      toast({ tone: "danger", title: "Erreur", desc: e instanceof Error ? e.message : String(e) });
    }
  }, [data.users, data.products, confirm, toast, refresh]);

  const columns: Column<Download>[] = [
    { key: "id", label: "Download ID", sortable: true, render: (r) => <span className="whip-keycell"><span className="whip-keycell__icon whip-keycell__icon--dl"><DownloadIcon size={14} /></span><Copyable value={r.id} display={r.id.slice(0, 24) + "…"} /></span> },
    { key: "username", label: "Utilisateur", width: 200, render: (r) => <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}><UserIcon size={13} style={{ color: "var(--whip-fg-subtle)" }} /><strong style={{ fontSize: 13 }}>{r.username}</strong></span> },
    { key: "productName", label: "Produit", width: 170, render: (r) => <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}><Package size={13} style={{ color: "var(--whip-fg-subtle)" }} />{r.productName}</span> },
    { key: "date", label: "Date", width: 160, sortable: true, sortValue: (r) => new Date(r.date).getTime(), render: (r) => <span className="whip-mono whip-mono--dim" style={{ fontSize: 12 }}>{fmtDateTime(r.date)}</span> },
    { key: "status", label: "Statut", width: 120, render: (r) => (r.status === "active" ? <span className="abs-badge abs-badge--active"><ShieldCheck size={11} />actif</span> : <span className="abs-badge abs-badge--revoked"><Ban size={11} />révoqué</span>) },
  ];
  const filters: TFilter<Download>[] = [
    { key: "status", label: "Statut", options: [{ value: "active", label: "Actif" }, { value: "revoked", label: "Révoqué" }] },
    { key: "productCode", label: "Produit", options: data.products.map((p) => ({ value: p.code, label: p.name })) },
  ];
  const rowActions = (r: Download) => (
    <DownloadRowActions r={r} confirm={confirm} toast={toast} actions={actions} />
  );
  const bulkActions: BulkAction<Download>[] = [
    {
      label: "Révoquer", icon: <Ban size={14} />, tone: "danger",
      onClick: async (sel, clear) => {
        const reasonRef = { current: REVOKE_REASONS[0].value };
        if (await confirm({
          title: `Révoquer ${sel.length} téléchargements ?`,
          message: (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <span style={{ fontSize: 13, color: "var(--whip-fg-subtle)" }}>{sel.length} lien{sel.length > 1 ? "s" : ""} seront invalidés.</span>
              <select
                className="whip-filter"
                style={{ width: "100%" }}
                defaultValue={reasonRef.current}
                onChange={(e) => { reasonRef.current = e.target.value; }}
              >
                {REVOKE_REASONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
              </select>
            </div>
          ),
          confirmLabel: "Révoquer",
        })) {
          sel.forEach((d) => actions.revokeDownload(d, reasonRef.current));
          clear();
        }
      },
    },
    { label: "Exporter CSV", icon: <DownloadIcon size={14} />, onClick: (sel) => exportCsv(sel, "downloads") },
  ];

  return (
    <>
      <PageHeader title="Téléchargements" eyebrow="Whip or get whipped" actions={
        <>
          <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={handleGenerate}>
            <UserPlus size={15} />Générer un download
          </button>
          <RefreshButton />
        </>
      } />
      <LoaderDropZone onDone={handleDeployDone} />
      <DataTable columns={columns} rows={data.downloads} rowKey="id" searchKeys={["id", "username", "productName"]} searchPlaceholder="Rechercher par utilisateur ou download ID…" filters={filters} rowActions={rowActions} bulkActions={bulkActions} pageSize={12} defaultSort={{ key: "date", dir: -1 }} dense />
    </>
  );
}
