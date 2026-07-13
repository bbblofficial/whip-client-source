"use client";
import { useEffect, useRef, useState } from "react";
import {
  Fingerprint,
  Upload,
  Check,
  ShieldCheck,
  ShieldX,
  RefreshCw,
  Ban,
  Shield,
  ArrowRight,
  Circle,
} from "lucide-react";
import { useApp } from "@/components/app-provider";
import { PageHeader, Avatar, Field } from "@/components/ui/primitives";
import { cn, fmtDateTime, timeAgo } from "@/lib/utils";
import type { ScanResult } from "@/lib/server/actions/watermark";
import type { Download } from "@/lib/types";

const SCAN_STEPS = [
  "Lecture du fichier…",
  "Recherche du sentinel WhipClient (.rdata · table dll_watermarks)…",
  "Décodage de l'overlay v5 du loader (table downloads)…",
  "Corrélation watermark → identité d'origine…",
  "Résolution de l'utilisateur source…",
];

interface ScanEntry {
  id: string;
  file: string;
  result: ScanResult;
  at: Date;
}

// Normalize a successful match (dll or loader) into a uniform view model.
function normalize(r: ScanResult) {
  if (r.status === "match" && r.kind === "dll") {
    return {
      kind: "dll" as const,
      username: r.watermark.username,
      downloadId: r.watermark.downloadId,
      fields: [
        { label: "Discord ID", value: r.watermark.discordId ?? "—", mono: true },
        { label: "HWID", value: r.watermark.hwid ?? "—", mono: true },
        { label: "Nom du PC", value: r.watermark.pcName ?? "—" },
        { label: "IP d'origine", value: r.watermark.ip ?? "—", mono: true },
        { label: "Session UUID", value: r.sessionUuid, mono: true },
        { label: "Marqué le", value: fmtDateTime(r.watermark.createdAt), mono: true },
      ],
    };
  }
  if (r.status === "match" && r.kind === "loader") {
    return {
      kind: "loader" as const,
      username: r.download.username,
      downloadId: r.download.id,
      fields: [
        { label: "Discord ID", value: r.download.discordId ?? "—", mono: true },
        { label: "Produit", value: r.download.productName ?? "—" },
        { label: "IP d'origine", value: r.download.ip ?? "—", mono: true },
        { label: "Téléchargé le", value: fmtDateTime(r.download.downloadedAt), mono: true },
        { label: "Utilisations", value: String(r.download.useCount), mono: true },
        { label: "Statut lien", value: r.download.revoked ? "révoqué" : "actif" },
      ],
    };
  }
  return null;
}

export default function ScanLeakPage() {
  const { data, actions, confirm, toast } = useApp();
  const [phase, setPhase] = useState<"idle" | "scanning" | "result">("idle");
  const [step, setStep] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanEntry[]>([]);
  const fileRef = useRef<HTMLInputElement>(null);

  const runScan = async (file: File) => {
    setPhase("scanning");
    setStep(0);
    setResult(null);
    // Lightweight stepper animation while the real scan runs server-side.
    let s = 0;
    const iv = setInterval(() => {
      s = Math.min(s + 1, SCAN_STEPS.length - 1);
      setStep(s);
    }, 320);
    try {
      const fd = new FormData();
      fd.set("file", file);
      const resp = await fetch("/api/scanleak", { method: "POST", body: fd });
      if (!resp.ok) {
        const j = await resp.json().catch(() => ({}));
        throw new Error(j.error || `Erreur ${resp.status}`);
      }
      const res = (await resp.json()) as ScanResult;
      clearInterval(iv);
      setStep(SCAN_STEPS.length);
      setResult(res);
      setPhase("result");
      setHistory((h) => [{ id: "scan_" + Date.now(), file: file.name, result: res, at: new Date() }, ...h]);
      actions.runScan(file.name);
    } catch (e) {
      clearInterval(iv);
      setPhase("idle");
      toast({ tone: "danger", title: "Scan échoué", desc: e instanceof Error ? e.message : String(e) });
    }
  };

  const view = result ? normalize(result) : null;
  const revoke = () => {
    if (!view?.downloadId) return;
    const dl = data.downloads.find((d) => d.id === view.downloadId) ?? ({ id: view.downloadId } as Download);
    actions.revokeDownload(dl, "Please update the loader");
  };

  return (
    <>
      <PageHeader title="Scan Leak" eyebrow="Identification de fuite par watermark" />
      <div className="whip-scanintro">
        <Fingerprint size={20} />
        <p>
          Dépose un dump mémoire, un DLL ou un <span className="whip-mono">loader.exe</span> pour identifier la session /
          le téléchargement d&apos;origine. Le moteur cherche d&apos;abord le sentinel WhipClient (
          <span className="whip-mono">.rdata</span>, table <span className="whip-mono">dll_watermarks</span>), puis
          l&apos;overlay v5 du loader (table <span className="whip-mono">downloads</span>).
        </p>
      </div>

      {phase === "idle" && (
        <div
          className="whip-dropzone"
          onClick={() => fileRef.current?.click()}
          onDragOver={(e) => {
            e.preventDefault();
            e.currentTarget.classList.add("whip-dropzone--over");
          }}
          onDragLeave={(e) => e.currentTarget.classList.remove("whip-dropzone--over")}
          onDrop={(e) => {
            e.preventDefault();
            e.currentTarget.classList.remove("whip-dropzone--over");
            const f = e.dataTransfer.files[0];
            if (f) runScan(f);
          }}
        >
          <input ref={fileRef} type="file" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) runScan(f); }} />
          <span className="whip-dropzone__icon">
            <Upload size={30} />
          </span>
          <div className="whip-dropzone__title">Drop un fichier ici ou clique pour sélectionner</div>
          <div className="whip-dropzone__hint">.dll, .exe, .bin, dump mémoire — max 64 MB</div>
        </div>
      )}

      {phase === "scanning" && (
        <div className="whip-panel whip-scanning">
          <div className="whip-scanning__spinner">
            <Fingerprint size={32} />
          </div>
          <div className="whip-scanning__steps">
            {SCAN_STEPS.map((s, i) => (
              <div key={i} className={cn("whip-scanstep", i < step && "whip-scanstep--done", i === step && "whip-scanstep--active")}>
                <span className="whip-scanstep__ic">{i < step ? <Check size={14} /> : i === step ? <span className="whip-scanstep__spin" /> : <Circle size={8} />}</span>
                {s}
              </div>
            ))}
          </div>
        </div>
      )}

      {phase === "result" && result && view && (
        <div className="whip-panel whip-scanresult">
          <div className="whip-scanresult__head">
            <div className="whip-scanresult__title">
              <ShieldCheck size={20} />
              Source identifiée
            </div>
            <span className="abs-badge abs-badge--brand">{view.kind === "dll" ? "DLL · dll_watermarks" : "Loader · downloads"}</span>
          </div>
          <div className="whip-scanmatch">
            <Avatar name={view.username || "?"} size={48} />
            <div>
              <div className="whip-scanmatch__user">{view.username || "Utilisateur inconnu"}</div>
              {view.downloadId && (
                <div className="whip-scanmatch__sub">
                  Download <span className="whip-mono">{view.downloadId.slice(0, 20)}…</span>
                </div>
              )}
            </div>
          </div>
          <div className="whip-fieldgrid whip-fieldgrid--2" style={{ marginTop: 18 }}>
            {view.fields.map((f) => (
              <Field key={f.label} label={f.label} mono={f.mono}>{f.value}</Field>
            ))}
          </div>
          <div className="whip-scanresult__actions">
            <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={() => { setPhase("idle"); setResult(null); }}><RefreshCw size={15} />Nouveau scan</button>
            {view.downloadId && (
              <button className="abs-btn abs-btn--md whip-btn-destructive" onClick={revoke}><Ban size={15} />Révoquer le download</button>
            )}
            {view.username && (
              <button className="abs-btn abs-btn--md whip-btn-destructive" onClick={async () => { if (await confirm({ title: "Blacklister le leaker ?", message: <>Bannir <strong>{view.username}</strong> pour fuite du client ?</>, confirmLabel: "Blacklister" })) actions.blacklistUser({ username: view.username!, reason: "Leak du client (scan watermark)", expiresAt: null }); }}><Shield size={15} />Blacklister {view.username}</button>
            )}
          </div>
        </div>
      )}

      {phase === "result" && result && !view && (
        <div className="whip-panel whip-scanresult">
          <div className="whip-scanresult__head">
            <div className="whip-scanresult__title">
              <ShieldX size={20} />
              {result.status === "no-magic" ? "Aucun watermark détecté" : "Watermark détecté mais introuvable en base"}
            </div>
          </div>
          <div className="whip-fieldgrid whip-fieldgrid--2" style={{ marginTop: 14 }}>
            <Field label="Taille du fichier" mono>{(result.fileSize / 1024).toFixed(1)} Ko</Field>
            {result.status === "no-match" && result.kind === "dll" && <Field label="Session UUID" mono>{result.sessionUuid}</Field>}
            {result.status === "no-match" && result.kind === "loader" && <Field label="Download ID" mono>{result.downloadId}</Field>}
          </div>
          <div className="whip-scanresult__actions">
            <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={() => { setPhase("idle"); setResult(null); }}><RefreshCw size={15} />Nouveau scan</button>
          </div>
        </div>
      )}

      <div className="whip-panel" style={{ marginTop: 18 }}>
        <div className="whip-panel__head">
          <h3 className="whip-panel__title">Historique des scans</h3>
          <span className="whip-panel__hint">{history.length} analyses</span>
        </div>
        <div className="whip-panel__body" style={{ padding: 0 }}>
          {history.length === 0 ? (
            <p className="whip-muted" style={{ padding: 16 }}>Aucun scan effectué dans cette session.</p>
          ) : (
            history.map((h) => {
              const v = normalize(h.result);
              return (
                <div key={h.id} className="whip-scanhist">
                  <span className="whip-scanhist__ic"><Fingerprint size={15} /></span>
                  <span className="whip-scanhist__file whip-mono">{h.file}</span>
                  <span className="whip-scanhist__arrow"><ArrowRight size={13} /></span>
                  <span className="whip-scanhist__user">{v?.username || "aucun match"}</span>
                  <span className={cn("abs-badge", v ? "abs-badge--active" : "abs-badge--expired")} style={{ marginLeft: "auto" }}>{v ? "identifié" : "—"}</span>
                  <span className="whip-scanhist__time">{timeAgo(h.at)}</span>
                </div>
              );
            })
          )}
        </div>
      </div>
    </>
  );
}
