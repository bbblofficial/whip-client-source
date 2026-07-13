"use client";
// Shared modals used by multiple pages: SpecsView, BlacklistModal, GenerateModal.
import { useState, useEffect } from "react";
import { Monitor, User as UserIcon, Zap, KeyRound, Shield, Package, Clock, Cpu, MemoryStick, HardDrive, CircuitBoard, History } from "lucide-react";
import { getMachineHistory } from "@/lib/server/actions/machines";
import type { MachineHistoryEntry } from "@/lib/types";
import { Modal } from "@/components/ui/overlays";
import { FormRow, Field, Switch } from "@/components/ui/primitives";
import { Dropdown, DatePicker, Combobox } from "@/components/ui/inputs";
import { cn, fmtDateTime, NOW, DAY } from "@/lib/utils";
import { useApp } from "@/components/app-provider";
import type { Machine } from "@/lib/types";


function Spec({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="whip-spec">
      <span className="whip-spec__ic">{icon}</span>
      <span className="whip-spec__meta">
        <span className="whip-spec__lbl">{label}</span>
        <span className="whip-spec__val">{value}</span>
      </span>
    </div>
  );
}

function ScreenSpec({ screenInfo }: { screenInfo: string }) {
  const screens = screenInfo && screenInfo !== "—"
    ? screenInfo.split(", ").filter(Boolean)
    : null;
  const multi = screens && screens.length > 1;
  return (
    <div className={multi ? "whip-spec whip-spec--fullspan" : "whip-spec"}>
      <span className="whip-spec__ic"><Monitor size={16} /></span>
      <span className="whip-spec__meta">
        <span className="whip-spec__lbl">
          {multi ? `Écrans (${screens!.length})` : "Écran"}
        </span>
        {screens ? (
          <span className="whip-spec__screens">
            {screens.map((s, i) => (
              <span key={i} className="whip-spec__screen-chip">{s}</span>
            ))}
          </span>
        ) : (
          <span className="whip-spec__val">—</span>
        )}
      </span>
    </div>
  );
}

function fmtRam(ramHex: string | undefined): string {
  if (!ramHex) return "—";
  const bytes = parseInt(ramHex, 16);
  if (isNaN(bytes) || bytes <= 0) return "—";
  const gb = bytes / (1024 ** 3);
  return Math.round(gb) + " Go";
}

const FIELD_LABELS: Record<string, string> = {
  pc_name: "Nom du PC", os: "Système", gpu_name: "GPU", cpu_brand: "CPU",
  ram_hex: "RAM", board_model: "Carte Mère", screen_info: "Écran", storage_info: "Stockage",
};

function fmtRelative(date: Date): string {
  const diff = Date.now() - new Date(date).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `il y a ${mins} min`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `il y a ${hrs}h`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `il y a ${days}j`;
  return new Date(date).toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" });
}

export function SpecsView({ machine, onClose }: { machine: { pcName: string; hwid?: string; os?: string; username?: string; status?: string }; onClose: () => void }) {
  const { data } = useApp();
  const full = data.machines.find((m) => m.pcName === machine.pcName) || (machine as Machine);
  const [history, setHistory] = useState<MachineHistoryEntry[] | null>(null);

  useEffect(() => {
    if (!full.id) return;
    getMachineHistory(full.id).then((rows) =>
      setHistory(rows.map((r) => ({
        id: r.id,
        fieldName: r.field_name,
        oldValue: r.old_value,
        newValue: r.new_value,
        changedAt: r.changed_at,
      })))
    );
  }, [full.id]);
  const os = full.os || "—";
  const hwid = full.hwid || "—";
  const gpu = full.gpuName || "—";
  const cpu = full.cpuBrand?.trim() || "—";
  const ram = fmtRam(full.ramHex);
  const cm = full.boardModel || "—";
  const screen = full.screenInfo || "—";
  const storage = full.storageInfo || "—";
  return (
    <Modal eyebrow={`specs · ${machine.pcName}`} title="Configuration du PC" onClose={onClose} size="lg" footer={<button className="abs-btn abs-btn--secondary abs-btn--md" onClick={onClose}>Fermer</button>}>
      <div className="whip-spechero">
        <span className="whip-spechero__icon"><Monitor size={22} /></span>
        <div>
          <div className="whip-spechero__pc whip-mono">{machine.pcName}</div>
          <div className="whip-spechero__os">
            {os}
            {full.username && <> · <UserIcon size={12} style={{ verticalAlign: -1 }} /> {full.username}</>}
            {full.status === "banned" && <span className="abs-badge abs-badge--revoked" style={{ marginLeft: 8 }}>banni</span>}
          </div>
        </div>
      </div>
      {gpu !== "—" && (
        <div className="whip-speccard whip-speccard--gpu">
          <span className="whip-speccard__ic"><Cpu size={20} /></span>
          <div className="whip-speccard__body">
            <span className="whip-speccard__lbl">Carte graphique</span>
            <span className="whip-speccard__val">{gpu}</span>
          </div>
          <span className="whip-speccard__vendor">{gpu.startsWith("AMD") ? "AMD" : "NVIDIA"}</span>
        </div>
      )}
      <div className="whip-specgrid">
        <Spec icon={<Cpu size={16} />} label="Processeur (CPU)" value={cpu} />
        <Spec icon={<MemoryStick size={16} />} label="Mémoire (RAM)" value={ram} />
        <Spec icon={<CircuitBoard size={16} />} label="Carte Mère" value={cm} />
        <ScreenSpec screenInfo={screen} />
        <Spec icon={<HardDrive size={16} />} label="Stockage" value={storage} />
        <Spec icon={<Zap size={16} />} label="Système d'exploitation" value={os} />
      </div>
      <div className="whip-fieldgrid" style={{ marginTop: 16 }}>
        <Field label="HWID (Hardware ID)" mono>{hwid}</Field>
        <Field label="Dernière activité">{full.lastActivity ? fmtDateTime(full.lastActivity) : "—"}</Field>
        <Field label="Clé de licence" mono>{full.licenseKey || "—"}</Field>
        <Field label="Statut">{full.status === "banned" ? "Banni" : "Actif"}</Field>
      </div>
      {history !== null && history.length > 0 && (
        <div className="whip-history">
          <div className="whip-history__hdr">
            <History size={13} />
            Historique des changements
          </div>
          <div className="whip-history__list">
            {history.map((e) => (
              <div key={e.id} className="whip-history__entry">
                <div className="whip-history__meta">
                  <span className="whip-history__field">{FIELD_LABELS[e.fieldName] ?? e.fieldName}</span>
                  <span className="whip-history__time">{fmtRelative(e.changedAt)}</span>
                </div>
                <div className="whip-history__change">
                  <span className="whip-history__old">{e.oldValue ?? "—"}</span>
                  <span className="whip-history__arrow">→</span>
                  <span className="whip-history__new">{e.newValue ?? "—"}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </Modal>
  );
}

export function BlacklistModal({ preUser, onClose }: { preUser?: string; onClose: () => void }) {
  const { data, actions } = useApp();
  const [f, setF] = useState<{ username: string; reason: string; expiresAt: Date | null }>({ username: preUser || "", reason: "", expiresAt: null });
  const submit = () => {
    if (!f.username) return;
    actions.blacklistUser({ username: f.username, reason: f.reason || "Non spécifié", expiresAt: f.expiresAt });
    onClose();
  };
  return (
    <Modal eyebrow="action destructrice" danger title="Blacklister" onClose={onClose} size="md"
      footer={<>
        <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={onClose}>Annuler</button>
        <button className="abs-btn abs-btn--md whip-btn-destructive" onClick={submit}><Shield size={15} />Blacklister</button>
      </>}>
      <div className="whip-form">
        <FormRow label="Utilisateur">
          <Dropdown value={f.username} placeholder="Sélectionner un utilisateur…" onChange={(v) => setF((s) => ({ ...s, username: v }))} options={data.users.map((u) => ({ value: u.username, label: u.username, icon: <UserIcon size={15} /> }))} />
        </FormRow>
        <FormRow label="Raison">
          <input className="abs-input" value={f.reason} onChange={(e) => setF((s) => ({ ...s, reason: e.target.value }))} placeholder="Raison du blacklist (optionnel)" />
        </FormRow>
        <FormRow label="Expiration (optionnel)" hint="Laisser vide pour un ban permanent.">
          <DatePicker value={f.expiresAt} min={NOW} placeholder="Ban permanent" onChange={(d) => setF((s) => ({ ...s, expiresAt: d }))} />
        </FormRow>
      </div>
    </Modal>
  );
}

export function GenerateModal({ preUser, onClose }: { preUser?: string; onClose: () => void }) {
  const { data, actions } = useApp();
  const [f, setF] = useState<{ username: string; productCode: string; lifetime: boolean; expiresAt: Date }>({
    username: preUser || "",
    productCode: "WHIP_CLIENT",
    lifetime: false,
    expiresAt: new Date(NOW.getTime() + 30 * DAY),
  });
  const submit = () => {
    actions.generateLicense({ username: f.username.trim() || null, productCode: f.productCode, lifetime: f.lifetime, expiresAt: f.expiresAt });
    onClose();
  };
  return (
    <Modal eyebrow="nouvelle clé" title="Générer licence" onClose={onClose} size="md"
      footer={<>
        <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={onClose}>Annuler</button>
        <button className="abs-btn abs-btn--primary abs-btn--md" onClick={submit}><KeyRound size={15} />Générer</button>
      </>}>
      <div className="whip-form">
        <FormRow label="Pseudo" hint="Laisser vide pour une clé non assignée">
          <Combobox value={f.username} onChange={(v) => setF((s) => ({ ...s, username: v }))} placeholder="Tapez ou sélectionnez un pseudo…" leftIcon={<UserIcon size={15} />} options={data.users.map((u) => ({ value: u.username, label: u.username, hint: u.grade }))} />
        </FormRow>
        <FormRow label="Produit">
          <Dropdown value={f.productCode} onChange={(v) => setF((s) => ({ ...s, productCode: v }))} options={data.products.map((p) => ({ value: p.code, label: p.name, icon: <Package size={15} /> }))} />
        </FormRow>
        <div className="whip-formtoggle">
          <span>Lifetime</span>
          <Switch on={f.lifetime} onClick={() => setF((s) => ({ ...s, lifetime: !s.lifetime }))} />
        </div>
        {!f.lifetime && (
          <FormRow label="Date d'expiration">
            <DatePicker value={f.expiresAt} min={NOW} onChange={(d) => setF((s) => ({ ...s, expiresAt: d }))} />
          </FormRow>
        )}
      </div>
    </Modal>
  );
}

export { fmtDateTime, cn };
