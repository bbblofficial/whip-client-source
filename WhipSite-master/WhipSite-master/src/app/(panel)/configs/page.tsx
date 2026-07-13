"use client";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Plus, Pencil, Trash2 as Trash, FileCode, User as UserIcon, CheckCircle, XCircle, Check, LayoutGrid, ChevronDown } from "lucide-react";
import { useApp } from "@/components/app-provider";
import { PageHeader, IconButton, FormRow, Switch } from "@/components/ui/primitives";
import { RefreshButton } from "@/components/ui/RefreshButton";
import { DataTable, type Column, type Filter as TFilter } from "@/components/ui/DataTable";
import { Modal } from "@/components/ui/overlays";
import { Dropdown } from "@/components/ui/inputs";
import { LogoMark } from "@/components/shell/brand";
import { cn, fmtDate } from "@/lib/utils";
import { combatModules, visualModules } from "@/lib/mock-data";
import type { Config, ModuleSetting } from "@/lib/types";

const ALL_MODULES = [...combatModules, ...visualModules];

function ConfigEditor({ config, onClose }: { config: Config; onClose: () => void }) {
  const { actions } = useApp();
  const [tab, setTab] = useState<"visual" | "json">("visual");
  const [name, setName] = useState(config.name);
  const [desc, setDesc] = useState(config.description || "");
  const [pub, setPub] = useState(config.public);
  const [sel, setSel] = useState(combatModules[0] ?? ALL_MODULES[0]);
  const [binding, setBinding] = useState(false);
  // Per-module settings, seeded from the config's persisted `data` JSON.
  const [settings, setSettings] = useState<Record<string, ModuleSetting>>(() => {
    const init: Record<string, ModuleSetting> = {};
    ALL_MODULES.forEach((m) => {
      init[m] = config.data?.[m] ? { ...config.data[m] } : { enable: false };
    });
    return init;
  });
  const [open, setOpen] = useState<Record<string, boolean>>({ COMBAT: true, VISUAL: true });
  const cats = [{ name: "COMBAT", mods: combatModules }, { name: "VISUAL", mods: visualModules }];
  const cur = settings[sel] ?? { enable: false };
  const patch = (p: Partial<ModuleSetting>) => setSettings((s) => ({ ...s, [sel]: { ...(s[sel] ?? { enable: false }), ...p } }));

  // Bind capture: after clicking "Bind", the next key pressed is recorded.
  useEffect(() => {
    if (!binding) return;
    const onKey = (e: KeyboardEvent) => {
      e.preventDefault();
      const key = e.key === " " ? "Space" : e.key.length === 1 ? e.key.toUpperCase() : e.key;
      patch({ bind: key });
      setBinding(false);
    };
    window.addEventListener("keydown", onKey, { once: true });
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [binding, sel]);

  const payload = { version: config.version, ...settings };
  const json = JSON.stringify(payload, null, 2);
  const save = () => {
    actions.saveConfig(config, { name, description: desc, public: pub, data: JSON.stringify(payload) }, false);
    onClose();
  };

  return (
    <Modal eyebrow={`id: ${config.id}`} title={<span>Modifier configuration <span className="abs-badge abs-badge--brand" style={{ marginLeft: 8 }}>{config.version}</span></span>} onClose={onClose} size="xl"
      footer={<>
        <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={onClose}>Annuler</button>
        <button className="abs-btn abs-btn--primary abs-btn--md" onClick={save}><Check size={15} />Appliquer les changements</button>
      </>}>
      <div className="whip-cfg">
        <div className="whip-cfg__meta">
          <FormRow label="Nom du preset"><input className="abs-input" value={name} onChange={(e) => setName(e.target.value)} /></FormRow>
          <FormRow label="Description"><input className="abs-input" value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="Description courte…" /></FormRow>
          <div className="whip-cfg__vis"><span className="whip-formrow__label">Visibilité publique</span><Switch on={pub} onClick={() => setPub((p) => !p)} /></div>
        </div>
        <div className="whip-cfg__tabs">
          <div className="whip-cfg__client"><LogoMark size={22} /> Whip Client <strong>v0.7</strong></div>
          <div className="whip-segmented">
            <button className={cn("whip-segmented__btn", tab === "visual" && "whip-segmented__btn--active")} onClick={() => setTab("visual")}><LayoutGrid size={14} />Visuel</button>
            <button className={cn("whip-segmented__btn", tab === "json" && "whip-segmented__btn--active")} onClick={() => setTab("json")}><FileCode size={14} />JSON</button>
          </div>
        </div>
        {tab === "visual" ? (
          <div className="whip-cfg__editor">
            <div className="whip-cfg__nav">
              {cats.map((c) => (
                <div key={c.name} className="whip-cfg__cat">
                  <button className="whip-cfg__catbtn" onClick={() => setOpen((o) => ({ ...o, [c.name]: !o[c.name] }))}>{c.name}<ChevronDown size={15} style={{ transform: open[c.name] ? "none" : "rotate(-90deg)" }} /></button>
                  {open[c.name] && c.mods.map((m) => (
                    <button key={m} className={cn("whip-cfg__mod", sel === m && "whip-cfg__mod--active")} onClick={() => setSel(m)}>
                      <span className={cn("whip-cfg__moddot", settings[m]?.enable && "whip-cfg__moddot--on")} />{m}
                    </button>
                  ))}
                </div>
              ))}
            </div>
            <div className="whip-cfg__panel">
              <div className="whip-cfg__panelhead">{sel}</div>
              <div className="whip-cfg__setting"><span>Enable</span><Switch on={!!cur.enable} onClick={() => patch({ enable: !cur.enable })} /></div>
              <div className="whip-cfg__setting">
                <span>Bind</span>
                <button className="whip-cfg__bind" onClick={() => setBinding(true)} style={binding ? { borderColor: "var(--whip-primary)", color: "var(--whip-primary)" } : undefined}>
                  {binding ? "Appuie sur une touche…" : cur.bind || "None"}
                </button>
              </div>
              <div className="whip-cfg__setting"><span>Mode</span><Dropdown size="sm" block={false} value={cur.mode || "Legit"} onChange={(v) => patch({ mode: v })} style={{ width: 140 }} options={[{ value: "Legit", label: "Legit" }, { value: "Rage", label: "Rage" }, { value: "Smooth", label: "Smooth" }]} /></div>
            </div>
            <div className="whip-cfg__panel whip-cfg__panel--settings">
              <div className="whip-cfg__panelhead">Settings</div>
              <div className="whip-cfg__setting">
                <span>Intensité <strong style={{ color: "var(--whip-fg)" }}>{cur.intensity ?? 50}</strong></span>
                <input type="range" min={0} max={100} value={cur.intensity ?? 50} onChange={(e) => patch({ intensity: Number(e.target.value) })} style={{ width: 160, accentColor: "var(--whip-primary)" }} />
              </div>
              <div className="whip-cfg__setting">
                <span>Couleur</span>
                <input type="color" value={cur.color ?? "#2f6bf2"} onChange={(e) => patch({ color: e.target.value })} style={{ width: 46, height: 28, background: "none", border: "none", cursor: "pointer" }} />
              </div>
            </div>
          </div>
        ) : (
          <pre className="whip-cfg__json">{json}</pre>
        )}
      </div>
    </Modal>
  );
}

function ConfigCreateModal({ onClose }: { onClose: () => void }) {
  const { data, actions } = useApp();
  const [f, setF] = useState({ name: "", description: "", owner: "", public: false });
  return (
    <Modal eyebrow="nouvelle config" title="Nouvelle configuration" onClose={onClose} size="md"
      footer={<>
        <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={onClose}>Annuler</button>
        <button className="abs-btn abs-btn--primary abs-btn--md" onClick={() => { if (!f.name) return; actions.saveConfig(null, { name: f.name, description: f.description, public: f.public, data: "{}" }, true); onClose(); }}>Créer</button>
      </>}>
      <div className="whip-form">
        <FormRow label="Nom"><input className="abs-input" value={f.name} onChange={(e) => setF((s) => ({ ...s, name: e.target.value }))} placeholder="Ex: Legit Settings v1" /></FormRow>
        <FormRow label="Description"><textarea className="abs-input whip-textarea" rows={2} value={f.description} onChange={(e) => setF((s) => ({ ...s, description: e.target.value }))} placeholder="Description de la config…" /></FormRow>
        <FormRow label="Propriétaire" hint="La config est rattachée à l'admin connecté."><Dropdown value={f.owner} placeholder="Système" onChange={(v) => setF((s) => ({ ...s, owner: v }))} options={[{ value: "", label: "Système" }, ...data.users.slice(0, 60).map((u) => ({ value: u.username, label: u.username, icon: <UserIcon size={15} /> }))]} /></FormRow>
        <div className="whip-formtoggle"><span>Rendre publique</span><Switch on={f.public} onClick={() => setF((s) => ({ ...s, public: !s.public }))} /></div>
      </div>
    </Modal>
  );
}

function ConfigsInner() {
  const { data, actions, confirm } = useApp();
  const params = useSearchParams();
  const [editor, setEditor] = useState<Config | null>(null);
  const [create, setCreate] = useState(false);
  useEffect(() => {
    if (params.get("action") === "create") setCreate(true);
  }, [params]);
  const columns: Column<Config>[] = [
    { key: "name", label: "Nom", sortable: true, render: (r) => <span className="whip-usercell"><span className="whip-cfgicon"><FileCode size={16} /></span><span className="whip-usercell__name">{r.name}</span></span> },
    { key: "owner", label: "Propriétaire", width: 200, render: (r) => (r.owner === "Système" ? <span className="whip-muted" style={{ fontStyle: "italic" }}>Système</span> : <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}><UserIcon size={13} style={{ color: "var(--whip-fg-subtle)" }} />{r.owner}</span>) },
    { key: "description", label: "Description", render: (r) => (r.description ? r.description : <span className="whip-muted">—</span>) },
    { key: "enabledCount", label: "Modules", width: 100, align: "center", render: (r) => <span className="abs-badge abs-badge--brand">{r.enabledCount} actifs</span> },
    { key: "public", label: "Public", width: 90, align: "center", render: (r) => (r.public ? <CheckCircle size={17} style={{ color: "var(--whip-success)" }} /> : <XCircle size={17} style={{ color: "var(--whip-danger)" }} />) },
    { key: "createdAt", label: "Création", width: 120, sortable: true, sortValue: (r) => new Date(r.createdAt).getTime(), render: (r) => <span className="whip-mono whip-mono--dim" style={{ fontSize: 12 }}>{fmtDate(r.createdAt)}</span> },
  ];
  const filters: TFilter<Config>[] = [{ key: "public", label: "Visibilité", options: [{ value: "true", label: "Publique" }, { value: "false", label: "Privée" }], match: (r, v) => String(r.public) === v }];
  const rowActions = (r: Config) => (
    <>
      <IconButton title="Éditer" icon={<Pencil size={15} />} onClick={() => setEditor(r)} />
      <IconButton tone="danger" title="Supprimer" icon={<Trash size={15} />} onClick={async () => { if (await confirm({ title: "Supprimer la configuration ?", message: <>Le preset <strong>{r.name}</strong> sera supprimé.</>, confirmLabel: "Supprimer" })) actions.deleteConfig(r); }} />
    </>
  );
  return (
    <>
      <PageHeader title="Configurations" eyebrow="Manage user presets" actions={<><RefreshButton /><button className="abs-btn abs-btn--primary abs-btn--md" onClick={() => setCreate(true)}><Plus size={16} />Ajouter</button></>} />
      <DataTable columns={columns} rows={data.configs} rowKey="id" searchKeys={["name", "owner", "description"]} searchPlaceholder="Rechercher par nom ou description…" filters={filters} rowActions={rowActions} onRowClick={(r) => setEditor(r)} pageSize={11} defaultSort={{ key: "createdAt", dir: -1 }} />
      {editor && <ConfigEditor config={editor} onClose={() => setEditor(null)} />}
      {create && <ConfigCreateModal onClose={() => setCreate(false)} />}
    </>
  );
}

export default function ConfigsPage() {
  return (
    <Suspense fallback={null}>
      <ConfigsInner />
    </Suspense>
  );
}
