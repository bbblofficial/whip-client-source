"use client";
import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Plus,
  Eye,
  Pencil,
  Trash2 as Trash,
  KeyRound,
  Lock,
  Activity,
  Monitor,
  Ban,
  Check,
  Clock,
  Cpu,
  Shield,
  User as UserIcon,
} from "lucide-react";
import { useApp } from "@/components/app-provider";
import { PageHeader, IconButton, Avatar, GradeBadge, StatusBadge, Copyable, Field } from "@/components/ui/primitives";
import { RefreshButton } from "@/components/ui/RefreshButton";
import { DataTable, type Column, type BulkAction } from "@/components/ui/DataTable";
import { Drawer } from "@/components/ui/overlays";
import { Modal } from "@/components/ui/overlays";
import { DrawerSection } from "@/components/ui/StatCard";
import { FormRow } from "@/components/ui/primitives";
import { Dropdown } from "@/components/ui/inputs";
import { AuditRow } from "@/components/blocks";
import { GenerateModal, BlacklistModal, SpecsView } from "@/components/shared-modals";
import { fmtDate, timeAgo } from "@/lib/utils";
import type { User } from "@/lib/types";

function UserModal({ user, onClose }: { user: User | null; onClose: () => void }) {
  const isNew = !user;
  const { actions } = useApp();
  const [f, setF] = useState({ username: user?.username || "", password: "", discordId: user?.discordId || "", grade: user?.grade || "user" });
  const submit = () => {
    if (!f.username.trim()) return;
    actions.saveUser(user, { username: f.username.trim(), discordId: f.discordId, grade: f.grade as User["grade"] }, isNew);
    onClose();
  };
  return (
    <Modal eyebrow={isNew ? "nouvel agent" : "modifier agent"} title={isNew ? "Ajouter un agent" : "Modifier agent"} onClose={onClose} size="md"
      footer={<>
        <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={onClose}>Annuler</button>
        <button className="abs-btn abs-btn--primary abs-btn--md" onClick={submit}>{isNew ? "Créer" : "Sauvegarder"}</button>
      </>}>
      <div className="whip-form">
        <FormRow label="Username"><input className="abs-input" value={f.username} onChange={(e) => setF((s) => ({ ...s, username: e.target.value }))} placeholder="pseudo" /></FormRow>
        <FormRow label="Password" hint={isNew ? "Mot de passe de connexion au client" : "Laisser vide pour ne pas changer"}><input className="abs-input" type="password" value={f.password} onChange={(e) => setF((s) => ({ ...s, password: e.target.value }))} placeholder="••••••••" /></FormRow>
        <FormRow label="Discord ID"><input className="abs-input abs-input--mono" value={f.discordId} onChange={(e) => setF((s) => ({ ...s, discordId: e.target.value }))} placeholder="000000000000000000" /></FormRow>
        <FormRow label="Grade"><Dropdown value={f.grade} onChange={(v) => setF((s) => ({ ...s, grade: v as User["grade"] }))} options={[{ value: "user", label: "User" }, { value: "reseller", label: "Reseller" }, { value: "admin", label: "Admin" }, { value: "owner", label: "Owner" }]} /></FormRow>
      </div>
    </Modal>
  );
}

function UserDrawer({ user, onClose, onEdit, onBlacklist }: { user: User; onClose: () => void; onEdit: (u: User) => void; onBlacklist: (u: User) => void }) {
  const { data, actions, confirm } = useApp();
  const router = useRouter();
  const [gen, setGen] = useState(false);
  const [specs, setSpecs] = useState<{ pcName: string } | null>(null);
  const lic = data.licenses.filter((l) => l.username === user.username);
  const mac = data.machines.filter((m) => m.username === user.username);
  const ses = data.sessions.filter((s) => s.username === user.username);
  const currentPcs = new Set(mac.map((m) => m.pcName));
  const history = ses.filter((s) => !currentPcs.has(s.pcName));
  const acts = data.audit.filter((e) => e.target === user.username || e.actor === user.username).slice(0, 6);
  const isBlacklisted = data.blacklist.some((b) => b.username === user.username);
  const activeLic = lic.filter((l) => l.status === "active").length;

  return (
    <Drawer eyebrow="Fiche · gestion rapide" title={user.username} onClose={onClose} width={500}
      footer={<>
        <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={() => onEdit(user)}><Pencil size={15} />Éditer</button>
        <button className="abs-btn abs-btn--md whip-btn-destructive" onClick={() => onBlacklist(user)} disabled={isBlacklisted}><Shield size={15} />{isBlacklisted ? "Déjà blacklisté" : "Blacklister"}</button>
      </>}>
      <div className="whip-userhero">
        <Avatar name={user.username} color={user.avatar} size={54} />
        <div>
          <div className="whip-userhero__name">{user.username}</div>
          <div className="whip-userhero__badges">
            <GradeBadge grade={user.grade} />
            {isBlacklisted && <span className="abs-badge abs-badge--revoked"><span className="abs-badge__dot" />blacklisté</span>}
          </div>
        </div>
      </div>

      <div className="whip-quickbar">
        <button className="whip-quickbtn" onClick={() => setGen(true)}><KeyRound size={16} /><span>Générer<br />licence</span></button>
        <button className="whip-quickbtn" onClick={async () => { if (await confirm({ title: "Réinitialiser le mot de passe ?", message: <>Un nouveau mot de passe sera généré pour <strong>{user.username}</strong>. L&apos;ancien cessera de fonctionner immédiatement.</>, confirmLabel: "Réinitialiser", tone: "danger" })) actions.resetPassword(user); }}><Lock size={16} /><span>Reset<br />password</span></button>
        <button className="whip-quickbtn" onClick={() => { onClose(); router.push(`/licenses?preset=user:${user.username}`); }}><KeyRound size={16} /><span>Voir<br />licences</span></button>
        <button className="whip-quickbtn" onClick={() => { onClose(); router.push(`/sessions?focus=${user.username}`); }}><Activity size={16} /><span>Voir<br />sessions</span></button>
      </div>

      <div className="whip-fieldgrid whip-fieldgrid--2">
        <Field label="Discord ID" mono>{user.discordId}</Field>
        <Field label="Membre depuis">{fmtDate(user.createdAt)}</Field>
        <Field label="Licences actives">{activeLic} / {lic.length}</Field>
        <Field label="Machines">{mac.length}</Field>
      </div>

      <DrawerSection title="Licences" count={lic.length} onAll={lic.length > 4 ? () => { onClose(); router.push(`/licenses?preset=user:${user.username}`); } : undefined}>
        {lic.length === 0 ? <p className="whip-muted">Aucune licence. <button className="whip-link" onClick={() => setGen(true)}>En générer une</button></p> : lic.slice(0, 5).map((l) => (
          <div key={l.id} className="whip-minirow whip-minirow--act">
            <span className="whip-minirow__main"><span className="whip-mono">{l.key}</span><StatusBadge status={l.status} /></span>
            <span className="whip-minirow__act">
              {l.status === "active"
                ? <IconButton tone="danger" title="Révoquer" icon={<Ban size={14} />} onClick={async () => { if (await confirm({ title: "Révoquer la licence ?", message: <>La clé <strong>{l.key}</strong> sera invalidée.</>, confirmLabel: "Révoquer" })) actions.revokeLicense(l); }} />
                : <IconButton tone="success" title="Réactiver" icon={<Check size={14} />} onClick={() => actions.restoreLicense(l)} />}
              <IconButton tone="info" title="Prolonger +30j" icon={<Clock size={14} />} onClick={() => actions.extendLicense(l, 30)} />
            </span>
          </div>
        ))}
      </DrawerSection>

      <DrawerSection title="Machines" count={mac.length}>
        {mac.length === 0 ? <p className="whip-muted">Aucune machine.</p> : mac.slice(0, 5).map((m) => (
          <div key={m.id} className="whip-minirow whip-minirow--act whip-minirow--click" onClick={() => setSpecs(m)} title="Voir les specs du PC">
            <span className="whip-minirow__main">
              <span className="whip-machicon whip-machicon--sm"><Monitor size={14} /></span>
              <span className="whip-twoline">
                <span className="whip-twoline__a" style={{ textTransform: "none", letterSpacing: 0 }}>{m.pcName} {m.status === "banned" && <span className="abs-badge abs-badge--revoked" style={{ marginLeft: 4 }}>banni</span>}</span>
                <span className="whip-twoline__b"><span className="whip-mono whip-mono--dim">{m.os.replace("Windows ", "Win ")}</span> · vue {timeAgo(m.lastActivity)}</span>
              </span>
            </span>
            <span className="whip-minirow__act">
              <IconButton tone="info" title="Voir les specs PC" icon={<Cpu size={14} />} onClick={() => setSpecs(m)} />
              <IconButton tone="info" title="Reset HWID" icon={<KeyRound size={14} />} onClick={async () => { if (await confirm({ title: "Réinitialiser le HWID ?", message: <>Le HWID de <strong>{m.pcName}</strong> sera réinitialisé.</>, confirmLabel: "Réinitialiser", tone: "danger" })) actions.resetHwid(m); }} />
              {m.status === "active"
                ? <IconButton tone="danger" title="Bannir" icon={<Ban size={14} />} onClick={async () => { if (await confirm({ title: "Bannir la machine ?", message: <>Le HWID de <strong>{m.pcName}</strong> sera bloqué.</>, confirmLabel: "Bannir" })) actions.banMachine(m); }} />
                : <IconButton tone="success" title="Réautoriser" icon={<Check size={14} />} onClick={() => actions.unbanMachine(m)} />}
            </span>
          </div>
        ))}
      </DrawerSection>

      <DrawerSection title="Historique des machines" count={history.length} onAll={history.length > 6 ? () => { onClose(); router.push(`/sessions?focus=${user.username}`); } : undefined}>
        {history.length === 0 ? <p className="whip-muted">Aucune autre machine que celles déjà liées.</p> : history.slice(0, 6).map((s) => (
          <div key={s.id} className="whip-histrow whip-histrow--click" onClick={() => setSpecs({ pcName: s.pcName })} title="Voir les specs du PC">
            <span className="whip-histrow__pc"><Monitor size={13} />{s.pcName}</span>
            <span className="whip-histrow__time whip-mono">{fmtDate(s.startedAt)}</span>
            <span className="whip-histrow__ip whip-mono whip-mono--dim">{s.ip}</span>
            {s.status === "active" ? <span className="abs-badge abs-badge--active"><span className="whip-livedot" />live</span> : <span className="whip-histrow__dur">{timeAgo(s.startedAt)}</span>}
            <Cpu size={13} className="whip-histrow__cfg" />
          </div>
        ))}
      </DrawerSection>

      <DrawerSection title="Activité liée" count={acts.length}>
        {acts.length === 0 ? <p className="whip-muted">Aucune activité.</p> : acts.map((e) => <AuditRow key={e.id} e={e} compact />)}
      </DrawerSection>

      {gen && <GenerateModal preUser={user.username} onClose={() => setGen(false)} />}
      {specs && <SpecsView machine={specs} onClose={() => setSpecs(null)} />}
    </Drawer>
  );
}

function UsersInner() {
  const { data, actions, confirm } = useApp();
  const params = useSearchParams();
  const router = useRouter();
  const [modal, setModal] = useState<{ user?: User; new?: boolean } | null>(null);
  const [drawer, setDrawer] = useState<User | null>(null);
  const [blState, setBlState] = useState<User | null>(null);

  useEffect(() => {
    if (params.get("action") === "create") setModal({ new: true });
    const focus = params.get("focus");
    if (focus) {
      const u = data.users.find((x) => x.username === focus);
      if (u) setDrawer(u);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  const rows = useMemo(() => data.users.map((u) => ({ ...u, blacklisted: data.blacklist.some((b) => b.username === u.username) })), [data.users, data.blacklist]);
  type Row = (typeof rows)[number];

  const columns: Column<Row>[] = [
    { key: "username", label: "Utilisateur", sortable: true, render: (r) => <span className="whip-usercell"><Avatar name={r.username} color={r.avatar} size={30} /><span><span className="whip-usercell__name">{r.username}</span>{r.blacklisted && <span className="whip-usercell__tag">blacklisté</span>}</span></span> },
    { key: "grade", label: "Grade", width: 120, render: (r) => <GradeBadge grade={r.grade} /> },
    { key: "discordId", label: "Discord ID", width: 180, render: (r) => <Copyable value={r.discordId} /> },
    { key: "licenseCount", label: "Licences", align: "center", sortable: true, width: 100, render: (r) => <span className="whip-countpill">{r.licenseCount}</span> },
    { key: "machineCount", label: "Machines", align: "center", sortable: true, width: 100, render: (r) => <span className="whip-countpill whip-countpill--muted">{r.machineCount}</span> },
    { key: "createdAt", label: "Création", sortable: true, width: 120, sortValue: (r) => new Date(r.createdAt).getTime(), render: (r) => <span className="whip-mono whip-mono--dim" style={{ fontSize: 12 }}>{fmtDate(r.createdAt)}</span> },
  ];
  const filters = [{ key: "grade", label: "Grade", options: [["user", "User"], ["reseller", "Reseller"], ["admin", "Admin"], ["owner", "Owner"]].map(([value, label]) => ({ value, label })) }];

  const rowActions = (r: Row) => (
    <>
      <IconButton tone="info" title="Ouvrir la fiche" icon={<Eye size={15} />} onClick={() => setDrawer(r)} />
      <IconButton title="Éditer" icon={<Pencil size={15} />} onClick={() => setModal({ user: r })} />
      <IconButton tone="danger" title="Supprimer" icon={<Trash size={15} />} onClick={async () => { if (await confirm({ title: "Supprimer cet utilisateur ?", message: <>L&apos;utilisateur <strong>{r.username}</strong> et ses accès seront supprimés définitivement.</>, confirmLabel: "Supprimer" })) actions.deleteUser(r); }} />
    </>
  );
  const bulkActions: BulkAction<Row>[] = [
    { label: "Blacklister", icon: <Shield size={14} />, tone: "danger", onClick: async (sel, clear) => { if (await confirm({ title: `Blacklister ${sel.length} utilisateurs ?`, message: "Ils perdront immédiatement l'accès au client.", confirmLabel: "Blacklister" })) { sel.forEach((u) => actions.blacklistUser({ username: u.username, reason: "Bulk blacklist", expiresAt: null })); clear(); } } },
    { label: "Supprimer", icon: <Trash size={14} />, tone: "danger", onClick: async (sel, clear) => { if (await confirm({ title: `Supprimer ${sel.length} utilisateurs ?`, message: "Action irréversible.", confirmLabel: "Supprimer" })) { sel.forEach((u) => actions.deleteUser(u)); clear(); } } },
  ];

  return (
    <>
      <PageHeader title="Utilisateurs" eyebrow="Whip or get whipped" actions={<><RefreshButton /><button className="abs-btn abs-btn--primary abs-btn--md" onClick={() => setModal({ new: true })}><Plus size={16} />Ajouter</button></>} />
      <DataTable columns={columns} rows={rows} rowKey="id" searchKeys={["username", "discordId"]} searchPlaceholder="Rechercher par nom ou ID Discord…" filters={filters} rowActions={rowActions} bulkActions={bulkActions} onRowClick={(r) => setDrawer(r)} pageSize={11} defaultSort={{ key: "createdAt", dir: -1 }} />
      {modal && <UserModal user={modal.user || null} onClose={() => setModal(null)} />}
      {blState && <BlacklistModal preUser={blState.username} onClose={() => setBlState(null)} />}
      {drawer && <UserDrawer user={drawer} onClose={() => setDrawer(null)} onEdit={(u) => { setDrawer(null); setModal({ user: u }); }} onBlacklist={(u) => { setDrawer(null); setBlState(u); }} />}
    </>
  );
}

export default function UsersPage() {
  return (
    <Suspense fallback={null}>
      <UsersInner />
    </Suspense>
  );
}
