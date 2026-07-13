"use client";
import { useMemo, useState } from "react";
import { Plus, Pencil, Search, Package, Shield, KeyRound } from "lucide-react";
import { useApp } from "@/components/app-provider";
import { PageHeader, IconButton, FormRow } from "@/components/ui/primitives";
import { RefreshButton } from "@/components/ui/RefreshButton";
import { Modal } from "@/components/ui/overlays";
import { fmtNum } from "@/lib/utils";
import type { Product } from "@/lib/types";

function ProductModal({ product, onClose }: { product: Product | null; onClose: () => void }) {
  const isNew = !product;
  const { actions } = useApp();
  const [f, setF] = useState({ name: product?.name || "", code: product?.code || "", desc: product?.description || "" });
  return (
    <Modal eyebrow={isNew ? "nouveau produit" : "produit"} title={isNew ? "Ajouter produit" : "Modifier produit"} onClose={onClose} size="md"
      footer={<>
        <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={onClose}>Annuler</button>
        <button className="abs-btn abs-btn--primary abs-btn--md" onClick={() => { if (!f.name) return; actions.saveProduct(product, { name: f.name }, isNew); onClose(); }}>Sauvegarder</button>
      </>}>
      <div className="whip-form">
        <FormRow label="Nom du produit"><input className="abs-input" value={f.name} onChange={(e) => setF((s) => ({ ...s, name: e.target.value }))} /></FormRow>
        <FormRow label="Code unique (ID)"><input className="abs-input abs-input--mono" value={f.code} onChange={(e) => setF((s) => ({ ...s, code: e.target.value }))} placeholder="WHIP_XXXX" /></FormRow>
        <FormRow label="Description"><textarea className="abs-input whip-textarea" value={f.desc} onChange={(e) => setF((s) => ({ ...s, desc: e.target.value }))} rows={3} /></FormRow>
      </div>
    </Modal>
  );
}

export default function ProductsPage() {
  const { data } = useApp();
  const [modal, setModal] = useState<{ product?: Product; new?: boolean } | null>(null);
  const [q, setQ] = useState("");
  const counts = useMemo(() => {
    const m: Record<string, number> = {};
    data.licenses.forEach((l) => (m[l.productCode] = (m[l.productCode] || 0) + 1));
    return m;
  }, [data.licenses]);
  const list = data.products.filter((p) => !q || p.name.toLowerCase().includes(q.toLowerCase()) || p.code.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <PageHeader title="Produits" eyebrow="Whip or get whipped" actions={<><RefreshButton /><button className="abs-btn abs-btn--primary abs-btn--md" onClick={() => setModal({ new: true })}><Plus size={16} />Ajouter</button></>} />
      <div className="whip-search whip-search--standalone" style={{ marginBottom: 18 }}>
        <Search size={16} className="whip-search__ic" />
        <input className="whip-search__input" placeholder="Rechercher par nom ou code…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="whip-prodgrid">
        {list.map((p) => (
          <div key={p.code} className="whip-prodcard" onClick={() => setModal({ product: p })}>
            <div className="whip-prodcard__top">
              <span className="whip-prodcard__icon">{p.icon === "shield" ? <Shield size={24} /> : <Package size={24} />}</span>
              <IconButton title="Éditer" icon={<Pencil size={15} />} onClick={() => setModal({ product: p })} />
            </div>
            <div className="whip-prodcard__title">{p.name} <span className="abs-tag abs-tag--premium">{p.code}</span></div>
            <div className="whip-prodcard__desc">{p.description}</div>
            <div className="whip-prodcard__foot">
              <span className="whip-prodcard__lic"><KeyRound size={13} /><strong>{fmtNum(counts[p.code] || 0)}</strong> licences</span>
              <span className="whip-prodcard__date whip-mono">SYSTÈME</span>
            </div>
          </div>
        ))}
      </div>
      {modal && <ProductModal product={modal.product || null} onClose={() => setModal(null)} />}
    </>
  );
}
