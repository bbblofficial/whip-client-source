"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { User, Lock, ArrowUpRight, AlertTriangle } from "lucide-react";
import { Constellation } from "@/components/shell/Constellation";
import { LogoMark } from "@/components/shell/brand";
import { login } from "@/lib/server/auth";

export default function LoginPage() {
  const router = useRouter();
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!u.trim()) {
      setErr("Identité requise.");
      return;
    }
    setLoading(true);
    setErr("");
    try {
      const fd = new FormData();
      fd.set("username", u);
      fd.set("password", p);
      const res = await login(fd);
      if (res?.error) {
        setErr(res.error);
        setLoading(false);
        return;
      }
      router.push("/dashboard");
      router.refresh();
    } catch {
      setErr("Une erreur est survenue lors de la connexion.");
      setLoading(false);
    }
  };

  return (
    <div className="whip-login">
      <Constellation />
      <form className="whip-login__card-wrap" onSubmit={submit}>
        <div className="whip-login__brand">
          <LogoMark size={92} />
          <div className="whip-login__name">WHIP</div>
          <div className="whip-login__tag">WHIP OR GET WHIPPED</div>
        </div>
        <div className="whip-login__card">
          <label className="whip-login__label">
            <User size={14} /> Identité
          </label>
          <input className="whip-login__input" value={u} onChange={(e) => setU(e.target.value)} placeholder="Nom d'utilisateur" autoFocus />
          <label className="whip-login__label">
            <Lock size={14} /> Clé secrète
          </label>
          <input className="whip-login__input" type="password" value={p} onChange={(e) => setP(e.target.value)} placeholder="••••••••" />
          {err && (
            <div className="whip-login__err">
              <AlertTriangle size={14} />
              {err}
            </div>
          )}
          <button className="abs-btn abs-btn--primary abs-btn--lg abs-btn--block" type="submit" disabled={loading} style={{ marginTop: 6 }}>
            {loading ? "Vérification…" : (
              <>
                Autoriser <ArrowUpRight size={16} />
              </>
            )}
          </button>
        </div>
        <div className="whip-login__foot">SYSTÈME DE CONTRÔLE MÉTALLIQUE V1.1</div>
      </form>
    </div>
  );
}
