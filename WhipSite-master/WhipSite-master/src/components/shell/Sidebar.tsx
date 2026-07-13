"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { LogOut } from "lucide-react";
import { cn } from "@/lib/utils";
import { NAV } from "./nav";
import { BrandLockup } from "./brand";
import { Avatar } from "@/components/ui/primitives";
import { useApp } from "@/components/app-provider";
import { logout } from "@/lib/server/auth";

export function Sidebar({ counts }: { counts: { sessions: number; audit: number } }) {
  const pathname = usePathname();
  const { user } = useApp();
  return (
    <aside className="whip-sidebar">
      <div className="whip-sidebar__brandzone">
        <BrandLockup />
      </div>
      <nav className="whip-nav">
        {NAV.map((g) => (
          <div key={g.group} className="whip-nav__group">
            <div className="whip-nav__grouplabel">{g.group}</div>
            {g.items.map((it) => {
              const Icon = it.icon;
              const isActive = pathname === it.href;
              const badge = it.badgeKey ? counts[it.badgeKey] : null;
              return (
                <Link
                  key={it.id}
                  href={it.href}
                  className={cn(
                    "whip-navitem",
                    isActive && "whip-navitem--active",
                    it.danger && "whip-navitem--danger",
                  )}
                >
                  <Icon size={17} className="whip-navitem__icon" />
                  <span className="whip-navitem__label">{it.label}</span>
                  {badge != null && badge > 0 && (
                    <span className={cn("whip-navitem__badge", it.id === "sessions" && "whip-navitem__badge--live")}>
                      {badge}
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>
      <div className="whip-sidebar__foot">
        <div className="whip-userchip">
          <Avatar name={user.username} color="#2563eb" size={36} />
          <div className="whip-userchip__meta">
            <div className="whip-userchip__name">{user.username}</div>
            <div className="whip-userchip__role">{user.grade}</div>
          </div>
        </div>
        <form action={logout}>
          <button type="submit" className="whip-logout" style={{ width: "100%" }}>
            <LogOut size={16} />
            <span>Déconnexion</span>
          </button>
        </form>
      </div>
    </aside>
  );
}
