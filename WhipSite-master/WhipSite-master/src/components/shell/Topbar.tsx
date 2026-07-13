"use client";
import { Search, Bell, RefreshCw } from "lucide-react";
import { Kbd } from "@/components/ui/primitives";
import { useApp } from "@/components/app-provider";
import { cn } from "@/lib/utils";

export function Topbar({
  onOpenPalette,
  notifCount,
  onBell,
}: {
  onOpenPalette: () => void;
  notifCount: number;
  onBell: () => void;
}) {
  const { refresh, refreshing } = useApp();
  return (
    <div className="whip-topbar">
      <button className="whip-omnibox" onClick={onOpenPalette}>
        <Search size={15} />
        <span className="whip-omnibox__text">Rechercher un utilisateur, une licence, un HWID…</span>
        <span className="whip-omnibox__kbd">
          <Kbd>⌘</Kbd>
          <Kbd>K</Kbd>
        </span>
      </button>
      <div className="whip-topbar__right">
        <button
          className="whip-topicon"
          title="Actualiser les données"
          onClick={() => void refresh()}
          disabled={refreshing}
        >
          <RefreshCw size={17} className={cn(refreshing && "whip-spin")} />
        </button>
        <button className="whip-topicon" title="Notifications" onClick={onBell}>
          <Bell size={18} />
          {notifCount > 0 && <span className="whip-topicon__dot">{notifCount > 9 ? "9+" : notifCount}</span>}
        </button>
      </div>
    </div>
  );
}
