"use client";
// Shared "Actualiser" button: re-pulls the whole panel dataset in place
// (via AppProvider.refresh) — no full page reload. Drop it in any
// PageHeader actions slot.
import { RefreshCw } from "lucide-react";
import { useApp } from "@/components/app-provider";
import { cn } from "@/lib/utils";

export function RefreshButton({ label = "Actualiser" }: { label?: string }) {
  const { refresh, refreshing } = useApp();
  return (
    <button
      className="abs-btn abs-btn--secondary abs-btn--md"
      onClick={() => void refresh()}
      disabled={refreshing}
      title="Actualiser les données"
    >
      <RefreshCw size={15} className={cn(refreshing && "whip-spin")} />
      {label}
    </button>
  );
}
