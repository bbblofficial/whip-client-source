import type { LucideIcon } from "lucide-react";
import {
  LayoutGrid,
  TrendingUp,
  ScrollText,
  Users,
  KeyRound,
  Monitor,
  Activity,
  Package,
  FileCode,
  Download,
  Shield,
  Fingerprint,
} from "lucide-react";

export interface NavItem {
  id: string;
  label: string;
  href: string;
  icon: LucideIcon;
  danger?: boolean;
  badgeKey?: "sessions" | "audit";
}
export interface NavGroup {
  group: string;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    group: "Vue d'ensemble",
    items: [
      { id: "dashboard", label: "Dashboard", href: "/dashboard", icon: LayoutGrid },
      { id: "stats", label: "Stats", href: "/stats", icon: TrendingUp },
      { id: "audit", label: "Journal d'audit", href: "/audit", icon: ScrollText, badgeKey: "audit" },
    ],
  },
  {
    group: "Gestion",
    items: [
      { id: "users", label: "Utilisateurs", href: "/users", icon: Users },
      { id: "licenses", label: "Licences", href: "/licenses", icon: KeyRound },
      { id: "machines", label: "Machines", href: "/machines", icon: Monitor },
      { id: "sessions", label: "Sessions", href: "/sessions", icon: Activity, badgeKey: "sessions" },
    ],
  },
  {
    group: "Catalogue",
    items: [
      { id: "products", label: "Produits", href: "/products", icon: Package },
      { id: "configs", label: "Configs", href: "/configs", icon: FileCode },
      { id: "downloads", label: "Downloads", href: "/downloads", icon: Download },
    ],
  },
  {
    group: "Sécurité",
    items: [
      { id: "blacklist", label: "Blacklist", href: "/blacklist", icon: Shield, danger: true },
      { id: "scanleak", label: "Scan Leak", href: "/scanleak", icon: Fingerprint },
    ],
  },
];

export const NAV_FLAT = NAV.flatMap((g) => g.items);
