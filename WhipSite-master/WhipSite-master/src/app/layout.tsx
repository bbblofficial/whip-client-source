import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "WHIP · System Control",
  description: "Panel d'administration — système de licensing account-bound.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
