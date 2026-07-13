import { redirect } from "next/navigation";
import { AppProvider, type SessionUser } from "@/components/app-provider";
import { Shell } from "@/components/shell/Shell";
import { getSession } from "@/lib/server/auth";
import { getPanelData } from "@/lib/server/panel-data";
import { mapGrade } from "@/lib/server/mappers";

// Authenticated zone. Verifies the signed session (signature + DB + grade),
// then loads the live dataset and hands it to the client AppProvider.
export default async function PanelLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();
  if (!session) redirect("/login");

  const user: SessionUser = { username: session.username, grade: mapGrade(session.grade) };
  const initial = await getPanelData();

  return (
    <AppProvider user={user} initial={initial}>
      <Shell>{children}</Shell>
    </AppProvider>
  );
}
