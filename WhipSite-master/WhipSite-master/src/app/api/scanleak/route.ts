import { NextResponse, type NextRequest } from "next/server";
import { scanWatermark } from "@/lib/server/actions/watermark";

// Binary uploads (DLL / loader / memory dump) go through a route handler
// instead of a server action: route handlers stream the body (no 1MB server
// action cap) and return the REAL error message instead of Next's masked one.
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    // CSRF: this route is excluded from middleware, so check origin here.
    const origin = req.headers.get("origin");
    const host = req.headers.get("host");
    if (origin && host && new URL(origin).host !== host) {
      return NextResponse.json({ error: "Origine non autorisée" }, { status: 403 });
    }
    const formData = await req.formData();
    const result = await scanWatermark(formData);
    return NextResponse.json(result);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    const status = message === "Non autorisé" ? 401 : 400;
    return NextResponse.json({ error: message }, { status });
  }
}
