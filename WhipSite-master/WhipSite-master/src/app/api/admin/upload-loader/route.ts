import { NextResponse } from "next/server";
import * as fs from "fs";
import { requireAdmin } from "@/lib/server/auth";
import prisma from "@/lib/server/prisma";
import { logAction } from "@/lib/server/logger";
import { notifySync } from "@/lib/server/sync";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(req: Request) {
  let adminId: string;
  try {
    const a = await requireAdmin();
    adminId = a.userId;
  } catch {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const exePath = process.env.LOADER_EXE_PATH;
  if (!exePath) {
    return NextResponse.json({ error: "LOADER_EXE_PATH not configured" }, { status: 503 });
  }

  let formData: FormData;
  try {
    formData = await req.formData();
  } catch {
    return NextResponse.json({ error: "Invalid form data" }, { status: 400 });
  }

  const file = formData.get("file") as File | null;
  if (!file) {
    return NextResponse.json({ error: "No file provided" }, { status: 400 });
  }
  if (!file.name.endsWith(".exe")) {
    return NextResponse.json({ error: "File must be a .exe" }, { status: 400 });
  }

  let buffer: Buffer;
  try {
    buffer = Buffer.from(await file.arrayBuffer());
    fs.writeFileSync(exePath, buffer);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: `Échec écriture: ${message}` }, { status: 500 });
  }

  try {
    const result = await prisma.download.updateMany({
      where: { revoked: false },
      data: { revoked: true, revoke_reason: "Please update the loader" },
    });

    await notifySync("download", "update");
    await logAction(adminId, "loader.deploy", "download", null, `${file.name} (${buffer.length} bytes) — ${result.count} downloads révoqués`);

    return NextResponse.json({ success: true, revoked: result.count, bytes: buffer.length });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: `Échec DB: ${message}` }, { status: 500 });
  }
}
