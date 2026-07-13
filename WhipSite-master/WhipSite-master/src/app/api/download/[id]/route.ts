import { NextResponse } from "next/server";
import * as fs from "fs";
import { requireAdmin } from "@/lib/server/auth";
import prisma from "@/lib/server/prisma";
import { patchLoader, generateFilename } from "@/lib/server/patcher";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    await requireAdmin();
  } catch {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;

  const download = await prisma.download.findUnique({ where: { id } });
  if (!download) return NextResponse.json({ error: "Not found" }, { status: 404 });
  if (download.revoked) return NextResponse.json({ error: "Download is revoked" }, { status: 410 });

  const exePath = process.env.LOADER_EXE_PATH;
  if (!exePath || !fs.existsSync(exePath)) {
    return NextResponse.json({ error: "LOADER_EXE_PATH not configured" }, { status: 503 });
  }

  const base = fs.readFileSync(exePath);
  const patched = patchLoader(
    base,
    download.download_id,
    download.auth_salt,
    download.algo_seed,
    download.expected_fingerprint,
  );

  const filename = generateFilename();

  const ab = patched.buffer.slice(patched.byteOffset, patched.byteOffset + patched.byteLength) as ArrayBuffer;
  return new NextResponse(ab, {
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Content-Length": String(patched.byteLength),
    },
  });
}
