"use server";

import prisma from "@/lib/server/prisma";
import { requireAdmin } from "@/lib/server/auth";

// === DLL watermark sentinel ===
// 8-byte non-printable sentinel — must stay byte-identical to the
// corresponding constants in WhipClient/src/DllMain.cpp,
// WhipServer/.../WatermarkService.java and ScanLeakTool.java.
const DLL_SENTINEL = new Uint8Array([0xC7, 0xA3, 0x91, 0x4E, 0xF8, 0x52, 0xB6, 0xD0]);
const UUID_BYTES_LEN = 16;

// === Loader exe overlay (LoaderPatcher v5) ===
// Layout appended to the END of WhipLoader.exe by WhipBot:
//   MAGIC[4] = "WHIP"          ASCII
//   VERSION[2] = 5              little-endian
//   obfDownloadId[16]            = downloadIdBytes XOR downloadIdSalt
//   timestamp[8]                 little-endian millis
//   downloadIdSalt[16]
//   obfAuthSalt[16] + authSaltKey[16]
//   obfAlgoSeed[32] + algoSeedKey[32]
//   obfCodeFingerprint[32] + codeFingerprintKey[32]  ← ajouté en v5 (Phase 3)
// Total overlay = 206 bytes. We only need the first 4+2+16+8+16 = 46
// to recover the downloadId.
const LOADER_MAGIC = new Uint8Array([0x57, 0x48, 0x49, 0x50]); // "WHIP"
const LOADER_VERSION = 5;

export type ScanResult =
    | {
          status: "no-magic";
          fileSize: number;
      }
    | {
          status: "no-match";
          fileSize: number;
          magicOffset: number;
          sessionUuid: string;
          kind: "dll";
      }
    | {
          status: "match";
          fileSize: number;
          magicOffset: number;
          sessionUuid: string;
          kind: "dll";
          watermark: {
              userId: string | null;
              username: string | null;
              discordId: string | null;
              hwid: string | null;
              ip: string | null;
              pcName: string | null;
              downloadId: string | null;
              createdAt: string;
          };
      }
    | {
          status: "no-match";
          fileSize: number;
          magicOffset: number;
          downloadId: string;
          kind: "loader";
      }
    | {
          status: "match";
          fileSize: number;
          magicOffset: number;
          downloadId: string;
          kind: "loader";
          download: {
              id: string;
              userId: string | null;
              username: string | null;
              discordId: string | null;
              productCode: string | null;
              productName: string | null;
              ip: string | null;
              downloadedAt: string;
              firstUsedAt: string | null;
              lastUsedAt: string | null;
              useCount: number;
              revoked: boolean;
          };
      };

/**
 * Scan a binary (DLL, loader.exe, dump, .bin) for either the WhipClient
 * watermark sentinel OR the WhipLoader overlay v4 magic, look up the
 * embedded identity in the corresponding table, return the attribution.
 *
 * 64 MB cap to keep memory footprint reasonable. See
 * `WhipLoader/DUMP_THREAT_MODEL.md §5.3`.
 */
export async function scanWatermark(formData: FormData): Promise<ScanResult> {
    await requireAdmin();

    const file = formData.get("file");
    if (!(file instanceof File)) {
        throw new Error("file field missing or not a File");
    }
    if (file.size > 64 * 1024 * 1024) {
        throw new Error("file too large (max 64 MB)");
    }

    const buf = new Uint8Array(await file.arrayBuffer());

    // 1. Try DLL sentinel first.
    const dllOff = findBytes(buf, DLL_SENTINEL,
        DLL_SENTINEL.length + UUID_BYTES_LEN + 8);
    if (dllOff >= 0) {
        return await lookupDllWatermark(buf, dllOff);
    }

    // 2. Try Loader overlay magic. Scan from end since the overlay sits
    //    at the very tail of the file (after random padding).
    const loaderOff = findLoaderOverlay(buf);
    if (loaderOff >= 0) {
        return await lookupLoaderDownload(buf, loaderOff);
    }

    return { status: "no-magic", fileSize: buf.length };
}

async function lookupDllWatermark(
    buf: Uint8Array,
    magicOffset: number,
): Promise<ScanResult> {
    const uuidBytes = buf.slice(
        magicOffset + DLL_SENTINEL.length,
        magicOffset + DLL_SENTINEL.length + UUID_BYTES_LEN,
    );
    const sessionUuid = bytesToUuid(uuidBytes);

    const row = await prisma.dllWatermark.findUnique({
        where: { session_uuid: sessionUuid },
    });

    if (!row) {
        return {
            status: "no-match",
            fileSize: buf.length,
            magicOffset,
            sessionUuid,
            kind: "dll",
        };
    }

    let username: string | null = null;
    if (row.user_id) {
        const user = await prisma.user.findUnique({
            where: { id: row.user_id },
            select: { username: true },
        });
        username = user?.username ?? null;
    }

    return {
        status: "match",
        fileSize: buf.length,
        magicOffset,
        sessionUuid,
        kind: "dll",
        watermark: {
            userId: row.user_id,
            username,
            discordId: row.discord_id,
            hwid: row.hwid,
            ip: row.ip,
            pcName: row.pc_name,
            downloadId: row.download_id,
            createdAt: row.created_at.toISOString(),
        },
    };
}

async function lookupLoaderDownload(
    buf: Uint8Array,
    magicOffset: number,
): Promise<ScanResult> {
    // Layout from magicOffset:
    //   +0   MAGIC[4] = "WHIP"
    //   +4   VERSION[2] LE = 5
    //   +6   obfDownloadId[16]
    //   +22  timestamp[8]
    //   +30  downloadIdSalt[16]
    const obfDownloadId = buf.slice(magicOffset + 6, magicOffset + 22);
    const downloadIdSalt = buf.slice(magicOffset + 30, magicOffset + 46);
    const downloadIdBytes = new Uint8Array(UUID_BYTES_LEN);
    for (let i = 0; i < UUID_BYTES_LEN; i++) {
        downloadIdBytes[i] = obfDownloadId[i] ^ downloadIdSalt[i];
    }
    // WhipBot stores download_id as the 32-char uppercase hex of these
    // 16 bytes (UUID.randomUUID().toString().replace("-","").toUpperCase()).
    const downloadId = bytesToHexUpper(downloadIdBytes);

    const row = await prisma.download.findUnique({
        where: { download_id: downloadId },
        include: {
            user: { select: { id: true, username: true, discord_id: true } },
            product: { select: { code: true, name: true } },
        },
    });

    if (!row) {
        return {
            status: "no-match",
            fileSize: buf.length,
            magicOffset,
            downloadId,
            kind: "loader",
        };
    }

    return {
        status: "match",
        fileSize: buf.length,
        magicOffset,
        downloadId,
        kind: "loader",
        download: {
            id: row.id,
            userId: row.user?.id ?? null,
            username: row.user?.username ?? null,
            discordId: row.user?.discord_id ?? null,
            productCode: row.product?.code ?? null,
            productName: row.product?.name ?? null,
            ip: row.ip_address,
            downloadedAt: row.downloaded_at.toISOString(),
            firstUsedAt: row.first_used_at?.toISOString() ?? null,
            lastUsedAt: row.last_used_at?.toISOString() ?? null,
            useCount: row.use_count,
            revoked: row.revoked,
        },
    };
}

/**
 * Linear scan for a byte sequence with required trailing room.
 * Returns first occurrence offset, or -1.
 */
function findBytes(buf: Uint8Array, needle: Uint8Array, minRoom: number): number {
    outer: for (let i = 0; i + minRoom <= buf.length; i++) {
        for (let j = 0; j < needle.length; j++) {
            if (buf[i + j] !== needle[j]) continue outer;
        }
        return i;
    }
    return -1;
}

/**
 * Find the loader overlay: magic "WHIP" followed by little-endian
 * version=4. Scans from end-of-file backwards for efficiency since the
 * overlay always sits at the file's tail.
 */
function findLoaderOverlay(buf: Uint8Array): number {
    // Need at least 4+2+16+8+16 = 46 bytes after the magic.
    const minRoom = 46;
    if (buf.length < minRoom) return -1;
    for (let i = buf.length - minRoom; i >= 0; i--) {
        if (
            buf[i] === LOADER_MAGIC[0] &&
            buf[i + 1] === LOADER_MAGIC[1] &&
            buf[i + 2] === LOADER_MAGIC[2] &&
            buf[i + 3] === LOADER_MAGIC[3]
        ) {
            const version = buf[i + 4] | (buf[i + 5] << 8);
            if (version === LOADER_VERSION) return i;
        }
    }
    return -1;
}

function bytesToUuid(bytes: Uint8Array): string {
    const hex: string[] = [];
    for (let i = 0; i < bytes.length; i++) {
        hex.push(bytes[i].toString(16).padStart(2, "0"));
    }
    return [
        hex.slice(0, 4).join(""),
        hex.slice(4, 6).join(""),
        hex.slice(6, 8).join(""),
        hex.slice(8, 10).join(""),
        hex.slice(10, 16).join(""),
    ].join("-");
}

function bytesToHexUpper(bytes: Uint8Array): string {
    const hex: string[] = [];
    for (let i = 0; i < bytes.length; i++) {
        hex.push(bytes[i].toString(16).padStart(2, "0").toUpperCase());
    }
    return hex.join("");
}
