"use server";

import prisma from "@/lib/server/prisma";
import { requireAdmin } from "@/lib/server/auth";
import { revalidatePath } from "next/cache";

const DAY_MS = 24 * 60 * 60 * 1000;

export async function getAdvancedStats() {
    await requireAdmin();
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * DAY_MS);

    const [
        licenseStatusDist,
        osDist,
        productPerformance,
        licenseGrowth,
        sessionsLast30d,
        topUsersRaw,
        totalAllTime,
    ] = await Promise.all([
        prisma.license.groupBy({
            by: ["status"],
            _count: { _all: true },
        }),
        prisma.machine.groupBy({
            by: ["os"],
            _count: { _all: true },
        }),
        prisma.product.findMany({
            include: {
                _count: { select: { licenses: { where: { status: "active" } } } },
            },
        }),
        prisma.license.findMany({
            where: { created_at: { gte: thirtyDaysAgo } },
            select: { created_at: true },
        }),
        // Sessions in the last 30 days only — was previously counting
        // ALL sessions ever and dividing by 30, which over-stated the
        // average for new installs and under-stated it for old ones.
        prisma.session.findMany({
            where: { started_at: { gte: thirtyDaysAgo } },
            select: { started_at: true, license_id: true },
        }),
        // Top users by session count — was previously fetching the
        // first 5 users in arbitrary order (no orderBy) and reducing
        // their licenses' session counts client-side. Now uses raw SQL
        // groupBy + manual join so we actually rank by sessions.
        prisma.$queryRaw<{ username: string; sessions: bigint }[]>`
            SELECT u.username,
                   COUNT(s.id) AS sessions
            FROM users u
            LEFT JOIN licenses l ON l.user_id = u.id
            LEFT JOIN sessions s ON s.license_id = l.id
            GROUP BY u.username
            HAVING COUNT(s.id) > 0
            ORDER BY sessions DESC
            LIMIT 10
        `,
        prisma.session.count(),
    ]);

    const totalLast30d = sessionsLast30d.length;
    // Avg/day computed over the actual span we observed sessions in
    // (cap 30 d). For a 1-week-old user with 21 sessions, this gives
    // ~3/day, not 21/30 = 0.7/day.
    const oldestStart = sessionsLast30d.reduce<number | null>((min, s) => {
        const t = s.started_at.getTime();
        return min === null || t < min ? t : min;
    }, null);
    const observedDays = oldestStart
        ? Math.max(1, Math.ceil((now.getTime() - oldestStart) / DAY_MS))
        : 1;
    const avgPerDay = totalLast30d / Math.min(30, observedDays);

    return {
        licenseStatus: licenseStatusDist.map((d: any) => ({
            label: d.status,
            count: d._count._all,
        })),
        osDistribution: osDist.map((d: any) => ({
            label: d.os,
            count: d._count._all,
        })),
        products: productPerformance.map((p: any) => ({
            name: p.name,
            active: p._count.licenses,
        })),
        growth: processGrowth(licenseGrowth),
        sessionsByDay: processSessions(sessionsLast30d),
        totalLaunches: totalAllTime,
        totalLaunches30d: totalLast30d,
        topUsers: topUsersRaw.map((r) => ({
            username: r.username,
            sessions: Number(r.sessions),
        })),
        avgLaunchesPerDay: avgPerDay.toFixed(1),
        observedDays,
    };
}

/**
 * Per-user session stats — used by the row-level "Reset stats" button
 * in /admin/users so admins can wipe an individual's session history
 * without nuking the whole table.
 */
export async function getUserStats(userId: string) {
    await requireAdmin();
    const totalSessions = await prisma.session.count({
        where: { license: { user_id: userId } },
    });
    const totalDownloads = await prisma.download.count({
        where: { user_id: userId },
    });
    return { totalSessions, totalDownloads };
}

/**
 * Reset stats for a single user — deletes all sessions tied to any of
 * their licenses + all their downloads. Does NOT touch the user, their
 * licenses, or their machines.
 */
export async function resetUserStats(userId: string) {
    await requireAdmin();
    const result = await prisma.$transaction(async (tx) => {
        const sessions = await tx.session.deleteMany({
            where: { license: { user_id: userId } },
        });
        const downloads = await tx.download.deleteMany({
            where: { user_id: userId },
        });
        return { sessions: sessions.count, downloads: downloads.count };
    });
    revalidatePath("/admin/stats");
    revalidatePath("/admin/users");
    revalidatePath("/admin/sessions");
    return result;
}

/**
 * Global wipe — deletes ALL sessions and ALL downloads. Use only on
 * dev / for fresh-start testing. Admin-gated as everything else.
 */
export async function resetAllStats() {
    await requireAdmin();
    const result = await prisma.$transaction(async (tx) => {
        const sessions = await tx.session.deleteMany({});
        const downloads = await tx.download.deleteMany({});
        return { sessions: sessions.count, downloads: downloads.count };
    });
    revalidatePath("/admin/stats");
    revalidatePath("/admin/users");
    revalidatePath("/admin/sessions");
    return result;
}

function processGrowth(data: { created_at: Date }[]) {
    const days: Record<string, number> = {};
    for (const item of data) {
        const date = item.created_at.toISOString().split("T")[0];
        days[date] = (days[date] || 0) + 1;
    }
    return Object.entries(days)
        .map(([date, count]) => ({ date, count }))
        .sort((a, b) => a.date.localeCompare(b.date));
}

function processSessions(data: { started_at: Date }[]) {
    const days: Record<string, number> = {};
    for (const item of data) {
        const date = item.started_at.toISOString().split("T")[0];
        days[date] = (days[date] || 0) + 1;
    }
    return Object.entries(days)
        .map(([date, count]) => ({ date, count }))
        .sort((a, b) => a.date.localeCompare(b.date));
}
