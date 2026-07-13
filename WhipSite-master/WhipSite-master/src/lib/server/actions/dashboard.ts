"use server";

import prisma from "@/lib/server/prisma";
import { requireAdmin } from "@/lib/server/auth";

export async function getDashboardStats() {
    await requireAdmin();
    try {
        const [userCount, productCount, licenseCount, activeSessions] = await Promise.all([
            prisma.user.count(),
            prisma.product.count(),
            prisma.license.count({ where: { status: "active" } }),
            prisma.session.count({ where: { ended_at: null } })
        ]);

        const recentActivity = await prisma.auditLog.findMany({
            orderBy: { created_at: "desc" },
            take: 5,
        });

        return {
            stats: [
                { label: "Utilisateurs", value: userCount.toString(), trend: "+0%", positive: true },
                { label: "Produits", value: productCount.toString(), trend: "+0%", positive: true },
                { label: "Licences Actives", value: licenseCount.toString(), trend: "+0%", positive: true },
                { label: "Sessions Live", value: activeSessions.toString(), trend: "+0%", positive: true },
            ],
            recentActivity: recentActivity.map(log => ({
                id: log.id,
                user: log.admin_id,
                action: log.action,
                target: `${log.entity} (${log.entity_id})`,
                time: log.created_at.toISOString()
            }))
        };
    } catch (error) {
        console.error("getDashboardStats error:", error);
        throw error;
    }
}
