"use server";

import { revalidatePath } from "next/cache";
import prisma from "@/lib/server/prisma";
import { notifySync } from "@/lib/server/sync";
import { requireAdmin } from "@/lib/server/auth";
import { z } from "zod";
import crypto from "crypto";

const licenseSchema = z.object({
    username: z.string().min(1).optional(),
    product_id: z.string().uuid(),
});

function generateLicenseKey() {
    const uuid = crypto.randomUUID().toUpperCase().replace(/-/g, "");
    return `WHIP-${uuid.substring(0, 4)}-${uuid.substring(4, 8)}-${uuid.substring(8, 12)}-${uuid.substring(12, 16)}`;
}

export async function getLicenses() {
    await requireAdmin();
    return await prisma.license.findMany({
        orderBy: { created_at: "desc" },
        include: {
            user: { select: { username: true } },
            product: { select: { name: true } },
            _count: { select: { sessions: true } }
        }
    });
}

export async function createLicense(formData: FormData) {
    await requireAdmin();
    const username = (formData.get("username") as string)?.trim() || undefined;
    const product_id = formData.get("product_id") as string;
    const expires_at_str = formData.get("expires_at") as string | null;
    const lifetime = formData.get("lifetime") === "on";

    licenseSchema.parse({ username, product_id });

    let user_id: string | null = null;
    let userCreated = false;
    if (username) {
        let user = await prisma.user.findUnique({ where: { username } });
        if (!user) {
            user = await prisma.user.create({ data: { username, password_hash: "!" } });
            userCreated = true;
        }
        user_id = user.id;
    }

    const license_key = generateLicenseKey();

    const license = await prisma.license.create({
        data: {
            license_key,
            user_id,
            product_id,
            expires_at: lifetime || !expires_at_str ? null : new Date(expires_at_str),
            status: "active",
        },
    });

    if (userCreated && user_id) await notifySync("user", "create", user_id);
    await notifySync("license", "create", license.id);
    revalidatePath("/admin/licenses");
}

export async function updateLicenseStatus(id: string, status: any) {
    await requireAdmin();
    await prisma.license.update({
        where: { id },
        data: { status },
    });
    await notifySync("license", "update", id);
    revalidatePath("/admin/licenses");
}

export async function deleteLicense(id: string) {
    await requireAdmin();
    // The DB is Flyway-managed, so the real FK actions may not match the
    // Cascade declared in schema.prisma — a plain license.delete() gets
    // blocked by sessions still referencing the license. Remove the
    // dependent sessions explicitly so the delete always succeeds.
    await prisma.$transaction(async (tx) => {
        await tx.session.deleteMany({ where: { license_id: id } });
        await tx.license.delete({ where: { id } });
    });
    await notifySync("license", "delete", id);
    revalidatePath("/admin/licenses");
}
