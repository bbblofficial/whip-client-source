"use server";

import { revalidatePath } from "next/cache";
import prisma from "@/lib/server/prisma";
import { notifySync } from "@/lib/server/sync";
import { requireAdmin } from "@/lib/server/auth";
import { z } from "zod";

const productSchema = z.object({
    code: z.string().min(2),
    name: z.string().min(2),
    description: z.string().optional(),
});

export async function getProducts() {
    await requireAdmin();
    return await prisma.product.findMany({
        orderBy: { created_at: "desc" },
        include: {
            _count: {
                select: { licenses: true }
            }
        }
    });
}

export async function createProduct(formData: FormData) {
    await requireAdmin();
    const code = formData.get("code") as string;
    const name = formData.get("name") as string;
    const description = formData.get("description") as string;

    productSchema.parse({ code, name, description });

    const product = await prisma.product.create({
        data: { code, name, description },
    });

    await notifySync("product", "create", product.id);
    revalidatePath("/admin/products");
}

export async function updateProduct(id: string, formData: FormData) {
    await requireAdmin();
    const code = formData.get("code") as string;
    const name = formData.get("name") as string;
    const description = formData.get("description") as string;

    await prisma.product.update({
        where: { id },
        data: { code, name, description },
    });

    await notifySync("product", "update", id);
    revalidatePath("/admin/products");
}

export async function deleteProduct(id: string) {
    await requireAdmin();
    // DB is Flyway-managed, so the real FK actions may not match the
    // Cascade declared in schema.prisma — a plain product.delete() gets
    // blocked by licenses (and downloads) still referencing the product.
    // Remove the dependents explicitly so the delete always succeeds.
    await prisma.$transaction(async (tx) => {
        await tx.session.deleteMany({
            where: { license: { product_id: id } },
        });
        await tx.license.deleteMany({ where: { product_id: id } });
        // Keep download history but detach it from the deleted product.
        await tx.download.updateMany({
            where: { product_id: id },
            data: { product_id: null },
        });
        await tx.product.delete({ where: { id } });
    });
    await notifySync("product", "delete", id);
    revalidatePath("/admin/products");
}
