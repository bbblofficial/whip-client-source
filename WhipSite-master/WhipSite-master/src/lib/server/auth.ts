"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { z } from "zod";
import bcrypt from "bcrypt";
import prisma from "@/lib/server/prisma";
import { signSession, verifySession, SESSION_MAX_AGE, type SessionPayload } from "@/lib/server/session";
import { logAction, logSystem } from "@/lib/server/logger";

const loginSchema = z.object({
    username: z.string().min(3),
    password: z.string().min(3),
});

export async function login(formData: FormData): Promise<{ error?: string; success?: boolean }> {
    const cookieStore = await cookies();
    const username = formData.get("username") as string;
    const password = formData.get("password") as string;

    const result = loginSchema.safeParse({ username, password });

    if (!result.success) {
        return { error: "Identifiants invalides." };
    }

    try {
        const user = await prisma.user.findUnique({
            where: { username },
        });

        if (!user) {
            await logSystem("auth.login_failed", "auth", `Utilisateur inconnu : ${username}`);
            return { error: "Nom d'utilisateur ou mot de passe incorrect." };
        }

        const passwordMatch = await bcrypt.compare(password, user.password_hash || "");

        if (!passwordMatch) {
            await logSystem("auth.login_failed", "auth", `Mot de passe incorrect : ${username}`);
            return { error: "Nom d'utilisateur ou mot de passe incorrect." };
        }

        if (user.grade !== "admin" && user.grade !== "owner") {
            await logSystem("auth.login_denied", "auth", `Accès refusé (grade ${user.grade}) : ${username}`);
            return { error: "Accès réservé aux administrateurs." };
        }

        const sessionToken = signSession({
            userId: user.id,
            username: user.username,
            grade: user.grade,
            iat: Math.floor(Date.now() / 1000),
        });

        const useSecureCookie = process.env.SECURE_COOKIES === "true";

        cookieStore.set("session", sessionToken, {
            httpOnly: true,
            secure: useSecureCookie,
            sameSite: "lax",
            maxAge: SESSION_MAX_AGE,
            path: "/",
        });

        await logAction(user.id, "auth.login", "auth", user.id, "Connexion au panel");
        return { success: true };
    } catch {
        return { error: "Une erreur est survenue lors de la connexion." };
    }
}

export async function logout() {
    const cookieStore = await cookies();
    const session = await getSession();
    if (session) await logAction(session.userId, "auth.logout", "auth", session.userId, "Déconnexion du panel");
    cookieStore.delete("session");
    redirect("/");
}

/**
 * Verifies the signed session cookie and validates the user still exists
 * with the correct grade in the database.
 */
export async function getSession(): Promise<SessionPayload | null> {
    const cookieStore = await cookies();
    const token = cookieStore.get("session")?.value;
    if (!token) return null;

    const payload = verifySession(token);
    if (!payload) return null;

    // Verify user still exists and still has admin/owner grade
    const user = await prisma.user.findUnique({
        where: { id: payload.userId },
        select: { id: true, username: true, grade: true },
    });

    if (!user || (user.grade !== "admin" && user.grade !== "owner")) {
        return null;
    }

    // Return fresh data from DB (in case grade/username changed)
    return {
        userId: user.id,
        username: user.username,
        grade: user.grade,
        iat: payload.iat,
    };
}

/**
 * Guard function for server actions. Throws if user is not an authenticated admin.
 */
export async function requireAdmin(): Promise<SessionPayload> {
    const session = await getSession();
    if (!session) {
        throw new Error("Non autorisé");
    }
    return session;
}
