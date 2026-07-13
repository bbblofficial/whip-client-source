import { NextResponse, type NextRequest } from "next/server";

// ── Admin auth gate (edge) ──
// Lightweight gate: presence of the signed `session` cookie. The real
// verification (HMAC signature + DB lookup + admin grade) happens in the
// (panel) layout server component via getSession(), which runs on the Node
// runtime where `crypto` is available. Here we just route based on whether
// a session cookie exists, and block cross-origin state-changing requests.
const PUBLIC_PREFIXES = ["/login", "/api"];

function isPublic(pathname: string) {
  return PUBLIC_PREFIXES.some((p) => pathname === p || pathname.startsWith(p + "/") || pathname === p);
}

// Edge-side, lightweight check: decode the cookie payload's `iat` (no signature
// verification — that's done in getSession on the Node runtime) only to decide
// routing. Treating an expired cookie as "no session" avoids the redirect loop
// /login ↔ /dashboard when the cookie is present but stale.
const SESSION_MAX_AGE = 60 * 60 * 24 * 7;
function sessionLooksValid(token: string | undefined): boolean {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  try {
    let b64 = parts[0].replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const payload = JSON.parse(atob(b64));
    if (!payload?.iat) return false;
    return Math.floor(Date.now() / 1000) - payload.iat <= SESSION_MAX_AGE;
  } catch {
    return false;
  }
}

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // CSRF: refuse cross-origin mutations.
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    const origin = req.headers.get("origin");
    const host = req.headers.get("host");
    if (origin && host && new URL(origin).host !== host) {
      return new NextResponse("Forbidden", { status: 403 });
    }
  }

  const hasSession = sessionLooksValid(req.cookies.get("session")?.value);
  const publicPath = isPublic(pathname);

  // Authenticated user hitting /login or root → send to dashboard.
  if (hasSession && (pathname === "/login" || pathname === "/")) {
    return NextResponse.redirect(new URL("/dashboard", req.url));
  }

  // Unauthenticated user on a protected path → send to login.
  if (!hasSession && !publicPath) {
    return NextResponse.redirect(new URL("/login", req.url));
  }

  return NextResponse.next();
}

export const config = {
  // /api/scanleak is excluded: the middleware mangles large multipart uploads
  // ("Failed to parse body as FormData"). The route handler does its own auth
  // (requireAdmin) + origin check instead.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api/scanleak).*)"],
};
