import { HttpError } from "./http.js";

export function normalizeRole(role) {
  if (role === "owner" || role === "admin") return "admin";
  if (role === "member" || role === "editor" || role === "guest+") return "editor";
  if (role === "commenter") return "commenter";
  if (role === "viewer-download-disabled") return "viewer-download-disabled";
  if (role === "guest" || role === "viewer") return "viewer";
  return "viewer";
}

export function roleLevel(role) {
  const normalized = normalizeRole(role);
  if (normalized === "admin") return 50;
  if (normalized === "editor") return 40;
  if (normalized === "commenter") return 30;
  if (normalized === "viewer") return 20;
  return 10;
}

export function isAdmin(user) {
  return normalizeRole(user?.role) === "admin";
}

export function isEditor(user) {
  const role = normalizeRole(user?.role);
  return role === "admin" || role === "editor";
}

export function isCommenterOrHigher(user) {
  return roleLevel(user?.role) >= roleLevel("commenter");
}

export function canDownloadByRole(user) {
  return normalizeRole(user?.role) !== "viewer-download-disabled";
}

function parseCookie(request) {
  const cookieHeader = request.headers.get("Cookie") || "";
  return Object.fromEntries(
    cookieHeader
      .split(";")
      .map((item) => item.trim())
      .filter(Boolean)
      .map((item) => {
        const [k, ...rest] = item.split("=");
        return [k, decodeURIComponent(rest.join("=") || "")];
      }),
  );
}

export async function getSessionUser(request, env) {
  const cookies = parseCookie(request);
  const sid = cookies.sess;
  if (!sid) return null;

  const now = Date.now();
  const session = await env.AUTH_DB.prepare(
    "SELECT id, username, expires FROM sessions WHERE id = ? AND expires > ?",
  )
    .bind(sid, now)
    .first();

  if (!session) return null;

  const dbUser = await env.AUTH_DB.prepare("SELECT role FROM users WHERE username = ?")
    .bind(session.username)
    .first();

  return {
    id: session.id,
    username: session.username,
    role: normalizeRole(dbUser?.role),
    expires: session.expires,
  };
}

export function requireUser(user) {
  if (!user) throw new HttpError(401, "Authentication required.");
}

