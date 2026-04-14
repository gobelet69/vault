import { isAdmin } from "../lib/auth.js";
import { logActivity, nowMs } from "../lib/db.js";
import { HttpError, assert, json, readJson } from "../lib/http.js";

async function hashPassword(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function normalizeIncomingRole(value) {
  const role = `${value || ""}`.trim();
  if (role === "owner") return "admin";
  if (role === "member") return "editor";
  if (["admin", "editor", "commenter", "viewer", "viewer-download-disabled"].includes(role)) return role;
  return "viewer";
}

export async function handleUserManagement(request, env, actorUser) {
  assert(isAdmin(actorUser), 403, "Admin role required.");
  const form = await request.formData();
  const action = `${form.get("action") || ""}`.trim();

  if (action === "create") {
    const username = `${form.get("u") || ""}`.trim();
    const password = `${form.get("p") || ""}`;
    const role = normalizeIncomingRole(form.get("r"));
    assert(username, 400, "Username is required.");
    assert(password.length >= 8, 400, "Password must be at least 8 characters.");

    const passwordHash = await hashPassword(password);
    await env.AUTH_DB.prepare(
      "INSERT OR REPLACE INTO users(username, password, role, created_at) VALUES (?, ?, ?, ?)",
    )
      .bind(username, passwordHash, role, new Date().toISOString())
      .run();
    await logActivity(env, actorUser.username, "user.created", null, { role }, username);
    return json({ ok: true, action, username, role });
  }

  if (action === "delete") {
    const username = `${form.get("u") || ""}`.trim();
    assert(username, 400, "Username is required.");
    assert(username !== actorUser.username, 400, "You cannot delete your own account.");
    await env.AUTH_DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
    await logActivity(env, actorUser.username, "user.deleted", null, {}, username);
    return json({ ok: true, action, username });
  }

  if (action === "update-role") {
    const username = `${form.get("u") || ""}`.trim();
    const role = normalizeIncomingRole(form.get("r"));
    assert(username, 400, "Username is required.");
    assert(username !== actorUser.username, 400, "You cannot change your own role.");
    await env.AUTH_DB.prepare("UPDATE users SET role = ? WHERE username = ?").bind(role, username).run();
    await logActivity(env, actorUser.username, "user.role_updated", null, { role }, username);
    return json({ ok: true, action, username, role });
  }

  throw new HttpError(400, "Invalid users action.");
}

export async function handleUserInvite(request, env, actorUser) {
  assert(isAdmin(actorUser), 403, "Admin role required.");
  const payload = await readJson(request);
  const email = `${payload.email || ""}`.trim();
  const role = normalizeIncomingRole(payload.role);
  assert(email.includes("@"), 400, "Valid email is required.");

  await env.DB.prepare(
    `
      INSERT INTO pending_invites (id, email, role, invited_by, created_at, status)
      VALUES (?, ?, ?, ?, ?, 'pending')
    `,
  )
    .bind(`invite_${crypto.randomUUID()}`, email, role, actorUser.username, nowMs())
    .run();

  await logActivity(env, actorUser.username, "invite.created", null, { email, role });
  return json({
    ok: true,
    message: "Invite recorded. Configure your email delivery provider to send this invite.",
    email,
    role,
  });
}
