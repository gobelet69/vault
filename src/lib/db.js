export function nowMs() {
  return Date.now();
}

export function makeId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

export async function ensureQuotaRow(env, username) {
  await env.DB.prepare(
    `
      INSERT INTO user_quotas (username, max_bytes, used_bytes, bandwidth_bytes, updated_at)
      VALUES (?, 10737418240, 0, 0, ?)
      ON CONFLICT(username) DO NOTHING
    `,
  )
    .bind(username, nowMs())
    .run();
}

export async function adjustUsedBytes(env, username, deltaBytes) {
  if (!username || !Number.isFinite(deltaBytes) || deltaBytes === 0) return;
  await ensureQuotaRow(env, username);
  await env.DB.prepare(
    `
      UPDATE user_quotas
      SET used_bytes = MAX(0, used_bytes + ?), updated_at = ?
      WHERE username = ?
    `,
  )
    .bind(deltaBytes, nowMs(), username)
    .run();
}

export async function addBandwidth(env, username, bytes) {
  if (!username || !Number.isFinite(bytes) || bytes <= 0) return;
  await ensureQuotaRow(env, username);
  await env.DB.prepare(
    `
      UPDATE user_quotas
      SET bandwidth_bytes = bandwidth_bytes + ?, updated_at = ?
      WHERE username = ?
    `,
  )
    .bind(bytes, nowMs(), username)
    .run();
}

export async function getQuota(env, username) {
  if (!username) return null;
  await ensureQuotaRow(env, username);
  return env.DB.prepare(
    "SELECT max_bytes, used_bytes, bandwidth_bytes, updated_at FROM user_quotas WHERE username = ?",
  )
    .bind(username)
    .first();
}

export async function recomputeUsedBytesFromStorage(env, username, { includeUnowned = false } = {}) {
  if (!username) return 0;
  await ensureQuotaRow(env, username);

  let cursor;
  let total = 0;
  do {
    const listed = await env.BUCKET.list({
      cursor,
      include: ["customMetadata"],
    });
    for (const object of listed.objects || []) {
      if (object.key.startsWith(".folder:")) continue;
      total += Number(object.size || 0);
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);

  await env.DB.prepare(
    `
      UPDATE user_quotas
      SET used_bytes = ?, updated_at = ?
      WHERE username = ?
    `,
  )
    .bind(total, nowMs(), username)
    .run();
  return total;
}

export async function logActivity(env, actor, action, fileKey = null, metadata = {}, targetUser = null) {
  await env.DB.prepare(
    `
      INSERT INTO activity_log (id, actor, action, file_key, target_user, metadata, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
  )
    .bind(makeId("act"), actor || "system", action, fileKey, targetUser, JSON.stringify(metadata || {}), nowMs())
    .run();
}

export async function upsertRecentItem(env, username, itemType, itemKey) {
  if (!username || !itemType || !itemKey) return;
  await env.DB.prepare(
    `
      INSERT INTO recent_items (username, item_type, item_key, last_accessed_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(username, item_type, item_key)
      DO UPDATE SET last_accessed_at = excluded.last_accessed_at
    `,
  )
    .bind(username, itemType, itemKey, nowMs())
    .run();
}

export async function enforceRateLimit(env, key, { windowSeconds = 60, maxRequests = 120 } = {}) {
  const windowStart = Math.floor(Date.now() / 1000 / windowSeconds) * windowSeconds;
  const now = nowMs();

  const row = await env.DB.prepare(
    `
      INSERT INTO rate_limits (limit_key, window_start, count, updated_at)
      VALUES (?, ?, 1, ?)
      ON CONFLICT(limit_key, window_start)
      DO UPDATE SET count = count + 1, updated_at = excluded.updated_at
      RETURNING count
    `,
  )
    .bind(key, windowStart, now)
    .first();

  return Number(row?.count || 0) <= maxRequests;
}

export async function cleanupExpiredData(env) {
  const now = nowMs();
  await Promise.all([
    env.DB.prepare("DELETE FROM file_edit_sessions WHERE last_heartbeat_at < ?").bind(now - 90_000).run(),
    env.DB.prepare(
      "DELETE FROM share_links WHERE expires_at IS NOT NULL AND expires_at < ?",
    )
      .bind(now)
      .run(),
    env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?")
      .bind(Math.floor(Date.now() / 1000) - 7200)
      .run(),
  ]);
}
