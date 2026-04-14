export class HttpError extends Error {
  constructor(status, message, details = null) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.details = details;
  }
}

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

export function text(message, status = 200, headers = {}) {
  return new Response(message, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      ...headers,
    },
  });
}

export function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      ...headers,
    },
  });
}

export async function readJson(request, { allowEmpty = false } = {}) {
  const raw = await request.text();
  if (!raw.trim()) {
    if (allowEmpty) return {};
    throw new HttpError(400, "Request body is required.");
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }
}

export function assert(condition, status, message, details = null) {
  if (!condition) throw new HttpError(status, message, details);
}

export function getApiErrorBody(error) {
  if (error instanceof HttpError) {
    return {
      error: error.message,
      details: error.details ?? undefined,
    };
  }
  return { error: "Internal server error." };
}

export function withSecurityHeaders(response) {
  const next = new Response(response.body, response);
  next.headers.set("X-Content-Type-Options", "nosniff");
  next.headers.set("X-Frame-Options", "SAMEORIGIN");
  next.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  next.headers.set(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "img-src 'self' data: blob:",
      "media-src 'self' blob:",
      "font-src 'self' data: https://cdn.jsdelivr.net",
      "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
      "style-src-elem 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
      "script-src 'self' 'unsafe-eval' https://cdn.jsdelivr.net",
      "connect-src 'self' https://cdn.jsdelivr.net",
      "worker-src 'self' blob: https://cdn.jsdelivr.net",
      "frame-src https://vscode.dev https://*.github.dev",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'self'",
    ].join("; "),
  );
  return next;
}
