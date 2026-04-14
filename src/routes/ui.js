import { html } from "../lib/http.js";

const FAVICON = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%23A855F7'/%3E%3Cstop offset='1' stop-color='%23EC4899'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='32' height='32' rx='8' fill='url(%23g)'/%3E%3Ctext x='16' y='21' font-family='Arial,sans-serif' font-weight='900' font-size='9' fill='white' text-anchor='middle'%3E111%3C/text%3E%3C/svg%3E`;

export function renderVaultAppShell(user) {
  const safeUser = JSON.stringify({
    username: user.username,
    role: user.role,
  })
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  return html(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>111 Vault</title>
    <link rel="icon" href="${FAVICON}" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link rel="stylesheet" href="/vault/static/vault-app.css" />
  </head>
  <body>
    <noscript>Vault requires JavaScript.</noscript>
    <div id="vault-root" data-user="${safeUser}"></div>
    <script type="module" src="/vault/static/vault-app.js"></script>
  </body>
</html>`);
}
