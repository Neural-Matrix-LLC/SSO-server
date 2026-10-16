// auth.js — spec §7.2 reference client, unchanged except that the SSO base URL is configurable
// (no host is hard-coded): window.SSO_BASE, else the page's own origin.
const SSO = (globalThis.SSO_BASE || globalThis.location?.origin || "").replace(/\/$/, "");
let accessToken = null, refreshTimer = null, user = null;

async function call(path, body) {
  const r = await fetch(SSO + path, {
    method: "POST", credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  const data = r.status === 204 ? {} : await r.json();
  if (!r.ok) throw Object.assign(new Error(data.detail || r.statusText), { code: data.error, status: r.status });
  return data;
}

function accept(data) {
  accessToken = data.access_token; user = data.user;
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => refresh().catch(() => {}), (data.expires_in - 60) * 1000);
  return user;
}

export const login   = (username, password) => call("/api/v1/auth/login", { username, password, client: "browser" }).then(accept);
export const refresh = () => call("/api/v1/auth/refresh").then(accept);
export async function logout() {
  clearTimeout(refreshTimer); accessToken = null; user = null;
  await call("/api/v1/auth/logout").catch(() => {});
}
export const currentUser = () => user;
export const ssoBase = () => SSO;
// demo-only helper so the test page can show the token's claims; real apps don't need it
export const _accessTokenForDemo = () => accessToken;

// Use this for every call to a back-end service.
export async function apiFetch(url, opts = {}) {
  const go = () => fetch(url, { ...opts, headers: { ...opts.headers, Authorization: `Bearer ${accessToken}` } });
  let r = await go();
  if (r.status === 401) {               // expired: refresh once and retry
    try { await refresh(); } catch { await logout(); throw new Error("login_required"); }
    r = await go();
  }
  return r;
}

// On app start:
export const restoreSession = () => refresh().catch(() => null); // null => show login form
