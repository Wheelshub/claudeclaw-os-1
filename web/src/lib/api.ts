// Dashboard API client.
//
// Authentication: cookie-only. The dashboard is gated by Entra OIDC; the
// signed `__Host-ccd_session` cookie (set at /auth/callback) authenticates
// every request. There is no token-mode anymore — `?token=` was removed
// in the "Entra-only auth" cleanup so Microsoft sign-in is the only way
// in.
//
// `chatId` is NOT auth — it tells the dashboard which Telegram chat to
// show context for. We persist it to sessionStorage on first load so
// subsequent navigations keep working without rewriting the URL.

const url = new URL(window.location.href);

let cachedChatId = url.searchParams.get('chatId') || '';
if (cachedChatId) {
  try { sessionStorage.setItem('claudeclaw.chatId', cachedChatId); } catch {}
} else {
  try { cachedChatId = sessionStorage.getItem('claudeclaw.chatId') || ''; } catch {}
}

export const chatId = cachedChatId;

// On 401, hard-redirect to /login with returnTo so the user lands back
// here after authenticating. Same-origin cookie sends automatically on
// fetch (default credentials='same-origin'), so we never need 'include'
// for our own API.
function handle401Redirect(): void {
  const returnTo = encodeURIComponent(window.location.pathname + window.location.search);
  window.location.href = `/login?returnTo=${returnTo}`;
}

export class ApiError extends Error {
  constructor(public status: number, public body: unknown, message: string) {
    super(message);
  }
}

async function apiFetch(path: string, init: RequestInit): Promise<Response> {
  const res = await fetch(path, init);
  if (res.status === 401) {
    handle401Redirect();
    throw new ApiError(401, {}, `${init.method || 'GET'} ${path} unauthorized`);
  }
  return res;
}

export async function apiGet<T = unknown>(path: string): Promise<T> {
  const res = await apiFetch(path, { method: 'GET' });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body, `GET ${path} failed: ${res.status}`);
  }
  return res.json();
}

export async function apiPost<T = unknown>(path: string, body?: unknown): Promise<T> {
  const res = await apiFetch(path, {
    method: 'POST',
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new ApiError(res.status, errBody, `POST ${path} failed: ${res.status}`);
  }
  return res.json();
}

export async function apiPatch<T = unknown>(path: string, body: unknown): Promise<T> {
  const res = await apiFetch(path, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new ApiError(res.status, errBody, `PATCH ${path} failed: ${res.status}`);
  }
  return res.json();
}

export async function apiPut<T = unknown>(path: string, body: unknown): Promise<T> {
  const res = await apiFetch(path, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new ApiError(res.status, errBody, `PUT ${path} failed: ${res.status}`);
  }
  return res.json();
}

export async function apiDelete<T = unknown>(path: string): Promise<T> {
  const res = await apiFetch(path, { method: 'DELETE' });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body, `DELETE ${path} failed: ${res.status}`);
  }
  return res.json();
}

// SSE URL builder. EventSource on same-origin URLs sends cookies on the
// handshake, so the URL is just the path. Kept as a function so callers
// don't need to know the auth model.
export function tokenizedSseUrl(path: string): string {
  return path;
}

// Vite dev runs on :5173 and proxies /api/* and /warroom/text to the
// backend on :3141. The legacy voice room at /warroom?mode=voice can't
// be proxied (it shares a path prefix with the v2 SPA route), so links
// that go to legacy pages must point at the backend origin in dev.
const BACKEND_ORIGIN = (import.meta as any).env?.DEV ? 'http://localhost:3141' : '';

export function legacyUrl(path: string): string {
  return BACKEND_ORIGIN + path;
}
