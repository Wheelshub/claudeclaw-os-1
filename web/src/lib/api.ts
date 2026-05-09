// Token + chatId come from the URL query string (set by the Telegram deep
// link or by a saved bookmark). We persist both to sessionStorage on first
// load so subsequent navigations keep working without rewriting the URL.
// We never use localStorage: dashboardToken is sensitive, and storing it
// across browser sessions would enlarge its blast radius.
//
// PLAN §15: behind the `useSessionAuth` flag, the wrapper drops the
// `?token=` query param and switches to `credentials: 'include'` so the
// signed session cookie set by /auth/callback authenticates each request.
// The flag is read from a `<meta name="ccd-use-session-auth">` injected by
// the dashboard server (`spaShellHtml()` in src/dashboard.ts) — that lets
// the operator flip between token and cookie auth via env + restart
// without a SPA rebuild. On any /api/* 401 in session mode, the wrapper
// hard-redirects to /login?returnTo=<current> so the user lands on the
// click-through landing page rather than seeing raw JSON errors.

const url = new URL(window.location.href);

let cachedToken = url.searchParams.get('token') || '';
if (cachedToken) {
  try { sessionStorage.setItem('claudeclaw.token', cachedToken); } catch {}
} else {
  try { cachedToken = sessionStorage.getItem('claudeclaw.token') || ''; } catch {}
}

let cachedChatId = url.searchParams.get('chatId') || '';
if (cachedChatId) {
  try { sessionStorage.setItem('claudeclaw.chatId', cachedChatId); } catch {}
} else {
  try { cachedChatId = sessionStorage.getItem('claudeclaw.chatId') || ''; } catch {}
}

export const dashboardToken = cachedToken;
export const chatId = cachedChatId;

function readSessionAuthMeta(): boolean {
  try {
    const el = document.querySelector('meta[name="ccd-use-session-auth"]');
    return el?.getAttribute('content') === 'true';
  } catch {
    return false;
  }
}

export const useSessionAuth = readSessionAuthMeta();

// Append `?token=` to a path. Token-mode only; never call in session mode.
function withToken(path: string): string {
  const sep = path.includes('?') ? '&' : '?';
  return `${path}${sep}token=${encodeURIComponent(dashboardToken)}`;
}

// Build the authenticated URL for a same-origin path. Session mode strips
// `?token=`; token mode preserves the legacy behavior. Used by both the
// fetch wrappers and inline `<img src=...>` / `fetch()` callers that need
// to honor the flag without duplicating logic.
export function authUrl(path: string): string {
  return useSessionAuth ? path : withToken(path);
}

// fetch() init for authenticated calls. In session mode we send the
// signed cookie; in token mode the token is in the URL and credentials
// are irrelevant (kept omitted to match prior behavior).
export function authInit(init?: RequestInit): RequestInit {
  if (!useSessionAuth) return init || {};
  return { ...(init || {}), credentials: 'include' };
}

// On 401 in session mode, hard-redirect the page to /login with a
// returnTo so the user lands back here after authenticating. Token
// mode keeps the legacy throw-and-let-the-caller-render-error path.
function handle401Redirect(): void {
  if (!useSessionAuth) return;
  const returnTo = encodeURIComponent(window.location.pathname + window.location.search);
  window.location.href = `/login?returnTo=${returnTo}`;
}

export class ApiError extends Error {
  constructor(public status: number, public body: unknown, message: string) {
    super(message);
  }
}

async function apiFetch(path: string, init: RequestInit): Promise<Response> {
  const res = await fetch(authUrl(path), authInit(init));
  if (res.status === 401 && useSessionAuth) {
    handle401Redirect();
    // Throw so callers don't try to parse a redirect-target body as JSON
    // while the navigation kicks in.
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

// SSE URL builder. EventSource doesn't accept credentials options the
// same way fetch does, but same-origin SSE includes cookies by default,
// so dropping `?token=` is enough to switch to session auth.
export function tokenizedSseUrl(path: string): string {
  return authUrl(path);
}

// Vite dev runs on :5173 and proxies /api/* and /warroom/text to the
// backend on :3141. The legacy voice room at /warroom?mode=voice can't
// be proxied (it shares a path prefix with the v2 SPA route), so links
// that go to legacy pages must point at the backend origin in dev.
const BACKEND_ORIGIN = (import.meta as any).env?.DEV ? 'http://localhost:3141' : '';

export function legacyUrl(path: string): string {
  return BACKEND_ORIGIN + path;
}

// Legacy /warroom* URLs accept `?token=...` for token-mode auth. In
// session mode the same-origin signed cookie authenticates these
// top-level navigations (SameSite=Lax sends cookies on GET nav). Use
// like `&token=${legacyTokenSuffix()}` is wrong — this returns the
// FULL `&token=...` segment or empty so callers don't have to branch.
export function legacyTokenParam(): string {
  return useSessionAuth ? '' : `&token=${encodeURIComponent(dashboardToken)}`;
}
