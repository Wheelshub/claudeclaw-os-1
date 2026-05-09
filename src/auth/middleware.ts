// Auth middleware for the dashboard.
//
// Two middleware exports:
//
//  1. `trustProxyValidator` — runs at the very top of the chain.
//     Rejects malformed `X-Forwarded-Proto` values with 400 + audit so
//     cookie-name selection (`__Host-` vs not) doesn't depend on a
//     spoofable header value. Subset of PLAN §13's full strict
//     trust-proxy work; the rest lands in §13.
//
//  2. `requireAuth` — replaces the old `/api/*` token-check middleware
//     AND the inline `requireToken()` calls scattered through the
//     dashboard. Single auth gate. Whitelist for the routes that must
//     stay public, then token path, then session path, then deny.
//
// Operator constraint (PLAN §2.4): `TRUST_PROXY=true` is only safe when
// the dashboard is bound to 127.0.0.1 AND the trusted proxy/tunnel
// terminates on the same host, OR network-level isolation blocks
// direct reachability of `DASHBOARD_PORT`. Otherwise an attacker can
// spoof `X-Forwarded-Proto` on a direct connection and influence
// cookie-name selection.
import type { Context, MiddlewareHandler } from 'hono';

import {
  DASHBOARD_TOKEN,
  ENTRA_APP_ROLE_VALUE,
  SESSION_AUTH_ENABLED,
  TRUST_PROXY,
} from '../config.js';

import {
  appendAuthAuditBestEffort,
  parseAndVerifySignedCookie,
  touchSessionThrottled,
} from './session.js';

// Hono's context variables are typed via this module-augmented map.
// Downstream handlers can read c.get('authMode') / c.get('user') with
// proper typing instead of casting.
declare module 'hono' {
  interface ContextVariableMap {
    authMode: 'token' | 'session';
    user: { oid: string; upn: string; name: string | null; sessionId: string };
  }
}

const WHITELIST_EXACT = new Set<string>([
  '/auth/login',
  '/auth/callback',
  '/auth/logout',
  '/login',
  '/favicon.ico',
]);

const WHITELIST_PREFIXES = ['/assets/'];

// /api/health/auth is NOT whitelisted — it's deferred to §11. Adding a
// stub here would create false-green during the OIDC rollout.

export function isWhitelisted(path: string): boolean {
  if (WHITELIST_EXACT.has(path)) return true;
  for (const prefix of WHITELIST_PREFIXES) {
    if (path.startsWith(prefix)) return true;
  }
  return false;
}

// Returns the effective request scheme. Returns null when TRUST_PROXY=true
// and X-Forwarded-Proto is malformed — the caller (trustProxyValidator)
// turns that into a 400.
export function getEffectiveScheme(c: Context): 'http' | 'https' | null {
  if (TRUST_PROXY) {
    const xfp = c.req.header('x-forwarded-proto');
    if (xfp === undefined) return 'http'; // header missing → treat as direct
    if (xfp === 'https') return 'https';
    if (xfp === 'http') return 'http';
    return null; // malformed: anything else fails closed
  }
  return 'http'; // direct bind is always http
}

export function extractClientIp(c: Context): string | undefined {
  return (
    c.req.header('cf-connecting-ip') ||
    c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ||
    undefined
  );
}

export const trustProxyValidator: MiddlewareHandler = async (c, next) => {
  const scheme = getEffectiveScheme(c);
  if (scheme === null) {
    appendAuthAuditBestEffort({
      event: 'proxy.bad-proto',
      details: { value: c.req.header('x-forwarded-proto') },
      ip: extractClientIp(c),
      userAgent: c.req.header('user-agent'),
    });
    return c.json({ error: 'malformed X-Forwarded-Proto' }, 400);
  }
  await next();
};

export const requireAuth: MiddlewareHandler = async (c, next) => {
  const url = new URL(c.req.url);
  const path = url.pathname;

  // 1. Whitelist
  if (isWhitelisted(path)) {
    await next();
    return;
  }

  // 2. Token path: ?token query OR Authorization: Bearer (same-origin / CLI
  //    only until §7 expands CORS allowed-headers).
  const queryToken = c.req.query('token');
  const authHeader = c.req.header('authorization') || '';
  const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
  const bearerToken = bearerMatch ? bearerMatch[1] : '';
  const presentedToken = queryToken || bearerToken;
  if (DASHBOARD_TOKEN && presentedToken && presentedToken === DASHBOARD_TOKEN) {
    c.set('authMode', 'token');
    await next();
    return;
  }

  // 3. Session path. Cookie scheme is selected via the validated effective
  //    scheme (trustProxyValidator already rejected malformed headers).
  const scheme = getEffectiveScheme(c);
  const isHttps = scheme === 'https';

  if (SESSION_AUTH_ENABLED) {
    let session;
    try {
      session = parseAndVerifySignedCookie(c.req.header('cookie'), isHttps);
    } catch {
      // Malformed cookie. Treat as anonymous and fall through to denial —
      // never let a parser exception escape the middleware.
      session = undefined;
    }
    if (session && session.roles.includes(ENTRA_APP_ROLE_VALUE)) {
      touchSessionThrottled(session);
      c.set('authMode', 'session');
      c.set('user', {
        oid: session.userOid,
        upn: session.userUpn,
        name: session.userName,
        sessionId: session.id,
      });
      await next();
      return;
    }
  }

  // 4. Denial. /api/ → 401 JSON; everything else → 302 to /login (the
  // landing page with a "Sign in with Microsoft" button). Browser users
  // get a clickable surface before being redirected to Microsoft; API
  // clients get a clean machine-readable 401.
  if (path.startsWith('/api/')) {
    // Match the legacy middleware's casing exactly so existing contract
    // tests (and any frontend code that string-matches on the body) keep
    // working after the gate swap.
    return c.json({ error: 'Unauthorized' }, 401);
  }
  const returnTo = encodeURIComponent(path + (url.search || ''));
  return c.redirect(`/login?returnTo=${returnTo}`, 302);
};
