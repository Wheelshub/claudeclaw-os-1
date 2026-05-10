// Auth middleware for the dashboard.
//
// Two middleware exports:
//
//  1. `trustProxyValidator` — runs at the very top of the chain.
//     Rejects malformed `X-Forwarded-Proto` values with 400 + audit so
//     cookie-name selection (`__Host-` vs not) doesn't depend on a
//     spoofable header value.
//
//  2. `requireAuth` — single auth gate for the entire dashboard.
//     Whitelist (login surface + Teams webhook + favicon + static
//     assets) → Entra session cookie → 302/401 deny. There is no
//     token path: Microsoft sign-in via OIDC is the only way in.
//
// Operator constraint: `TRUST_PROXY=true` is only safe when the
// dashboard is bound to 127.0.0.1 AND the trusted proxy/tunnel
// terminates on the same host, OR network-level isolation blocks
// direct reachability of `DASHBOARD_PORT`. Otherwise an attacker can
// spoof `X-Forwarded-Proto` on a direct connection and influence
// cookie-name selection.
import type { Context, MiddlewareHandler } from 'hono';

import {
  ENTRA_APP_ROLE_VALUE,
  TRUST_PROXY,
} from '../config.js';

import {
  appendAuthAuditBestEffort,
  parseAndVerifySignedCookie,
  touchSessionThrottled,
} from './session.js';

// Hono's context variables are typed via this module-augmented map.
// Downstream handlers can read c.get('user') with proper typing instead
// of casting.
declare module 'hono' {
  interface ContextVariableMap {
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

  // 2. Entra session cookie. Cookie scheme is selected via the validated
  //    effective scheme (trustProxyValidator already rejected malformed
  //    X-Forwarded-Proto headers).
  const scheme = getEffectiveScheme(c);
  const isHttps = scheme === 'https';

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
    c.set('user', {
      oid: session.userOid,
      upn: session.userUpn,
      name: session.userName,
      sessionId: session.id,
    });
    await next();
    return;
  }

  // 3. Denial. /api/ → 401 JSON; everything else → 302 to /login (the
  // landing page with a "Sign in with Microsoft" button). Browser users
  // get a clickable surface; API clients get machine-readable 401.
  if (path.startsWith('/api/')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  const returnTo = encodeURIComponent(path + (url.search || ''));
  return c.redirect(`/login?returnTo=${returnTo}`, 302);
};
