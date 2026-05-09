// OIDC dashboard auth routes: /auth/login, /auth/callback, /auth/logout.
//
// Mounted onto the dashboard Hono app via registerAuthRoutes(app) at the
// precise location BEFORE app.get('/') and BEFORE the SPA catch-all so
// these routes don't fall through to the SPA shell. See dashboard.ts for
// the mount call.
//
// PLAN refs: §12 routes table, §3.1 WS Origin (separate; here for /auth
// only), §4 audit table, §4.2 best-effort audit wrapper, §5 callback
// concurrency gate, §6 returnTo validator, §2.5 rate limiter.
//
// /api/health/auth is NOT registered here — that's deferred to §11 to
// avoid a false-green readiness signal.
import type { Context, Hono } from 'hono';

import {
  AUTH_CALLBACK_MAX_INFLIGHT,
  DASHBOARD_URL,
  ENTRA_REDIRECT_URI_DEV,
  ENTRA_REDIRECT_URI_PROD,
  OIDC_ENABLED,
} from '../config.js';
import {
  consumeOidcRequest,
  purgeExpiredOidcRequests,
  saveOidcRequest,
} from '../db.js';
import {
  EntraError,
  buildAuthorizeUrl,
  calculatePKCECodeChallenge,
  checkAuthorizationClaims,
  exchangeCodeForTokens,
  getEntraConfiguration,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
} from './entra.js';
import { extractClientIp, getEffectiveScheme } from './middleware.js';
import { consumeRateToken } from './rate-limit.js';
import { sanitizeReturnTo } from './return-to.js';
import {
  TX_BINDING_LIFETIME_SECONDS,
  appendAuthAuditBestEffort,
  buildClearCookieHeader,
  buildSetCookieHeader,
  buildTxBindingClearCookieHeader,
  buildTxBindingSetCookieHeader,
  createSession,
  generateTxBinding,
  hashTxBinding,
  parseAndVerifySignedCookie,
  parseTxBindingCookie,
  revokeSession,
} from './session.js';

// ── /auth/callback concurrency gate state ──────────────────────────
// Module-scoped; Node single-threadedness makes plain ++/-- safe.
let inflightCallbacks = 0;

// PLAN §13: redirect URI selection. Effective host comes from
// configuration only — never from the Host or X-Forwarded-Host header.
// Rules:
//   - https + DASHBOARD_URL set + ENTRA_REDIRECT_URI_PROD host == DASHBOARD_URL host
//     → ENTRA_REDIRECT_URI_PROD
//   - http + ENTRA_REDIRECT_URI_DEV host is localhost
//     → ENTRA_REDIRECT_URI_DEV
//   - Anything else → fail closed; do NOT call Entra
//
// The host-match check defends against operator misconfiguration where
// ENTRA_REDIRECT_URI_PROD points to a different domain than DASHBOARD_URL
// (typo, stale env). Without it, /auth/login would happily build an
// authorize URL whose redirect_uri lands on the wrong host post-handshake.
type RedirectUriResult =
  | { ok: true; uri: string }
  | { ok: false; reason: string };

function validateRedirectUriSelection(c: Context): RedirectUriResult {
  const scheme = getEffectiveScheme(c);
  if (scheme === null) {
    // trustProxyValidator already 400'd; defensive only.
    return { ok: false, reason: 'unknown-scheme' };
  }
  if (scheme === 'https') {
    const prodUri = (ENTRA_REDIRECT_URI_PROD || '').trim();
    const dashUrl = (DASHBOARD_URL || '').trim();
    if (!prodUri) return { ok: false, reason: 'prod-redirect-uri-missing' };
    if (!dashUrl) return { ok: false, reason: 'dashboard-url-missing' };
    let prodHost: string;
    let dashHost: string;
    try {
      prodHost = new URL(prodUri).host;
      dashHost = new URL(dashUrl).host;
    } catch {
      return { ok: false, reason: 'redirect-uri-malformed' };
    }
    if (prodHost !== dashHost) {
      return { ok: false, reason: 'redirect-uri-host-mismatch' };
    }
    return { ok: true, uri: prodUri };
  }
  // scheme === 'http'
  const devUri = (ENTRA_REDIRECT_URI_DEV || '').trim();
  if (!devUri) return { ok: false, reason: 'dev-redirect-uri-missing' };
  let devHost: string;
  try {
    devHost = new URL(devUri).hostname;
  } catch {
    return { ok: false, reason: 'redirect-uri-malformed' };
  }
  // PLAN §13: http path is for localhost dev only.
  const isLocalhost =
    devHost === 'localhost' || devHost === '127.0.0.1' || devHost === '[::1]';
  if (!isLocalhost) {
    return { ok: false, reason: 'dev-redirect-uri-not-localhost' };
  }
  return { ok: true, uri: devUri };
}

// Origin allowlist for /auth/logout (separate from CORS — handles the
// CSRF lane for state-changing POSTs). Mirrors the rule in
// dashboard.ts:346-370 so behavior is consistent.
const allowedOriginHost = (() => {
  const raw = (DASHBOARD_URL || '').trim();
  if (!raw) return '';
  try {
    return new URL(raw).hostname;
  } catch {
    return '';
  }
})();

function isOriginAllowed(originHeader: string): boolean {
  let host = '';
  try {
    host = new URL(originHeader).hostname;
  } catch {
    return false;
  }
  return (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '[::1]' ||
    host === '0.0.0.0' ||
    (allowedOriginHost.length > 0 && host === allowedOriginHost)
  );
}

function failureHtml(reason: string): string {
  // Minimal failure page. PLAN §11 may upgrade to richer template later.
  const safeReason = reason.replace(/[<>&"']/g, (ch) =>
    ch === '<' ? '&lt;' : ch === '>' ? '&gt;' : ch === '&' ? '&amp;' : ch === '"' ? '&quot;' : '&#39;',
  );
  return `<!doctype html>
<meta charset="utf-8">
<title>Login failed</title>
<body style="font-family:system-ui,sans-serif;max-width:40em;margin:4em auto;line-height:1.5">
  <h1>Login failed</h1>
  <p>Reason: <code>${safeReason}</code></p>
  <p><a href="/auth/login">Try again</a></p>
</body>`;
}

// ── Route handlers ──────────────────────────────────────────────────

async function handleLogin(c: Context): Promise<Response> {
  const ip = extractClientIp(c);
  const userAgent = c.req.header('user-agent');

  // Rate limit gate
  const rl = consumeRateToken('login', ip ?? '0.0.0.0');
  if (!rl.allowed) {
    appendAuthAuditBestEffort({ event: 'login.rate_limited', ip, userAgent });
    c.header('Retry-After', String(rl.retryAfterSeconds));
    return c.json({ error: 'rate limited' }, 429);
  }

  // Kill switch
  if (!OIDC_ENABLED) {
    appendAuthAuditBestEffort({
      event: 'kill-switch.engaged',
      reason: 'OIDC_ENABLED=false',
      details: { route: '/auth/login' },
      ip,
      userAgent,
    });
    return c.json({ error: 'OIDC disabled' }, 503);
  }

  // returnTo validation (open-redirect guard)
  const returnTo = sanitizeReturnTo(c.req.query('returnTo'));

  // Opportunistic sweep — keeps dashboard_oidc_requests bounded under
  // attack traffic. Cheap synchronous DELETE.
  try {
    purgeExpiredOidcRequests();
  } catch {
    // Sweep is best-effort; failure shouldn't block login.
  }

  // Acquire OIDC config (cached after first call). Failure → 503 + audit.
  let cfg;
  try {
    cfg = await getEntraConfiguration();
  } catch (err) {
    appendAuthAuditBestEffort({
      event: 'entra.discovery.failure',
      reason: err instanceof EntraError ? err.reason : 'unknown',
      details: { message: err instanceof Error ? err.message : String(err) },
      ip,
      userAgent,
    });
    appendAuthAuditBestEffort({
      event: 'entra.discovery.degraded_login_blocked',
      ip,
      userAgent,
    });
    return c.html(failureHtml('discovery-unavailable'), 503);
  }

  // Generate cryptographic material
  const state = randomState();
  const nonce = randomNonce();
  const pkceVerifier = randomPKCECodeVerifier();
  const codeChallenge = await calculatePKCECodeChallenge(pkceVerifier);
  const txBinding = generateTxBinding();
  const redirectResult = validateRedirectUriSelection(c);
  if (!redirectResult.ok) {
    appendAuthAuditBestEffort({
      event: 'login.failure',
      reason: redirectResult.reason,
      details: { scheme: getEffectiveScheme(c) },
      ip,
      userAgent,
    });
    return c.html(failureHtml(redirectResult.reason), 500);
  }
  const redirectUri = redirectResult.uri;

  // Persist the in-flight request row
  saveOidcRequest({
    state,
    pkceVerifier,
    nonce,
    redirectUri,
    returnTo,
    txBindingHash: txBinding.hash,
    lifetimeSeconds: TX_BINDING_LIFETIME_SECONDS,
  });

  // Set tx cookie + emit start audit
  const isHttps = getEffectiveScheme(c) === 'https';
  c.header('Set-Cookie', buildTxBindingSetCookieHeader(txBinding.value, isHttps));
  appendAuthAuditBestEffort({
    event: 'login.start',
    state: state.slice(0, 8), // prefix only — full state is sensitive
    ip,
    userAgent,
  });

  const authorizeUrl = buildAuthorizeUrl(cfg, {
    redirectUri,
    state,
    codeChallenge,
    nonce,
  });
  return c.redirect(authorizeUrl.toString(), 302);
}

async function handleCallback(c: Context): Promise<Response> {
  const ip = extractClientIp(c);
  const userAgent = c.req.header('user-agent');
  const isHttps = getEffectiveScheme(c) === 'https';

  // Rate limit gate
  const rl = consumeRateToken('callback', ip ?? '0.0.0.0');
  if (!rl.allowed) {
    appendAuthAuditBestEffort({ event: 'callback.rate_limited', ip, userAgent });
    c.header('Retry-After', String(rl.retryAfterSeconds));
    return c.json({ error: 'rate limited' }, 429);
  }

  // Kill switch
  if (!OIDC_ENABLED) {
    appendAuthAuditBestEffort({
      event: 'kill-switch.engaged',
      reason: 'OIDC_ENABLED=false',
      details: { route: '/auth/callback' },
      ip,
      userAgent,
    });
    return c.json({ error: 'OIDC disabled' }, 503);
  }

  // Cheap pre-checks (BEFORE concurrency gate per round 2 fix).
  const state = c.req.query('state');
  const txCookieValue = parseTxBindingCookie(c.req.header('cookie'), isHttps);
  if (!state || !txCookieValue) {
    appendAuthAuditBestEffort({
      event: 'auth.tx_binding_mismatch',
      reason: !state ? 'state-missing' : 'tx-cookie-missing',
      ip,
      userAgent,
    });
    c.header('Set-Cookie', buildTxBindingClearCookieHeader(isHttps));
    return c.html(failureHtml('tx-binding-mismatch'), 403);
  }

  // Concurrency gate BEFORE consumeOidcRequest. If gate is saturated, the
  // user's one-time state row is preserved; they can retry within the
  // ~10 min expires_at window once load eases. (Round 2 fix.)
  if (inflightCallbacks >= AUTH_CALLBACK_MAX_INFLIGHT) {
    appendAuthAuditBestEffort({
      event: 'callback.concurrency_gate',
      details: { inflight: inflightCallbacks, max: AUTH_CALLBACK_MAX_INFLIGHT },
      state: state.slice(0, 8),
      ip,
      userAgent,
    });
    return c.json({ error: 'callback concurrency limit' }, 503);
  }

  // Atomic single-use consume. Hash mismatch → returns undefined → 403.
  const computedHash = hashTxBinding(txCookieValue);
  const oidcRequest = consumeOidcRequest(state, computedHash);
  if (!oidcRequest) {
    appendAuthAuditBestEffort({
      event: 'auth.tx_binding_mismatch',
      reason: 'consume-failed',
      state: state.slice(0, 8),
      ip,
      userAgent,
    });
    c.header('Set-Cookie', buildTxBindingClearCookieHeader(isHttps));
    return c.html(failureHtml('tx-binding-mismatch'), 403);
  }

  // Increment counter ONLY around the expensive Microsoft round-trip +
  // claim validation + session creation. Decrement in finally so any
  // throw / early return releases the slot.
  inflightCallbacks++;
  try {
    let cfg;
    try {
      cfg = await getEntraConfiguration();
    } catch (err) {
      appendAuthAuditBestEffort({
        event: 'login.failure',
        reason: err instanceof EntraError ? err.reason : 'discovery-failed',
        state: state.slice(0, 8),
        ip,
        userAgent,
      });
      c.header('Set-Cookie', buildTxBindingClearCookieHeader(isHttps));
      return c.html(failureHtml('discovery-failed'), 503);
    }

    let exchange;
    try {
      exchange = await exchangeCodeForTokens({
        cfg,
        currentUrl: new URL(c.req.url),
        pkceCodeVerifier: oidcRequest.pkceVerifier,
        expectedState: state,
        expectedNonce: oidcRequest.nonce,
      });
    } catch (err) {
      const reason = err instanceof EntraError ? err.reason : 'token-exchange-timeout';
      appendAuthAuditBestEffort({
        event: 'login.failure',
        reason,
        details: { message: err instanceof Error ? err.message : String(err) },
        state: state.slice(0, 8),
        ip,
        userAgent,
      });
      c.header('Set-Cookie', buildTxBindingClearCookieHeader(isHttps));
      return c.html(failureHtml(reason), 502);
    }

    // PLAN §13: recompute the redirect URI selection and validate that
    // it matches the row stored at /auth/login time. If config drifted
    // mid-session (operator changed env vars between login + callback)
    // OR proxy header semantics changed → fail closed.
    const recheck = validateRedirectUriSelection(c);
    if (!recheck.ok) {
      appendAuthAuditBestEffort({
        event: 'login.failure',
        reason: recheck.reason,
        state: state.slice(0, 8),
        ip,
        userAgent,
      });
      c.header('Set-Cookie', buildTxBindingClearCookieHeader(isHttps));
      return c.html(failureHtml(recheck.reason), 500);
    }
    const validation = checkAuthorizationClaims({
      claims: exchange.claims,
      expectedRedirectUri: recheck.uri,
      redirectUriUsedAtAuthorize: oidcRequest.redirectUri,
    });

    if (!validation.ok) {
      appendAuthAuditBestEffort({
        event: 'login.failure',
        reason: validation.reason,
        state: state.slice(0, 8),
        ip,
        userAgent,
      });
      c.header('Set-Cookie', buildTxBindingClearCookieHeader(isHttps));
      return c.html(failureHtml(validation.reason), 403);
    }

    // Success — create session, set cookie, clear tx cookie, audit, redirect
    const { session, signedValue: _signedValue } = createSession({
      userOid: validation.claims.oid,
      userUpn: validation.claims.upn,
      userName: validation.claims.name ?? null,
      tenantId: validation.claims.tid,
      roles: validation.claims.roles,
      idToken: exchange.idToken,
      userAgent: userAgent ?? null,
      ip: ip ?? null,
    });
    void _signedValue;

    // Two cookie headers — one to set the new session, one to clear the
    // tx cookie. Hono's c.header() with append-style works for multiple
    // Set-Cookie values.
    c.header('Set-Cookie', buildSetCookieHeader(session.id, isHttps), { append: true });
    c.header('Set-Cookie', buildTxBindingClearCookieHeader(isHttps), { append: true });

    appendAuthAuditBestEffort({
      event: 'login.success',
      userOid: session.userOid,
      userUpn: session.userUpn,
      sessionId: session.id,
      state: state.slice(0, 8),
      ip,
      userAgent,
    });

    return c.redirect(oidcRequest.returnTo, 302);
  } finally {
    inflightCallbacks--;
  }
}

async function handleLogout(c: Context): Promise<Response> {
  const ip = extractClientIp(c);
  const userAgent = c.req.header('user-agent');
  const isHttps = getEffectiveScheme(c) === 'https';

  // Origin enforcement (CSRF — /auth/logout is whitelisted past the
  // dashboard's existing Origin middleware because it sits before the
  // CSRF middleware in the chain on the auth-routes path).
  const origin = c.req.header('origin');
  if (!origin) {
    appendAuthAuditBestEffort({ event: 'auth.csrf.no-origin', ip, userAgent });
    return c.json({ error: 'origin required' }, 403);
  }
  if (!isOriginAllowed(origin)) {
    appendAuthAuditBestEffort({
      event: 'auth.csrf.bad-origin',
      details: { origin },
      ip,
      userAgent,
    });
    return c.json({ error: 'cross-origin not allowed' }, 403);
  }

  // Read existing session (if any). Missing/invalid is OK — we still
  // clear the cookie and redirect, just without auditing a phantom logout.
  let session;
  try {
    session = parseAndVerifySignedCookie(c.req.header('cookie'), isHttps);
  } catch {
    session = undefined;
  }

  if (session) {
    const revoked = revokeSession(session.id);
    if (revoked) {
      appendAuthAuditBestEffort({
        event: 'logout',
        userOid: session.userOid,
        userUpn: session.userUpn,
        sessionId: session.id,
        ip,
        userAgent,
      });
    }
    // If revoke returned false (already revoked elsewhere), no audit row.
  }

  c.header('Set-Cookie', buildClearCookieHeader(isHttps));
  return c.redirect('/login', 302);
}

// ── Mount helper ────────────────────────────────────────────────────

export function registerAuthRoutes(app: Hono): void {
  app.get('/auth/login', handleLogin);
  app.get('/auth/callback', handleCallback);
  app.post('/auth/logout', handleLogout);
}
