// Session machinery for the dashboard's OIDC browser auth.
//
// Cookie shape: `<id>.<sig>` where
//   id  = base64url(crypto.randomBytes(32))
//   sig = base64url(HMAC-SHA-256(SESSION_SECRET, id))
//
// Verification splits at the first '.', timingSafeEqual on the MAC, then
// looks the id up in the DB. The MAC tells us the cookie hasn't been
// tampered with; the DB lookup tells us the session is still valid.
//
// HTTPS uses the `__Host-` prefix (browsers reject the cookie if it
// arrives with Domain= or without Path=/, and require Secure). For
// `http://localhost` dev we drop the prefix because Secure cannot be set
// without HTTPS. Microsoft's OIDC localhost carve-out makes plain HTTP
// fine for dev.
import crypto from 'crypto';

import { SESSION_SECRET } from '../config.js';
import {
  type AuthAuditInput,
  type DashboardSession,
  appendAuthAudit,
  createDashboardSession,
  getDashboardSession,
  revokeDashboardSession,
  touchDashboardSession,
} from '../db.js';
import { logger } from '../logger.js';

export const SESSION_LIFETIME_SECONDS = 28800; // 8 hours

// Throttle window for touchSessionThrottled. Under normal traffic, a single
// user generates 50-100 requests/min; without throttling each becomes a
// SQLite write. 60s is fine-grained enough for the only consumer (operator
// querying "was this session active recently") and quiet enough to avoid
// write-storm noise during incidents.
export const SESSION_TOUCH_THROTTLE_SECONDS = 60;

const COOKIE_HTTPS = '__Host-ccd_session';
const COOKIE_HTTP = 'ccd_session';

function getSessionSecret(): Buffer {
  if (!SESSION_SECRET) {
    throw new Error(
      'SESSION_SECRET is not set. Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64url\'))"',
    );
  }
  return Buffer.from(SESSION_SECRET, 'utf-8');
}

function signId(id: string): string {
  return crypto.createHmac('sha256', getSessionSecret()).update(id).digest('base64url');
}

function timingSafeEqualB64url(a: string, b: string): boolean {
  let bufA: Buffer;
  let bufB: Buffer;
  try {
    bufA = Buffer.from(a, 'base64url');
    bufB = Buffer.from(b, 'base64url');
  } catch {
    return false;
  }
  if (bufA.length === 0 || bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Returns the verified id if the MAC checks out, undefined otherwise.
// Does not touch the database.
function verifySignedValue(signedValue: string): string | undefined {
  const dot = signedValue.indexOf('.');
  if (dot <= 0 || dot === signedValue.length - 1) return undefined;
  const id = signedValue.slice(0, dot);
  const sig = signedValue.slice(dot + 1);
  return timingSafeEqualB64url(sig, signId(id)) ? id : undefined;
}

export function buildSessionCookieValue(id: string): string {
  return `${id}.${signId(id)}`;
}

export function getActiveSessionCookieName(isHttps: boolean): string {
  return isHttps ? COOKIE_HTTPS : COOKIE_HTTP;
}

export interface CreateSessionInput {
  userOid: string;
  userUpn: string;
  userName?: string | null;
  tenantId: string;
  roles: string[];
  idToken: string;
  userAgent?: string | null;
  ip?: string | null;
}

export interface CreateSessionResult {
  session: DashboardSession;
  signedValue: string;
}

export function createSession(input: CreateSessionInput): CreateSessionResult {
  const id = crypto.randomBytes(32).toString('base64url');
  const idTokenHash = crypto.createHash('sha256').update(input.idToken).digest('base64url');
  const session = createDashboardSession({
    id,
    userOid: input.userOid,
    userUpn: input.userUpn,
    userName: input.userName ?? null,
    tenantId: input.tenantId,
    roles: input.roles,
    idTokenHash,
    userAgent: input.userAgent ?? null,
    ip: input.ip ?? null,
    lifetimeSeconds: SESSION_LIFETIME_SECONDS,
  });
  return { session, signedValue: buildSessionCookieValue(id) };
}

export function getSessionFromSignedValue(signedValue: string): DashboardSession | undefined {
  const id = verifySignedValue(signedValue);
  return id ? getDashboardSession(id) : undefined;
}

export function touchSession(id: string): void {
  touchDashboardSession(id);
}

// Calls touchSession only when the session's last_seen_at is older than
// SESSION_TOUCH_THROTTLE_SECONDS. Default path used by requireAuth on every
// authenticated request — bare touchSession() exists for explicit-ping
// callers who've already decided the touch should happen.
export function touchSessionThrottled(session: DashboardSession): void {
  const now = Math.floor(Date.now() / 1000);
  if (now - session.lastSeenAt < SESSION_TOUCH_THROTTLE_SECONDS) return;
  touchDashboardSession(session.id);
}

// Returns true when an actual revocation happened. Callers that audit
// `session.revoke` should gate the audit on this return value to avoid
// emitting phantom rows for stale or already-revoked ids.
export function revokeSession(id: string): boolean {
  return revokeDashboardSession(id);
}

// Best-effort audit wrapper. Auth state changes (createSession, revokeSession,
// cookie set/clear) cannot depend on audit success — a failed audit row is
// observability degradation, not a state-correctness problem. Wraps every
// audit insert in try/catch + WARN log so a SQLite lock or disk-full error
// can't 500 a handler that already mutated durable auth state.
export function appendAuthAuditBestEffort(input: AuthAuditInput): void {
  try {
    appendAuthAudit(input);
  } catch (err) {
    logger.warn(
      { err, event: input.event, ip: input.ip, sessionId: input.sessionId },
      'auth audit insert failed — auth state change still applied',
    );
  }
}

function cookieAttrs(isHttps: boolean, maxAge: number): string[] {
  const attrs = ['HttpOnly', 'Path=/', 'SameSite=Lax', `Max-Age=${maxAge}`];
  if (isHttps) attrs.push('Secure');
  return attrs;
}

export function buildSetCookieHeader(sessionId: string, isHttps: boolean): string {
  const name = getActiveSessionCookieName(isHttps);
  const value = buildSessionCookieValue(sessionId);
  return [`${name}=${value}`, ...cookieAttrs(isHttps, SESSION_LIFETIME_SECONDS)].join('; ');
}

export function buildClearCookieHeader(isHttps: boolean): string {
  const name = getActiveSessionCookieName(isHttps);
  return [`${name}=`, ...cookieAttrs(isHttps, 0)].join('; ');
}

// Shared parser used by both Hono middleware AND the raw Node WS upgrade
// handler (Hono's helpers aren't available there). Iterates every entry
// matching the active cookie name — a misbehaving proxy can emit
// duplicates, and we want the first one whose MAC + DB lookup succeeds
// rather than picking the first by position and silently rejecting valid
// later entries.
export function parseAndVerifySignedCookie(
  cookieHeader: string | null | undefined,
  isHttps: boolean,
): DashboardSession | undefined {
  if (!cookieHeader) return undefined;
  const wantedName = getActiveSessionCookieName(isHttps);
  const candidates: string[] = [];
  for (const part of cookieHeader.split(/;\s*/)) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === wantedName) {
      candidates.push(part.slice(eq + 1).trim());
    }
  }
  for (const value of candidates) {
    const session = getSessionFromSignedValue(value);
    if (session) return session;
  }
  return undefined;
}

// ── Browser-binding transaction cookie ──────────────────────────────
//
// Short-lived cookie (10 min) minted at /auth/login, verified at
// /auth/callback. Ties the login start to the same browser at callback
// time — without it, an attacker who steals a `state` value (e.g. via a
// log line, referer header, or shoulder-surf of the URL bar) could
// complete the OIDC handshake from a different browser.
//
// Wire shape: cookie holds the raw 32-byte value (base64url). The DB row
// holds HMAC-SHA-256(SESSION_SECRET, value). Verification: read cookie,
// recompute hash, look up by (state, computed_hash). The DB does the
// constant-time match implicitly via the WHERE-clause check in
// consumeOidcRequest. A leaked DB row alone cannot be used to forge a
// cookie — you'd need SESSION_SECRET too.

export const TX_BINDING_LIFETIME_SECONDS = 600;

const TX_COOKIE_HTTPS = '__Host-ccd_oidc_tx';
const TX_COOKIE_HTTP = 'ccd_oidc_tx';

export function getTxBindingCookieName(isHttps: boolean): string {
  return isHttps ? TX_COOKIE_HTTPS : TX_COOKIE_HTTP;
}

export function hashTxBinding(value: string): string {
  return crypto.createHmac('sha256', getSessionSecret()).update(value).digest('base64url');
}

export interface TxBinding {
  value: string;
  hash: string;
}

export function generateTxBinding(): TxBinding {
  const value = crypto.randomBytes(32).toString('base64url');
  return { value, hash: hashTxBinding(value) };
}

export function buildTxBindingSetCookieHeader(value: string, isHttps: boolean): string {
  const name = getTxBindingCookieName(isHttps);
  return [`${name}=${value}`, ...cookieAttrs(isHttps, TX_BINDING_LIFETIME_SECONDS)].join('; ');
}

export function buildTxBindingClearCookieHeader(isHttps: boolean): string {
  const name = getTxBindingCookieName(isHttps);
  return [`${name}=`, ...cookieAttrs(isHttps, 0)].join('; ');
}

// Returns the raw tx_binding value if a cookie is present (caller hashes
// it for the DB lookup). Returns the FIRST entry — unlike the session
// cookie path, there's no "try every duplicate" loop because the DB
// `consumeOidcRequest` is what gates correctness; iterating here would
// only mask cookie-emission bugs.
export function parseTxBindingCookie(
  cookieHeader: string | null | undefined,
  isHttps: boolean,
): string | undefined {
  if (!cookieHeader) return undefined;
  const wantedName = getTxBindingCookieName(isHttps);
  for (const part of cookieHeader.split(/;\s*/)) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === wantedName) {
      const value = part.slice(eq + 1).trim();
      return value || undefined;
    }
  }
  return undefined;
}
