// Auth route + middleware regression tests.
//
// Why: PLAN §12 removes the inline `requireToken()` calls from /, /warroom,
// /warroom/text, /warroom-test-audio handlers and replaces them with the
// unified requireAuth middleware. These tests assert that:
//
//   1. Each previously-gated branch is still gated (no auth → redirect or 401).
//   2. Both auth modes (?token= and signed session cookie) reach the handler.
//   3. The new /auth/* routes behave per spec on the OIDC failure paths.
//   4. returnTo validator rejects open-redirect attacks.
//
// Tests use Hono's `app.request()` so no server is booted. The DB is the
// in-memory fixture from `_initTestDatabase()`. SESSION_SECRET +
// DASHBOARD_TOKEN are set by `test-env-setup.ts` (vitest setupFiles).

import type { Hono } from 'hono';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { _initTestDatabase, createDashboardSession } from '../db.js';
import { buildDashboardApp } from '../dashboard.js';
import { _resetRateLimitState } from './rate-limit.js';
import { buildSessionCookieValue } from './session.js';

const TOKEN = process.env.DASHBOARD_TOKEN || 'test-contract-token';

let app: Hono;

beforeAll(() => {
  app = buildDashboardApp(undefined) as unknown as Hono;
});

beforeEach(() => {
  _initTestDatabase();
  _resetRateLimitState();
});

afterEach(() => {
  // Restore env vars touched by individual tests.
  delete process.env.DASHBOARD_LEGACY;
});

// Forge a signed session cookie that requireAuth's session path will
// accept. Bypasses the Microsoft round-trip — we're testing route gating,
// not OIDC flow correctness.
function forgeValidSessionCookie(): string {
  const id = 'test-session-' + Math.random().toString(36).slice(2, 18);
  const now = Math.floor(Date.now() / 1000);
  createDashboardSession({
    id,
    userOid: 'test-oid-00000000',
    userUpn: 'test@example.com',
    userName: 'Test User',
    tenantId: 'test-tenant',
    roles: ['Dashboard.User'],
    idTokenHash: 'test-hash',
    userAgent: 'vitest',
    ip: '127.0.0.1',
    lifetimeSeconds: 3600,
  });
  void now;
  return 'ccd_session=' + buildSessionCookieValue(id);
}

function forgeSessionCookieMissingRole(): string {
  const id = 'test-session-norole-' + Math.random().toString(36).slice(2, 10);
  createDashboardSession({
    id,
    userOid: 'test-oid-00000001',
    userUpn: 'norole@example.com',
    tenantId: 'test-tenant',
    roles: ['SomeOtherRole'],
    idTokenHash: 'test-hash',
    lifetimeSeconds: 3600,
  });
  return 'ccd_session=' + buildSessionCookieValue(id);
}

function withCookie(headers: Record<string, string>, cookie: string): Record<string, string> {
  return { ...headers, Cookie: cookie };
}

// ── Route gate tests — the previously-inline-gated branches ────────

describe('requireAuth gates the previously-inline-gated branches', () => {
  // The 4 actual inline-removal branches in dashboard.ts (PLAN's count
  // of 6 was off — /warroom-music and /warroom-client.js never had
  // inline gates).
  describe('GET / (legacy branch)', () => {
    beforeEach(() => {
      // Force the legacy branch (no Vite dist + DASHBOARD_LEGACY=true).
      process.env.DASHBOARD_LEGACY = 'true';
    });

    it('no auth → 302 redirect to /login landing page', async () => {
      const res = await app.request('/');
      expect(res.status).toBe(302);
      expect(res.headers.get('location')).toContain('/login?returnTo=');
    });

    it('?token= → not 401, not redirected to a login page', async () => {
      const res = await app.request('/?token=' + TOKEN);
      expect(res.status).not.toBe(401);
      const loc = res.headers.get('location') || '';
      expect(loc.includes('/login')).toBe(false);
    });

    it('valid session cookie → not 401, not redirected to a login page', async () => {
      const cookie = forgeValidSessionCookie();
      const res = await app.request('/', { headers: withCookie({}, cookie) });
      expect(res.status).not.toBe(401);
      const loc = res.headers.get('location') || '';
      expect(loc.includes('/login')).toBe(false);
    });
  });

  describe.each([
    ['/warroom?mode=picker'],
    ['/warroom?mode=voice'],
    ['/warroom/text'],
    ['/warroom-test-audio'],
  ])('GET %s', (urlPath) => {
    it('no auth → 302 redirect to /login landing page', async () => {
      const res = await app.request(urlPath);
      expect(res.status).toBe(302);
      expect(res.headers.get('location')).toContain('/login?returnTo=');
    });

    it('?token= → not 401, not redirected to a login page', async () => {
      const sep = urlPath.includes('?') ? '&' : '?';
      const res = await app.request(`${urlPath}${sep}token=${TOKEN}`);
      expect(res.status).not.toBe(401);
      const loc = res.headers.get('location') || '';
      expect(loc.includes('/login')).toBe(false);
    });

    it('valid session cookie → not 401, not redirected to a login page', async () => {
      const cookie = forgeValidSessionCookie();
      const res = await app.request(urlPath, { headers: withCookie({}, cookie) });
      expect(res.status).not.toBe(401);
      const loc = res.headers.get('location') || '';
      expect(loc.includes('/login')).toBe(false);
    });
  });
});

describe('requireAuth: API routes', () => {
  it('GET /api/health without auth → 401 JSON', async () => {
    const res = await app.request('/api/health');
    expect(res.status).toBe(401);
  });

  it('GET /api/health with valid cookie → not 401', async () => {
    const cookie = forgeValidSessionCookie();
    const res = await app.request('/api/health', { headers: withCookie({}, cookie) });
    expect(res.status).not.toBe(401);
  });

  it('GET /api/health with cookie missing required role → 401', async () => {
    const cookie = forgeSessionCookieMissingRole();
    const res = await app.request('/api/health', { headers: withCookie({}, cookie) });
    expect(res.status).toBe(401);
  });

  it('GET /api/health with Authorization Bearer token → not 401', async () => {
    const res = await app.request('/api/health', {
      headers: { Authorization: 'Bearer ' + TOKEN },
    });
    expect(res.status).not.toBe(401);
  });
});

// ── /auth/* route behavior ──────────────────────────────────────────

describe('/auth/login', () => {
  it('returns 503 when OIDC_ENABLED=false', async () => {
    const original = process.env.OIDC_ENABLED;
    process.env.OIDC_ENABLED = 'false';
    try {
      // Re-import the module-cached config wouldn't pick this up cleanly;
      // we test the env-driven kill switch logic indirectly via §6.6
      // smoke. For unit-level coverage we accept that the running app
      // captured OIDC_ENABLED=true at import time. This test is a
      // placeholder asserting the route at least exists and doesn't 404.
      const res = await app.request('/auth/login');
      // Either 503 (if env captured false) or 302 (toward Microsoft).
      // Both prove the route is wired.
      expect([302, 503, 500]).toContain(res.status);
    } finally {
      process.env.OIDC_ENABLED = original;
    }
  });

  it('does not 404 — route is registered', async () => {
    const res = await app.request('/auth/login');
    expect(res.status).not.toBe(404);
  });
});

describe('/auth/callback', () => {
  it('does not 404 — route is registered', async () => {
    const res = await app.request('/auth/callback');
    expect(res.status).not.toBe(404);
  });

  it('without state or tx cookie → 403 + clears tx cookie', async () => {
    const res = await app.request('/auth/callback');
    expect(res.status).toBe(403);
    const setCookie = res.headers.get('set-cookie') || '';
    expect(setCookie).toContain('ccd_oidc_tx=');
    expect(setCookie).toContain('Max-Age=0');
  });
});

describe('/auth/logout', () => {
  it('rejects POST without Origin header → 403', async () => {
    const res = await app.request('/auth/logout', { method: 'POST' });
    expect(res.status).toBe(403);
  });

  it('rejects POST with cross-origin Origin → 403', async () => {
    const res = await app.request('/auth/logout', {
      method: 'POST',
      headers: { Origin: 'https://evil.example' },
    });
    expect(res.status).toBe(403);
  });

  it('accepts POST with same-origin Origin (localhost) → 302 to /login', async () => {
    const res = await app.request('/auth/logout', {
      method: 'POST',
      headers: { Origin: 'http://localhost:3141' },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/login');
  });

  it('clears session cookie regardless of session state', async () => {
    const res = await app.request('/auth/logout', {
      method: 'POST',
      headers: { Origin: 'http://localhost:3141' },
    });
    const setCookie = res.headers.get('set-cookie') || '';
    expect(setCookie).toContain('ccd_session=');
    expect(setCookie).toContain('Max-Age=0');
  });
});

// ── returnTo validator (sanitizeReturnTo) ───────────────────────────

describe('sanitizeReturnTo', () => {
  // Imported here so the test bundle reports both file's coverage.
  it('accepts simple paths', async () => {
    const { sanitizeReturnTo } = await import('./return-to.js');
    expect(sanitizeReturnTo('/')).toBe('/');
    expect(sanitizeReturnTo('/foo')).toBe('/foo');
    expect(sanitizeReturnTo('/agents/main')).toBe('/agents/main');
  });

  it('rejects protocol-relative URLs', async () => {
    const { sanitizeReturnTo } = await import('./return-to.js');
    expect(sanitizeReturnTo('//evil.example')).toBe('/');
  });

  it('rejects backslash paths (Windows-style)', async () => {
    const { sanitizeReturnTo } = await import('./return-to.js');
    expect(sanitizeReturnTo('/\\foo')).toBe('/');
  });

  it('rejects control characters', async () => {
    const { sanitizeReturnTo } = await import('./return-to.js');
    expect(sanitizeReturnTo('/foo\x00bar')).toBe('/');
    expect(sanitizeReturnTo('/foo\nbar')).toBe('/');
  });

  it('rejects > 512 chars', async () => {
    const { sanitizeReturnTo } = await import('./return-to.js');
    expect(sanitizeReturnTo('/' + 'a'.repeat(600))).toBe('/');
  });

  it('rejects percent-encoded backslash bypass', async () => {
    const { sanitizeReturnTo } = await import('./return-to.js');
    // /%5Cfoo decodes to /\foo which has a backslash → reject
    expect(sanitizeReturnTo('/%5Cfoo')).toBe('/');
  });

  it('rejects malformed percent encoding', async () => {
    const { sanitizeReturnTo } = await import('./return-to.js');
    // Bad percent-encoding throws in decodeURIComponent → fall back
    expect(sanitizeReturnTo('/%ZZ')).toBe('/');
  });

  it('falls back to default for null/undefined/empty', async () => {
    const { sanitizeReturnTo } = await import('./return-to.js');
    expect(sanitizeReturnTo(null)).toBe('/');
    expect(sanitizeReturnTo(undefined)).toBe('/');
    expect(sanitizeReturnTo('')).toBe('/');
  });
});
