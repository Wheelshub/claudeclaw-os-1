#!/usr/bin/env tsx
/**
 * Prestart guard for OIDC dashboard auth.
 *
 * Wired via package.json as `prestart` and `predev:dashboard`. Runs
 * before any dashboard boot to catch misconfigured env vars early —
 * better to fail fast with a clear message than to discover the issue
 * mid-OIDC-handshake when Microsoft returns an unhelpful error.
 *
 * Usage (operator-driven):
 *   op run -- npm run dev:dashboard   # predev:dashboard fires this first
 *   op run -- npm start                # prestart fires this first
 *
 * Without `op run --`, the env reads from process.env / .env directly;
 * if your secrets are in 1Password, you'll see the literal `op://`
 * placeholder values and fail the format checks below.
 *
 * Exits 0 on pass, 1 on failure with explicit per-key messages.
 */
import { readEnvFile } from '../src/env.js';

const REQUIRED_KEYS = [
  'ENTRA_TENANT_ID',
  'ENTRA_CLIENT_ID',
  'ENTRA_CLIENT_SECRET',
  'ENTRA_REDIRECT_URI_PROD',
  'ENTRA_REDIRECT_URI_DEV',
  'ENTRA_APP_ROLE_VALUE',
  'SESSION_SECRET',
  'DASHBOARD_URL',
  'DASHBOARD_TOKEN',
] as const;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_RE = /^[0-9a-f]+$/i;

const errors: string[] = [];
const warnings: string[] = [];

function read(key: string, env: Record<string, string>): string {
  // process.env wins (op run -- exports values that way) over .env file.
  return (process.env[key] || env[key] || '').trim();
}

function isUnresolvedOpRef(value: string): boolean {
  return value.startsWith('op://');
}

const env = readEnvFile([...REQUIRED_KEYS]);

// 1. Presence
for (const key of REQUIRED_KEYS) {
  const value = read(key, env);
  if (!value) {
    errors.push(`${key} is missing — set it in .env or via op run --`);
    continue;
  }
  if (isUnresolvedOpRef(value)) {
    errors.push(
      `${key} contains a literal op:// reference (${value}). Run with \`op run -- ...\` so 1Password resolves it before the process starts.`,
    );
  }
}

// 2. Format checks (only run if presence passed for the key in question)
function check(key: string, predicate: (v: string) => boolean, message: string): void {
  const value = read(key, env);
  if (!value || isUnresolvedOpRef(value)) return; // already errored above
  if (!predicate(value)) {
    errors.push(`${key}: ${message}. Got: ${value}`);
  }
}

function checkWarn(key: string, predicate: (v: string) => boolean, message: string): void {
  const value = read(key, env);
  if (!value || isUnresolvedOpRef(value)) return;
  if (!predicate(value)) {
    warnings.push(`${key}: ${message}. Got: ${value}`);
  }
}

check('ENTRA_TENANT_ID', (v) => UUID_RE.test(v), 'must be a UUID (e.g. 12345678-1234-1234-1234-123456789012)');

check(
  'ENTRA_REDIRECT_URI_PROD',
  (v) => v.startsWith('https://'),
  'must start with https:// (Microsoft requires HTTPS for non-localhost redirect URIs)',
);

check(
  'ENTRA_REDIRECT_URI_DEV',
  (v) => v.startsWith('http://localhost:') || v.startsWith('http://127.0.0.1:') || v.startsWith('http://[::1]:'),
  "must start with http://localhost: (or http://127.0.0.1: / http://[::1]:) — Microsoft's HTTP carve-out applies only to loopback hosts",
);

check(
  'SESSION_SECRET',
  (v) => HEX_RE.test(v) && v.length >= 64,
  'must be at least 64 hex chars (generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))")',
);

check('ENTRA_APP_ROLE_VALUE', (v) => v.length > 0, 'must be non-empty');

check(
  'DASHBOARD_URL',
  (v) => {
    try {
      const u = new URL(v);
      return u.protocol === 'https:' || u.protocol === 'http:';
    } catch {
      return false;
    }
  },
  'must be a parseable URL with http:// or https:// scheme',
);

checkWarn(
  'DASHBOARD_TOKEN',
  (v) => v.length >= 32,
  'is shorter than 32 chars — recommend at least 32 random chars (low-entropy tokens are guessable)',
);

// 3. Cross-field consistency: prod redirect URI host should match
//    DASHBOARD_URL host (also enforced at runtime in src/auth/routes.ts
//    per PLAN §13, but better to fail at startup).
const dashUrl = read('DASHBOARD_URL', env);
const prodRedirect = read('ENTRA_REDIRECT_URI_PROD', env);
if (dashUrl && prodRedirect && !isUnresolvedOpRef(dashUrl) && !isUnresolvedOpRef(prodRedirect)) {
  try {
    const dashHost = new URL(dashUrl).host;
    const prodHost = new URL(prodRedirect).host;
    if (dashHost !== prodHost) {
      errors.push(
        `ENTRA_REDIRECT_URI_PROD host (${prodHost}) does not match DASHBOARD_URL host (${dashHost}) — Entra redirect must land on the dashboard's own domain.`,
      );
    }
  } catch {
    // URL parsing already covered by individual checks above.
  }
}

// 4. Print results
if (warnings.length > 0) {
  console.warn('\n⚠️  prestart warnings:');
  for (const w of warnings) console.warn(`  - ${w}`);
}

if (errors.length > 0) {
  console.error('\n❌ prestart failed — environment is not ready for OIDC dashboard auth:\n');
  for (const e of errors) console.error(`  - ${e}`);
  console.error('\nFix the items above and re-run. If your secrets live in 1Password, prefix the command with `op run --`.\n');
  process.exit(1);
}

console.log('✅ prestart: OIDC dashboard env vars look good.');
