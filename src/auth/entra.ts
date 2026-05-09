// Microsoft Entra OIDC client wrapper.
//
// Wraps openid-client v6 with our config + timeout policy. The discovered
// `Configuration` object is cached module-scope so we pay the JWKS / OIDC
// metadata round-trip once per process. Discovery and token exchange are
// each gated by a Promise.race timeout so a slow Entra response can never
// hang the dashboard process.
//
// Validation policy follows PLAN §5: explicit checks for `iss`, `aud`,
// `tid`, `ver`, `roles` (must contain ENTRA_APP_ROLE_VALUE), and the
// caller asserts the redirect URI used at authorize time matches the one
// expected at callback time. Each failure maps to a typed reason that
// the caller turns into an audit row + structured log line.
import * as client from 'openid-client';

import {
  ENTRA_APP_ROLE_VALUE,
  ENTRA_CLIENT_ID,
  ENTRA_CLIENT_SECRET,
  ENTRA_DISCOVERY_TIMEOUT_MS,
  ENTRA_TENANT_ID,
  ENTRA_TOKEN_EXCHANGE_TIMEOUT_MS,
} from '../config.js';
import { logger } from '../logger.js';

export type EntraFailureReason =
  | 'wrong-tenant'
  | 'wrong-aud'
  | 'wrong-iss'
  | 'wrong-version'
  | 'no-roles-claim'
  | 'missing-required-role'
  | 'missing-identity-claims'
  | 'redirect-uri-mismatch'
  | 'tx-binding-mismatch'
  | 'discovery-failed'
  | 'token-exchange-timeout'
  | 'jwks-failed';

export class EntraError extends Error {
  readonly reason: EntraFailureReason;
  constructor(reason: EntraFailureReason, message?: string) {
    super(message ?? reason);
    this.name = 'EntraError';
    this.reason = reason;
  }
}

let cachedConfig: client.Configuration | undefined;
let cachedConfigPromise: Promise<client.Configuration> | undefined;

function expectedIssuer(): string {
  return `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0`;
}

function getIssuerUrl(): URL {
  if (!ENTRA_TENANT_ID) {
    throw new EntraError('discovery-failed', 'ENTRA_TENANT_ID is not set');
  }
  return new URL(expectedIssuer());
}

function withTimeout<T>(p: Promise<T>, ms: number, reason: EntraFailureReason): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<T>((_, reject) => {
    timer = setTimeout(() => reject(new EntraError(reason, `${reason} after ${ms}ms`)), ms);
  });
  return Promise.race([p, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

export async function getEntraConfiguration(): Promise<client.Configuration> {
  if (cachedConfig) return cachedConfig;
  if (cachedConfigPromise) return cachedConfigPromise;
  if (!ENTRA_CLIENT_ID || !ENTRA_CLIENT_SECRET) {
    throw new EntraError(
      'discovery-failed',
      'ENTRA_CLIENT_ID or ENTRA_CLIENT_SECRET is not set',
    );
  }
  cachedConfigPromise = withTimeout(
    client.discovery(getIssuerUrl(), ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET),
    ENTRA_DISCOVERY_TIMEOUT_MS,
    'discovery-failed',
  )
    .then((cfg) => {
      cachedConfig = cfg;
      return cfg;
    })
    .catch((err: unknown) => {
      // Clear the in-flight promise so the next call can retry instead of
      // permanently caching the rejection.
      cachedConfigPromise = undefined;
      throw err;
    });
  return cachedConfigPromise;
}

// Triggers discovery + JWKS fetch synchronously at boot so the first
// user-facing /auth/login isn't paying the cold-start cost. Failure is
// logged WARN but does NOT abort startup — /auth/login will return 503
// (`entra.discovery.unavailable`) until the next call succeeds.
export async function prewarmEntraConfiguration(): Promise<void> {
  try {
    await getEntraConfiguration();
    logger.info('Entra OIDC discovery cached');
  } catch (err) {
    logger.warn(
      { err },
      'Entra OIDC discovery failed at prewarm — /auth/login will return 503 until next attempt succeeds',
    );
  }
}

export interface BuildAuthorizeUrlInput {
  redirectUri: string;
  state: string;
  codeChallenge: string;
  nonce: string;
}

export function buildAuthorizeUrl(
  cfg: client.Configuration,
  input: BuildAuthorizeUrlInput,
): URL {
  return client.buildAuthorizationUrl(cfg, {
    redirect_uri: input.redirectUri,
    scope: 'openid profile email',
    state: input.state,
    code_challenge: input.codeChallenge,
    code_challenge_method: 'S256',
    nonce: input.nonce,
    response_type: 'code',
    response_mode: 'query',
    prompt: 'select_account',
  });
}

export interface ExchangeCodeInput {
  cfg: client.Configuration;
  currentUrl: URL;
  pkceCodeVerifier: string;
  expectedState: string;
  expectedNonce: string;
}

export interface ExchangeCodeResult {
  idToken: string;
  claims: Record<string, unknown>;
}

export async function exchangeCodeForTokens(
  input: ExchangeCodeInput,
): Promise<ExchangeCodeResult> {
  const tokens = await withTimeout(
    client.authorizationCodeGrant(input.cfg, input.currentUrl, {
      pkceCodeVerifier: input.pkceCodeVerifier,
      expectedState: input.expectedState,
      expectedNonce: input.expectedNonce,
      idTokenExpected: true,
    }),
    ENTRA_TOKEN_EXCHANGE_TIMEOUT_MS,
    'token-exchange-timeout',
  );
  if (!tokens.id_token) {
    throw new EntraError('jwks-failed', 'no id_token in token endpoint response');
  }
  const claims = tokens.claims() as Record<string, unknown> | undefined;
  if (!claims) {
    throw new EntraError('jwks-failed', 'id_token claims could not be parsed');
  }
  return { idToken: tokens.id_token, claims };
}

export interface CheckClaimsInput {
  claims: Record<string, unknown>;
  expectedRedirectUri: string;
  redirectUriUsedAtAuthorize: string;
}

export interface ValidatedClaims {
  oid: string;
  upn: string;
  name?: string;
  tid: string;
  iss: string;
  aud: string;
  ver: string;
  roles: string[];
  nonce?: string;
}

export type CheckClaimsResult =
  | { ok: true; claims: ValidatedClaims }
  | { ok: false; reason: EntraFailureReason };

export function checkAuthorizationClaims(input: CheckClaimsInput): CheckClaimsResult {
  const c = input.claims;

  if (input.expectedRedirectUri !== input.redirectUriUsedAtAuthorize) {
    return { ok: false, reason: 'redirect-uri-mismatch' };
  }
  if (typeof c.iss !== 'string' || c.iss !== expectedIssuer()) {
    return { ok: false, reason: 'wrong-iss' };
  }
  if (typeof c.aud !== 'string' || c.aud !== ENTRA_CLIENT_ID) {
    return { ok: false, reason: 'wrong-aud' };
  }
  if (typeof c.tid !== 'string' || c.tid !== ENTRA_TENANT_ID) {
    return { ok: false, reason: 'wrong-tenant' };
  }
  if (typeof c.ver !== 'string' || c.ver !== '2.0') {
    return { ok: false, reason: 'wrong-version' };
  }
  if (!Array.isArray(c.roles)) {
    return { ok: false, reason: 'no-roles-claim' };
  }
  const roles = c.roles.filter((r): r is string => typeof r === 'string');
  if (!roles.includes(ENTRA_APP_ROLE_VALUE)) {
    return { ok: false, reason: 'missing-required-role' };
  }

  // Microsoft v2 id_tokens use `oid` for stable per-user identity. UPN
  // sources, in priority order: `upn` (AAD-only), `preferred_username`
  // (B2B/B2C), `email` (last resort).
  const oid = typeof c.oid === 'string' ? c.oid : undefined;
  const upn =
    typeof c.upn === 'string'
      ? c.upn
      : typeof c.preferred_username === 'string'
        ? c.preferred_username
        : typeof c.email === 'string'
          ? c.email
          : undefined;
  if (!oid || !upn) {
    return { ok: false, reason: 'missing-identity-claims' };
  }

  return {
    ok: true,
    claims: {
      oid,
      upn,
      name: typeof c.name === 'string' ? c.name : undefined,
      tid: c.tid,
      iss: c.iss,
      aud: c.aud,
      ver: c.ver,
      roles,
      nonce: typeof c.nonce === 'string' ? c.nonce : undefined,
    },
  };
}

// Re-export PKCE / state / nonce generators so callers don't have to
// import openid-client directly. Keeps the OIDC dep behind a single
// boundary (this module).
export const randomPKCECodeVerifier = client.randomPKCECodeVerifier;
export const calculatePKCECodeChallenge = client.calculatePKCECodeChallenge;
export const randomState = client.randomState;
export const randomNonce = client.randomNonce;
