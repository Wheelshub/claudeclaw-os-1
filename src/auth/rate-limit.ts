// Minimal per-IP token-bucket limiter for /auth/login and /auth/callback.
//
// Pulled forward from PLAN §8 to provide unauthenticated-DB-write
// protection during Stage A. /auth/login is unauthenticated and writes
// one dashboard_oidc_requests row + one audit row per call; without a
// limiter, a request flood can grow both tables until the polished §8
// implementation lands. §8 will replace this using the same env
// constants for drop-in compatibility.
//
// State: in-process Map<ip, bucket> per route. Single Node process,
// single-thread; plain `++/--` and Map mutations are safe without
// atomics. No periodic sweep yet — bounded acceptable for Stage A
// (operator-only, localhost). §10 sweep can prune stale entries later.
//
// Limitations (round 2 documented):
// - IP extraction relies on the existing X-Forwarded-For parsing in
//   src/dashboard.ts; with TRUST_PROXY not yet fully validated (full
//   §13), an attacker behind the trusted proxy could spoof the IP and
//   reset their bucket. Acceptable for Stage A; §13 closes the gap.
// - No token refund on legitimate-but-failed callbacks (the bucket
//   counts the request, not the outcome). Intentional — we want to
//   limit total request volume, not just successful ones.
import {
  AUTH_CALLBACK_RATE_LIMIT_PER_IP_PER_MIN,
  AUTH_LOGIN_RATE_LIMIT_PER_IP_PER_MIN,
} from '../config.js';

export type RateLimitRoute = 'login' | 'callback';

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

interface Bucket {
  tokens: number;
  lastRefill: number; // epoch ms
}

const limits: Record<RateLimitRoute, number> = {
  login: AUTH_LOGIN_RATE_LIMIT_PER_IP_PER_MIN,
  callback: AUTH_CALLBACK_RATE_LIMIT_PER_IP_PER_MIN,
};

const buckets: Record<RateLimitRoute, Map<string, Bucket>> = {
  login: new Map(),
  callback: new Map(),
};

export function consumeRateToken(route: RateLimitRoute, ip: string): RateLimitResult {
  const max = limits[route];
  if (max <= 0) {
    // Defensive: a misconfigured 0/negative env value disables limiting.
    return { allowed: true, retryAfterSeconds: 0 };
  }
  const refillRatePerMs = max / 60_000;
  const now = Date.now();

  const map = buckets[route];
  let bucket = map.get(ip);
  if (!bucket) {
    bucket = { tokens: max, lastRefill: now };
    map.set(ip, bucket);
  } else {
    const elapsed = Math.max(0, now - bucket.lastRefill);
    bucket.tokens = Math.min(max, bucket.tokens + elapsed * refillRatePerMs);
    bucket.lastRefill = now;
  }

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return { allowed: true, retryAfterSeconds: 0 };
  }

  // Compute time until one full token regenerates.
  const tokensNeeded = 1 - bucket.tokens;
  const msNeeded = tokensNeeded / refillRatePerMs;
  const retryAfterSeconds = Math.max(1, Math.ceil(msNeeded / 1000));
  return { allowed: false, retryAfterSeconds };
}

// Test-only: reset all in-memory state. Used by Vitest fixtures so
// rate-limit state from one test doesn't bleed into the next.
export function _resetRateLimitState(): void {
  buckets.login.clear();
  buckets.callback.clear();
}
