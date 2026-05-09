// Open-redirect guard for the OIDC `returnTo` parameter.
//
// `/auth/login?returnTo=…` is a user-controlled string we'll redirect to
// after a successful login. Without validation, an attacker can craft
// a phishing link that drops the victim on a lookalike host — the URL
// looks legitimate (it does start with our dashboard), but after login
// it redirects to evil.com.
//
// Strategy: only allow paths inside our origin (start with `/`, no
// protocol-relative `//`, no Windows-style `\` separators, no control
// chars, bounded length). Validate the raw input AND the
// percent-decoded form so `%2F%2Fevil.com` style bypasses fail.

const MAX_RETURN_TO_LEN = 512;

const CONTROL_CHAR = /[\x00-\x1F\x7F]/;

function looksSafePath(p: string): boolean {
  if (p.length === 0 || p.length > MAX_RETURN_TO_LEN) return false;
  if (!p.startsWith('/')) return false;
  if (p.startsWith('//')) return false;
  if (p.includes('\\')) return false;
  // Per PLAN §6: no `:` before any `/`. Practically redundant with the
  // start-with-`/` check (since the first `/` is at index 0), but kept
  // as defence-in-depth in case the start-check is ever relaxed.
  const firstColon = p.indexOf(':');
  const firstSlash = p.indexOf('/');
  if (firstColon !== -1 && firstColon < firstSlash) return false;
  if (CONTROL_CHAR.test(p)) return false;
  return true;
}

export function sanitizeReturnTo(
  input: string | null | undefined,
  defaultPath = '/',
): string {
  if (!input) return defaultPath;
  if (!looksSafePath(input)) return defaultPath;
  let decoded: string;
  try {
    decoded = decodeURIComponent(input);
  } catch {
    return defaultPath;
  }
  if (!looksSafePath(decoded)) return defaultPath;
  return input;
}
