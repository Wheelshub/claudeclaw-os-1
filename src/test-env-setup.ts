// Runs before any test module imports. Sets the env vars that config.ts
// reads at import time so contract tests can build a working dashboard
// app without polluting the developer's real .env or DB.
process.env.DASHBOARD_MUTATIONS_ENABLED = process.env.DASHBOARD_MUTATIONS_ENABLED || 'true';
process.env.WARROOM_ENABLED = process.env.WARROOM_ENABLED || 'false';
// Pinned for the CSRF allowlist regression — the contract test issues
// a POST with Origin=https://dash.test.example and asserts the
// middleware lets it through. Without this, the CSRF check has no
// allowed-origin host and 403s every cross-origin POST.
process.env.DASHBOARD_URL = process.env.DASHBOARD_URL || 'https://dash.test.example';
// SESSION_SECRET is required by src/auth/session.ts to HMAC-sign cookies.
// Tests set a fixed value so signed cookies are reproducible across runs.
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret-do-not-ship';
// Loose-validated TRUST_PROXY=false so tests don't need to fake X-Forwarded-Proto.
process.env.TRUST_PROXY = process.env.TRUST_PROXY || 'false';
// OIDC routes live so /auth/login etc. work in tests.
process.env.OIDC_ENABLED = process.env.OIDC_ENABLED || 'true';
// Entra app role for session validation in requireAuth's session path.
process.env.ENTRA_APP_ROLE_VALUE = process.env.ENTRA_APP_ROLE_VALUE || 'Dashboard.User';
// PLAN §13 redirect URI selection: tests run with TRUST_PROXY=false so
// scheme is 'http'; the dev URI must point at localhost for the validator
// to accept it. This isn't a real Entra app — it's just a syntactically
// valid value so /auth/login doesn't 500 with `dev-redirect-uri-missing`.
process.env.ENTRA_REDIRECT_URI_DEV =
  process.env.ENTRA_REDIRECT_URI_DEV || 'http://localhost:3141/auth/callback';
