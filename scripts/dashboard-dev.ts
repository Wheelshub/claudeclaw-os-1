#!/usr/bin/env tsx
/**
 * Dashboard-only dev entry point.
 *
 * Boots the dashboard HTTP server with no Telegram bot, no scheduler, no
 * War Room, no decay/consolidation. Useful for OIDC iteration when you
 * want to exercise the auth flow without booting the full bot stack
 * (which requires a Telegram token, ALLOWED_CHAT_ID, etc.).
 *
 * The single dashboard endpoint that needs the bot
 * (processMessageFromDashboard) returns 503 here instead of crashing —
 * see src/dashboard.ts. All other endpoints behave normally.
 *
 * First-boot sequence on a fresh clone (store/ absent):
 *
 *   mkdir -p store
 *   op run -- npm run migrate
 *   op run -- npm run dev:dashboard
 *
 * The mkdir is required because both scripts/migrate.ts and
 * src/migrations.ts treat a missing store/ as "fresh install — nothing
 * to migrate" and auto-stamp .applied.json to the latest version, which
 * would skip pending migrations permanently.
 *
 * On subsequent boots (store/ already exists):
 *
 *   op run -- npm run dev:dashboard
 *
 * The prestart guard (predev:dashboard) runs scripts/check-env.ts first
 * to verify all OIDC env vars are present and well-formed.
 *
 * Browse to http://localhost:3141/auth/login to start the OIDC handshake.
 */
import { PROJECT_ROOT } from '../src/config.js';
import { startDashboard } from '../src/dashboard.js';
import { initDatabase } from '../src/db.js';
import { logger } from '../src/logger.js';
import { checkPendingMigrations } from '../src/migrations.js';
import { initOrchestrator } from '../src/orchestrator.js';

async function main(): Promise<void> {
  logger.info('dashboard-dev: dashboard-only mode (no bot, scheduler, or warroom)');

  checkPendingMigrations(PROJECT_ROOT);

  try {
    initDatabase();
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error({ err }, 'Database initialization failed: %s', msg);
    if (msg.includes('DB_ENCRYPTION_KEY')) {
      logger.error(
        'Fix: add DB_ENCRYPTION_KEY to .env. Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
      );
    }
    process.exit(1);
  }
  logger.info('Database ready');

  // Powers /api/agents listing in the dashboard. Cheap; no bot dep.
  initOrchestrator();

  // botApi=undefined → the lone Telegram-bound endpoint returns 503.
  startDashboard(undefined);

  const shutdown = (): void => {
    logger.info('dashboard-dev: shutting down');
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err: unknown) => {
  logger.error({ err }, 'Fatal error');
  process.exit(1);
});
