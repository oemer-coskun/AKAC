import { requireConnectionUrl } from '../reference/config.ts';
import { MemoryJobLock } from '../reference/limits.ts';
import type { JobLock } from '../reference/limits.ts';
import { PostgresJobLock } from '../adapters/postgres-ha.ts';
/**
 * The job lock of the maintenance scripts (ADR-016): a PostgreSQL advisory lock on
 * DATABASE_URL, so gateway instances and CronJob pods never run the same job for the
 * same tenant at once. Without DATABASE_URL (SQLite, single node) a process-local lock.
 */
export function jobLock(env: Record<string, string | undefined> = process.env): JobLock {
  const url = requireConnectionUrl(env, 'DATABASE_URL');
  return url ? new PostgresJobLock(url) : new MemoryJobLock();
}
