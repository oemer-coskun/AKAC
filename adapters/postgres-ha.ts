import pg from 'pg';
import { validId } from '../reference/validation.ts';
import { IDEMPOTENCY_KEY, JOBS, validScope } from '../reference/limits.ts';
import type { IdempotencyClaim, IdempotencyStore, JobLock, RateLimitStore, RateVerdict, StoredResponse } from '../reference/limits.ts';

/**
 * Shared operational state for several gateway instances over one PostgreSQL
 * database (migration 009, ADR-016): rate-limit windows, admin Idempotency-Key
 * records and job locks. Every statement runs in a short transaction that sets
 * `akac.tenant`, so forced row-level security confines it to one tenant. Errors
 * reject and the listeners answer 503 (fail closed).
 */
const HEX64 = /^[a-f0-9]{64}$/;
export type SharedStateOptions = { schema?: string; max?: number };
function pool(connectionString: string, options: SharedStateOptions): pg.Pool {
  if (options.schema !== undefined && !/^[a-z_][a-z0-9_]{0,62}$/.test(options.schema)) throw new Error('Invalid schema name');
  const p = new pg.Pool({ connectionString, max: options.max ?? 4, connectionTimeoutMillis: 3000, statement_timeout: 3000, idle_in_transaction_session_timeout: 10000,
    ...(options.schema ? { options: `-c search_path=${options.schema}` } : {}) });
  p.on('error', () => {});
  return p;
}
async function inTenant<T>(p: pg.Pool, tenant: string, fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  if (!validId(tenant)) throw new Error('Invalid tenant');
  const client = await p.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('akac.tenant', $1, true)", [tenant]);
    const value = await fn(client);
    await client.query('COMMIT');
    return value;
  } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
  finally { client.release(); }
}
/**
 * Two round trips instead of four for the per-request rate limit: the tenant is set for
 * the session of a connection of this private pool (every use sets it first), and the
 * statement runs in autocommit.
 */
async function asTenant<T>(p: pg.Pool, tenant: string, fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  if (!validId(tenant)) throw new Error('Invalid tenant');
  const client = await p.connect();
  let broken = false;
  try {
    await client.query("SELECT set_config('akac.tenant', $1, false)", [tenant]);
    return await fn(client);
  } catch (error) { broken = true; throw error; }
  finally { client.release(broken); }
}
/** Expired rows of one tenant are removed in bounded batches, at most once per `every` ms per tenant and instance. */
class Sweeper {
  private last = new Map<string, number>();
  private table: string; private every: number;
  constructor(table: 'akac_rate_limits' | 'akac_idempotency_keys', every: number) { this.table = table; this.every = every; }
  due(tenant: string): boolean {
    const now = Date.now(), last = this.last.get(tenant) ?? 0;
    if (now - last < this.every) return false;
    if (this.last.size >= 10_000) this.last.clear();
    this.last.set(tenant, now); return true;
  }
  async sweep(client: pg.PoolClient, tenant: string, batch = 500): Promise<number> {
    const r = await client.query(`DELETE FROM ${this.table} WHERE ctid IN (SELECT ctid FROM ${this.table} WHERE tenant = $1 AND expires_at < now() LIMIT $2)`, [tenant, batch]);
    return r.rowCount ?? 0;
  }
}

/**
 * Fixed windows shared by every instance. The window index comes from the database
 * clock (statement_timestamp), so instances with skewed clocks count into the same
 * window. One upsert per request: it resets the count when the window changed.
 */
export class PostgresRateLimits implements RateLimitStore {
  readonly shared = true;
  private pool: pg.Pool;
  private sweeper = new Sweeper('akac_rate_limits', 60_000);
  constructor(connectionString: string, options: SharedStateOptions = {}) { this.pool = pool(connectionString, options); }
  async take(tenant: string, scope: string, key: string, limit: number, windowMs: number, cost = 1): Promise<RateVerdict> {
    if (!validScope(scope) || !HEX64.test(key) || !Number.isSafeInteger(limit) || limit < 1 || !Number.isSafeInteger(windowMs) || windowMs < 1
      || !Number.isSafeInteger(cost) || cost < 0) throw new Error('Invalid rate limit request');
    return asTenant(this.pool, tenant, async client => {
      if (this.sweeper.due(tenant)) await this.sweeper.sweep(client, tenant);
      const r = await client.query(`WITH t AS (SELECT floor(extract(epoch FROM statement_timestamp()) * 1000)::bigint AS ms)
        INSERT INTO akac_rate_limits AS l (tenant, scope, bucket, window_index, count, expires_at)
        SELECT $1, $2, $3, t.ms / $4, $5, to_timestamp(((t.ms / $4 + 1) * $4) / 1000.0) FROM t
        ON CONFLICT (tenant, scope, bucket) DO UPDATE SET
          count = CASE WHEN l.window_index = EXCLUDED.window_index THEN l.count + EXCLUDED.count ELSE EXCLUDED.count END,
          window_index = EXCLUDED.window_index, expires_at = EXCLUDED.expires_at
        RETURNING l.count, (SELECT ((ms / $4 + 1) * $4 - ms) FROM t) AS remaining`, [tenant, scope, key, windowMs, cost]);
      const row = r.rows[0];
      const count = Number(row.count), retryAfter = Math.max(1, Math.ceil(Number(row.remaining) / 1000));
      return count > limit ? { ok: false, status: 429, retryAfter, reason: 'limited' } : { ok: true };
    });
  }
  async close() { await this.pool.end(); }
}

/**
 * Admin Idempotency-Key records shared by every instance. A claim is one
 * INSERT .. ON CONFLICT: exactly one concurrent request wins a key. An in-flight
 * claim holds a short lease (`leaseMs`); after it lapses (the instance died before
 * completing) the key can be claimed again. A completed record lives `ttlMs`.
 */
export class PostgresIdempotency implements IdempotencyStore {
  readonly shared = true;
  private pool: pg.Pool;
  private ttlMs: number; private leaseMs: number;
  private sweeper = new Sweeper('akac_idempotency_keys', 60_000);
  constructor(connectionString: string, options: SharedStateOptions & { ttlMs?: number; leaseMs?: number } = {}) {
    this.ttlMs = options.ttlMs ?? 24 * 3600_000; this.leaseMs = options.leaseMs ?? 60_000;
    if (!Number.isSafeInteger(this.ttlMs) || this.ttlMs < 1000 || !Number.isSafeInteger(this.leaseMs) || this.leaseMs < 1000 || this.leaseMs > this.ttlMs) throw new Error('Invalid idempotency configuration');
    this.pool = pool(connectionString, options);
  }
  private check(owner: string, key: string) { if (!HEX64.test(owner) || !IDEMPOTENCY_KEY.test(key)) throw new Error('Invalid idempotency key'); }
  async claim(tenant: string, owner: string, key: string, fingerprint: string): Promise<IdempotencyClaim> {
    this.check(owner, key);
    if (!HEX64.test(fingerprint)) throw new Error('Invalid fingerprint');
    return inTenant(this.pool, tenant, async client => {
      if (this.sweeper.due(tenant)) await this.sweeper.sweep(client, tenant);
      // A new row, or an expired one (lapsed lease or TTL) taken over; a live row is left untouched.
      const won = await client.query(`INSERT INTO akac_idempotency_keys AS k (tenant, owner, key, fingerprint, status, body, expires_at)
        VALUES ($1, $2, $3, $4, NULL, NULL, now() + make_interval(secs => $5 / 1000.0))
        ON CONFLICT (tenant, owner, key) DO UPDATE SET fingerprint = EXCLUDED.fingerprint, status = NULL, body = NULL,
          created_at = now(), expires_at = EXCLUDED.expires_at
        WHERE k.expires_at <= now() RETURNING 1`, [tenant, owner, key, fingerprint, this.leaseMs]);
      if (won.rowCount === 1) return { state: 'new' };
      const row = (await client.query('SELECT fingerprint, status, body FROM akac_idempotency_keys WHERE tenant = $1 AND owner = $2 AND key = $3',
        [tenant, owner, key])).rows[0];
      if (!row) throw new Error('Idempotency record vanished');
      return { state: 'seen', fingerprint: row.fingerprint, ...(row.status === null ? {} : { response: { status: Number(row.status), ...(row.body === null ? {} : { body: row.body }) } }) };
    });
  }
  async complete(tenant: string, owner: string, key: string, response: StoredResponse): Promise<void> {
    this.check(owner, key);
    if (!Number.isInteger(response?.status) || response.status < 100 || response.status > 599) throw new Error('Invalid response');
    await inTenant(this.pool, tenant, client => client.query(`UPDATE akac_idempotency_keys SET status = $4, body = $5::jsonb,
      expires_at = now() + make_interval(secs => $6 / 1000.0) WHERE tenant = $1 AND owner = $2 AND key = $3 AND status IS NULL`,
      [tenant, owner, key, response.status, response.body === undefined ? null : JSON.stringify(response.body), this.ttlMs]));
  }
  async release(tenant: string, owner: string, key: string): Promise<void> {
    this.check(owner, key);
    await inTenant(this.pool, tenant, client => client.query('DELETE FROM akac_idempotency_keys WHERE tenant = $1 AND owner = $2 AND key = $3 AND status IS NULL', [tenant, owner, key]));
  }
  async close() { await this.pool.end(); }
}

/** Advisory-lock namespace (first key of the two-int form); the migration lock uses (1095450947, 3). */
export const JOB_LOCK_CLASS = 1095450948;
/**
 * Leader-free job serialization: `pg_try_advisory_lock(JOB_LOCK_CLASS, hashtext(job, tenant))`
 * on a dedicated session. A second instance (or CronJob pod) that finds the lock held
 * skips the run instead of queueing. The lock is released when the job ends, and by
 * PostgreSQL when the session ends, so a crashed holder never blocks later runs.
 * Advisory locks are cluster-local: they do not serialize across a failover to a
 * replica that was promoted while the old primary still runs (see docs/HA.md).
 */
export class PostgresJobLock implements JobLock {
  readonly shared = true;
  private pool: pg.Pool;
  constructor(connectionString: string, options: SharedStateOptions = {}) { this.pool = pool(connectionString, { max: 2, ...options }); }
  async run<T>(job: string, tenant: string, fn: () => Promise<T>): Promise<{ ran: true; value: T } | { ran: false }> {
    if (!(JOBS as readonly string[]).includes(job) || !validId(tenant)) throw new Error('Invalid job');
    // Job names never contain '/', so the name is unambiguous (PostgreSQL text cannot carry NUL).
    const name = `${job}/${tenant}`;
    const client = await this.pool.connect();
    let locked = false;
    try {
      locked = (await client.query('SELECT pg_try_advisory_lock($1, hashtext($2)) AS ok', [JOB_LOCK_CLASS, name])).rows[0].ok === true;
      if (!locked) return { ran: false };
      return { ran: true, value: await fn() };
    } finally {
      // An unlock failure leaves the session suspect: destroy it so PostgreSQL drops the lock.
      if (locked) {
        try { await client.query('SELECT pg_advisory_unlock($1, hashtext($2))', [JOB_LOCK_CLASS, name]); client.release(); }
        catch { client.release(true); }
      } else client.release();
    }
  }
  async close() { await this.pool.end(); }
}
