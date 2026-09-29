import pg from 'pg';
import type { DpopReplayCache } from './dpop.ts';

/**
 * Shared DPoP replay cache (migration 007): all instances that use the same database reject a replayed
 * proof. An expired identifier may be reused; expired rows are deleted opportunistically. Errors reject, so
 * the gateway fails closed (503) when the database cannot decide.
 */
export class PostgresReplayCache implements DpopReplayCache {
  private pool: pg.Pool;
  private timer: NodeJS.Timeout;
  constructor(connectionString: string, options: { schema?: string; max?: number } = {}) {
    if (options.schema !== undefined && !/^[a-z_][a-z0-9_]{0,62}$/.test(options.schema)) throw new Error('Invalid schema name');
    this.pool = new pg.Pool({ connectionString, max: options.max ?? 4, connectionTimeoutMillis: 3000, statement_timeout: 3000,
      ...(options.schema ? { options: `-c search_path=${options.schema}` } : {}) });
    this.pool.on('error', () => {});
    this.timer = setInterval(() => { void this.pool.query('DELETE FROM akac_dpop_replay WHERE expires_at < now()').catch(() => {}); }, 60_000);
    this.timer.unref();
  }
  async consume(jti: string, jkt: string, expiresAt: number): Promise<boolean> {
    const r = await this.pool.query(
      `INSERT INTO akac_dpop_replay (jti, jkt, expires_at) VALUES ($1, $2, to_timestamp($3))
       ON CONFLICT (jti, jkt) DO UPDATE SET expires_at = EXCLUDED.expires_at WHERE akac_dpop_replay.expires_at <= now() RETURNING 1`,
      [jti, jkt, expiresAt]);
    return r.rowCount === 1;
  }
  async close() { clearInterval(this.timer); await this.pool.end(); }
}
