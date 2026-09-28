import pg from 'pg';
import type { State, Store } from '../reference/types.ts';
import { emptyState } from '../reference/types.ts';

/** One locked state row deliberately favors correctness over throughput in v0.1. */
export class PostgresStore implements Store {
  private pool: pg.Pool;
  private ready: Promise<void>;
  constructor(connectionString: string) {
    this.pool = new pg.Pool({ connectionString, max: 5, connectionTimeoutMillis: 5000,
      statement_timeout: 10000, idle_in_transaction_session_timeout: 15000 });
    const pool = this.pool;
    this.ready = (async () => {
      await pool.query('CREATE TABLE IF NOT EXISTS akac_state (id INTEGER PRIMARY KEY CHECK(id=1), body JSONB NOT NULL)');
      await pool.query('INSERT INTO akac_state(id,body) VALUES(1,$1) ON CONFLICT DO NOTHING', [JSON.stringify(emptyState())]);
    })();
  }
  async transaction<T>(fn: (state: State) => Promise<T>): Promise<T> {
    await this.ready;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query('SELECT body FROM akac_state WHERE id=1 FOR UPDATE');
      const state = result.rows[0]?.body as State;
      if (state?.schema !== 'akac-state/0.1') throw new Error('Unsupported state schema');
      const value = await fn(state);
      await client.query('UPDATE akac_state SET body=$1 WHERE id=1', [JSON.stringify(state)]);
      await client.query('COMMIT'); return value;
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }
  async close() { await this.ready; await this.pool.end(); }
}
