import { DatabaseSync } from 'node:sqlite';
import type { State, Store } from './types.ts';
import { emptyState } from './types.ts';

/** Serializes the complete authorize -> act -> audit transaction in one process. */
export class MemoryStore implements Store {
  private state: State;
  private tail: Promise<void> = Promise.resolve();
  constructor(initial: State = emptyState()) { this.state = structuredClone(initial); }
  async transaction<T>(fn: (state: State) => Promise<T>): Promise<T> {
    let release!: () => void;
    const previous = this.tail; this.tail = new Promise(resolve => { release = resolve; });
    await previous;
    const next = structuredClone(this.state);
    try { const result = await fn(next); this.state = next; return result; }
    finally { release(); }
  }
  async close() { await this.tail; }
}

export class SqliteStore implements Store {
  private db: DatabaseSync;
  private tail: Promise<void> = Promise.resolve();
  constructor(path: string) {
    this.db = new DatabaseSync(path, { timeout: 5000 });
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS akac_state (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)');
    this.db.prepare('INSERT OR IGNORE INTO akac_state(id,body) VALUES(1,?)').run(JSON.stringify(emptyState()));
  }
  async transaction<T>(fn: (state: State) => Promise<T>): Promise<T> {
    let release!: () => void;
    const previous = this.tail; this.tail = new Promise(resolve => { release = resolve; });
    await previous;
    let started = false;
    try {
      this.db.exec('BEGIN IMMEDIATE'); started = true;
      const row = this.db.prepare('SELECT body FROM akac_state WHERE id=1').get() as { body: string };
      const state = JSON.parse(row.body) as State;
      if (state.schema !== 'akac-state/0.1') throw new Error('Unsupported state schema');
      const result = await fn(state);
      this.db.prepare('UPDATE akac_state SET body=? WHERE id=1').run(JSON.stringify(state));
      this.db.exec('COMMIT'); return result;
    } catch (error) { if (started) this.db.exec('ROLLBACK'); throw error; }
    finally { release(); }
  }
  async close() { await this.tail; this.db.close(); }
}
