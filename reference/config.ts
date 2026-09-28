import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { SqliteStore } from './store.ts';
import { PostgresStore } from '../adapters/postgres.ts';
import type { Store } from './types.ts';
export function configuredStore(): Store {
  if (process.env.DATABASE_URL) return new PostgresStore(process.env.DATABASE_URL);
  const path = process.env.AKAC_DB ?? 'data/akac.sqlite';
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  return new SqliteStore(path);
}
