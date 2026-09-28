import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { configuredStore } from '../reference/config.ts';
import { fixture, bindings } from '../examples/fixture.ts';
const store = configuredStore();
const file = process.env.AKAC_CREDENTIALS_FILE ?? 'data/credentials.json';
try {
  if (existsSync(file)) throw new Error('Refusing to overwrite an existing credential file');
  await store.transaction(async state => {
    if (Object.keys(state.actors).length) throw new Error('Refusing to overwrite a nonempty state');
    Object.assign(state, fixture());
  });
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, JSON.stringify(Object.values(bindings).map(binding => ({ token: randomBytes(32).toString('hex'), binding })), null, 2), { mode: 0o600, flag: 'wx' });
  console.log(`Seeded synthetic identities; credentials written to ${file}. Grants expire in one hour.`);
} finally { await store.close(); }
