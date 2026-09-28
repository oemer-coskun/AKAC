import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { configuredStore } from '../reference/config.ts';
import { importState } from '../reference/store.ts';
import { fixture, bindings } from '../examples/fixture.ts';
const store = configuredStore();
const file = process.env.AKAC_CREDENTIALS_FILE ?? 'data/credentials.json';
const adminFile = process.env.AKAC_ADMIN_CREDENTIALS_FILE ?? 'data/admin-credentials.json';
try {
  if (existsSync(file) || existsSync(adminFile)) throw new Error('Refusing to overwrite an existing credential file');
  const state = fixture();
  // Synthetic administrators, one per standing admin role (a single actor holding several would be a design smell).
  const admins = { 'demo-security-admin': 'security-admin', 'demo-kb-admin': 'kb-admin', 'demo-auditor': 'auditor' } as const;
  for (const [id, role] of Object.entries(admins)) state.actors[id] = { id, tenant: 'acme', kind: 'user', roles: [role], projects: [], clearance: 'restricted', active: true };
  const occupied = await store.transaction('acme', async tx => {
    await tx.load({ actors: Object.keys(state.actors) });
    return Object.keys(tx.state.actors).length > 0;
  });
  if (occupied) throw new Error('Refusing to overwrite a nonempty state');
  await importState(store, state);
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  mkdirSync(dirname(adminFile), { recursive: true, mode: 0o700 });
  writeFileSync(file, JSON.stringify(Object.values(bindings).map(binding => ({ token: randomBytes(32).toString('hex'), binding })), null, 2), { mode: 0o600, flag: 'wx' });
  writeFileSync(adminFile, JSON.stringify(Object.keys(admins).map(admin => ({ token: randomBytes(32).toString('hex'), binding: { tenant: 'acme', admin } })), null, 2), { mode: 0o600, flag: 'wx' });
  console.log(`Seeded synthetic identities; agent credentials written to ${file}, admin credentials to ${adminFile}. Grants expire in one hour.`);
} finally { await store.close(); }
