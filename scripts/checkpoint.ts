import { readFileSync, writeFileSync } from 'node:fs';
import { configuredStore } from '../reference/config.ts';
import { signCheckpoint } from '../reference/checkpoint.ts';
const [privateKeyFile, tenant, keyId, output] = process.argv.slice(2);
if (!privateKeyFile || !tenant || !keyId || !output) throw new Error('Usage: node scripts/checkpoint.ts PRIVATE_KEY_FILE TENANT KEY_ID OUTPUT');
const store = configuredStore();
try {
  // Each tenant is its own audit stream; the checkpoint stream identifier is the tenant.
  const entries = await store.auditLog(tenant);
  const checkpoint = signCheckpoint(entries, readFileSync(privateKeyFile, 'utf8'), tenant, keyId);
  writeFileSync(output, JSON.stringify(checkpoint, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log('Checkpoint written. Anchor it in independently protected storage.');
} finally { await store.close(); }
