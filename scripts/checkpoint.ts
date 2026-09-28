import { readFileSync, writeFileSync } from 'node:fs';
import { configuredStore } from '../reference/config.ts';
import { signCheckpoint } from '../reference/checkpoint.ts';
const [privateKeyFile, stream, keyId, output] = process.argv.slice(2);
if (!privateKeyFile || !stream || !keyId || !output) throw new Error('Usage: node scripts/checkpoint.ts PRIVATE_KEY_FILE STREAM_ID KEY_ID OUTPUT');
const store = configuredStore();
try {
  const entries = await store.transaction(async state => structuredClone(state.audits));
  const checkpoint = signCheckpoint(entries, readFileSync(privateKeyFile, 'utf8'), stream, keyId);
  writeFileSync(output, JSON.stringify(checkpoint, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log('Checkpoint written. Anchor it in independently protected storage.');
} finally { await store.close(); }
