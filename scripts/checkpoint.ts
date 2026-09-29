import { readFileSync, writeFileSync } from 'node:fs';
import { configuredStore } from '../reference/config.ts';
import { signCheckpointV2 } from '../reference/checkpoint.ts';
import { treeHead } from '../reference/evidence.ts';
import type { Audit } from '../reference/types.ts';
const [privateKeyFile, tenant, keyId, output] = process.argv.slice(2);
if (!privateKeyFile || !tenant || !keyId || !output) throw new Error('Usage: node scripts/checkpoint.ts PRIVATE_KEY_FILE TENANT KEY_ID OUTPUT');
const store = configuredStore();
try {
  // Each tenant is its own audit stream; the checkpoint stream identifier is the tenant.
  // The whole stream is read in pages, its hash chain verified and the RFC 9162 root
  // recomputed from the entries themselves, so stored Merkle nodes are not trusted.
  const entries: Audit[] = [];
  for (let after = 0; ;) {
    const page = await store.auditLog(tenant, after, 10_000);
    entries.push(...page);
    if (page.length < 10_000) break;
    after = page.at(-1)!.sequence;
  }
  const checkpoint = signCheckpointV2(entries, readFileSync(privateKeyFile, 'utf8'), tenant, keyId);
  // Cross-check the store's incremental tree when the stream did not grow meanwhile.
  const head = await treeHead(store, tenant);
  if (head.treeSize === checkpoint.treeSize && head.rootHash !== checkpoint.rootHash) throw new Error('Stored audit tree disagrees with the audit entries');
  writeFileSync(output, JSON.stringify(checkpoint, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log(`Checkpoint (akac-audit-checkpoint/2, treeSize ${checkpoint.treeSize}) written. Anchor it in independently protected storage.`);
} finally { await store.close(); }
