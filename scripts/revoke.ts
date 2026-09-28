import { configuredStore } from '../reference/config.ts';
import { Engine } from '../reference/engine.ts';
const [tenant, admin, type, id] = process.argv.slice(2);
if (!tenant || !admin || !id || !['grant', 'knowledge', 'actor'].includes(type ?? '')) throw new Error('Usage: node scripts/revoke.ts TENANT ADMIN grant|knowledge|actor ID');
const store = configuredStore();
try { console.log(await new Engine(store).revoke(tenant, admin, type as 'grant' | 'knowledge' | 'actor', id)); }
finally { await store.close(); }
