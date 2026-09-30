import { migrate } from '../adapters/postgres.ts';
import { ConfigError, requireConnectionUrl } from '../reference/config.ts';
// Runs pending PostgreSQL migrations as the schema owner, then exits. Intended for a
// release job (Compose service) so the gateway role needs no DDL rights.
let url: string | undefined;
try { url = requireConnectionUrl(process.env, 'AKAC_MIGRATION_DATABASE_URL'); } catch (error) {
  if (error instanceof ConfigError) { for (const p of error.problems) console.error(`configuration error: ${p}`); process.exit(2); }
  throw error;
}
if (!url) throw new Error('Set AKAC_MIGRATION_DATABASE_URL (and AKAC_MIGRATION_DATABASE_PASSWORD_FILE) to the schema owner connection');
const applied = await migrate(url);
console.log(JSON.stringify({ level: 'info', time: new Date().toISOString(), msg: 'migrations complete', applied }));
