import { readFileSync } from 'node:fs';
import { Engine } from './engine.ts';
import { createGateway } from './http.ts';
import type { Credential } from './http.ts';
import { configuredStore } from './config.ts';
import { OpaPolicy } from '../adapters/opa.ts';

const path = process.env.AKAC_CREDENTIALS_FILE;
if (!path) throw new Error('AKAC_CREDENTIALS_FILE is required. Run npm run seed for a local synthetic demo.');
const credentials = JSON.parse(readFileSync(path, 'utf8')) as Credential[];
const store = configuredStore();
const policy = process.env.OPA_URL ? new OpaPolicy(process.env.OPA_URL) : undefined;
const server = createGateway(new Engine(store, { policy }), credentials);
const host = process.env.HOST ?? '127.0.0.1';
const port = Number(process.env.PORT ?? 8787);
server.listen(port, host, () => console.log(`AKAC draft gateway listening on ${host}:${port}; policy=${policy ? 'OPA + core' : 'core'}`));
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, () => {
  server.close(() => { void store.close().then(() => process.exit(0)); });
});
