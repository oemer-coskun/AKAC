import { readFileSync } from 'node:fs';
import { Engine } from './engine.ts';
import { createGateway } from './http.ts';
import type { Credential } from './http.ts';
import { configuredStore } from './config.ts';
import { OpaPolicy } from '../adapters/opa.ts';
import { JwtAuthenticator } from '../adapters/jwt.ts';
import type { JwtConfiguration } from '../adapters/jwt.ts';

const path = process.env.AKAC_CREDENTIALS_FILE;
const jwtPath = process.env.AKAC_JWT_CONFIG_FILE;
if (Boolean(path) === Boolean(jwtPath)) throw new Error('Set exactly one of AKAC_CREDENTIALS_FILE or AKAC_JWT_CONFIG_FILE');
const credentials = path ? JSON.parse(readFileSync(path, 'utf8')) as Credential[] : [];
const authenticator = jwtPath ? new JwtAuthenticator(JSON.parse(readFileSync(jwtPath, 'utf8')) as JwtConfiguration) : undefined;
const store = configuredStore();
const policy = process.env.OPA_URL ? new OpaPolicy(process.env.OPA_URL, process.env.OPA_REVISION) : undefined;
const server = createGateway(new Engine(store, { policy }), credentials, { authenticator });
const host = process.env.HOST ?? '127.0.0.1';
const port = Number(process.env.PORT ?? 8787);
server.listen(port, host, () => console.log(`AKAC draft gateway listening on ${host}:${port}; policy=${policy ? 'OPA + core' : 'core'}`));
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, () => {
  server.close(() => { void store.close().then(() => process.exit(0)); });
});
