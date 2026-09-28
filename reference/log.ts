import { randomBytes, randomUUID } from 'node:crypto';

export type Level = 'debug' | 'info' | 'warn' | 'error';
const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };
/** Fields that could carry secrets or protected content are dropped by name, whatever the caller passes. */
const FORBIDDEN = /token|secret|authorization|password|credential|content|query|prompt|cookie|key/i;
export type Fields = Record<string, string | number | boolean | null | undefined>;
export type Logger = { debug(msg: string, f?: Fields): void; info(msg: string, f?: Fields): void; warn(msg: string, f?: Fields): void; error(msg: string, f?: Fields): void };

/** Structured JSON lines. Only bounded scalar fields are written; never request bodies, queries, tokens or documents. */
export function createLogger(options: { level?: Level; write?: (line: string) => void } = {}): Logger {
  const min = ORDER[options.level ?? 'info'];
  const write = options.write ?? ((line: string) => { process.stdout.write(line + '\n'); });
  const log = (level: Level, msg: string, fields: Fields = {}) => {
    if (ORDER[level] < min) return;
    const entry: Record<string, unknown> = { level, time: new Date().toISOString(), msg: String(msg).slice(0, 200) };
    for (const [k, v] of Object.entries(fields)) {
      if ((v !== null && typeof v === 'object') || FORBIDDEN.test(k) || !/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(k) || k in entry) continue;
      entry[k] = typeof v === 'string' ? v.slice(0, 200) : v;
    }
    try { write(JSON.stringify(entry)); } catch { /* logging never affects requests */ }
  };
  return { debug: (m, f) => log('debug', m, f), info: (m, f) => log('info', m, f), warn: (m, f) => log('warn', m, f), error: (m, f) => log('error', m, f) };
}
/** W3C trace-context `traceparent`: reuse a well-formed trace id, otherwise start a new trace. The header never carries authority. */
export function traceIdOf(header: string | undefined): string {
  const m = /^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$/.exec(header ?? '');
  return m && m[1] !== '0'.repeat(32) && m[2] !== '0'.repeat(16) ? m[1]! : randomBytes(16).toString('hex');
}
export const newRequestId = () => randomUUID();
