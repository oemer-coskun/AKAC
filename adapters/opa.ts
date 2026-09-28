import type { PolicyHook } from '../reference/types.ts';

/** OPA can only narrow the deterministic safety boundary, never bypass it. */
export class OpaPolicy implements PolicyHook {
  private endpoint: string;
  readonly revision: string;
  constructor(endpoint: string, expectedRevision = 'akac-company/0.2') {
    const url = new URL(endpoint);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('Invalid OPA URL');
    this.endpoint = endpoint;
    if (!expectedRevision || expectedRevision.length > 128) throw new Error('Invalid OPA revision');
    this.revision = expectedRevision;
  }
  private async evaluate(input: Parameters<PolicyHook['check']>[0]): Promise<{ allow: boolean; revision: string } | null> {
    try {
      const response = await fetch(this.endpoint, { method: 'POST', redirect: 'error',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ input }), signal: AbortSignal.timeout(1500) });
      if (!response.ok || !response.body) { await response.body?.cancel(); return null; }
      const reader = response.body.getReader(), parts: Uint8Array[] = []; let size = 0;
      while (true) {
        const { done, value } = await reader.read(); if (done) break;
        size += value.length;
        if (size > 16384) { await reader.cancel(); return null; } parts.push(value);
      }
      const envelope = JSON.parse(Buffer.concat(parts).toString('utf8')) as { result?: { allow?: unknown; revision?: unknown } };
      const result = envelope.result;
      if (!result || typeof result.allow !== 'boolean' || result.revision !== this.revision
        || Object.keys(result).some(k => !['allow', 'revision'].includes(k))) return null;
      return { allow: result.allow, revision: result.revision };
    } catch { return null; }
  }
  async check(input: Parameters<PolicyHook['check']>[0]): Promise<boolean> {
    return (await this.evaluate(input))?.allow === true;
  }
  async ready(): Promise<boolean> {
    return await this.evaluate({ tenant: 'health-probe', action: 'read', purpose: 'health-probe', classification: 'public' }) !== null;
  }
}
