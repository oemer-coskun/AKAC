import type { PolicyHook } from '../reference/types.ts';

/** OPA can only narrow the deterministic safety boundary, never bypass it. */
export class OpaPolicy implements PolicyHook {
  private endpoint: string;
  constructor(endpoint: string) {
    const url = new URL(endpoint);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('Invalid OPA URL');
    this.endpoint = endpoint;
  }
  async check(input: Parameters<PolicyHook['check']>[0]): Promise<boolean> {
    try {
      const response = await fetch(this.endpoint, { method: 'POST', redirect: 'error',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ input }), signal: AbortSignal.timeout(1500) });
      if (!response.ok) return false;
      const body = await response.text();
      if (body.length > 16384) return false;
      const result = JSON.parse(body) as { result?: unknown };
      return result.result === true;
    } catch { return false; }
  }
}
