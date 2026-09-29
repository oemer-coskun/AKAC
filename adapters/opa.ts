import type { PolicyHook, PolicyVerdict } from '../reference/types.ts';

type Input = Parameters<PolicyHook['check']>[0];
/**
 * OPA can only narrow the deterministic safety boundary, never bypass it.
 *
 * The decision document is exactly `{allow, revision}` or, since 0.4,
 * `{allow, revision, obligations}` with `obligations` an array. Any other member,
 * a non-boolean `allow`, a revision other than the pinned one, or a non-array
 * `obligations` makes the response unusable (POLICY_UNAVAILABLE). The engine
 * validates each obligation strictly: an unknown or malformed obligation denies
 * with UNSUPPORTED_OBLIGATION.
 */
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
  private async evaluate(input: Input): Promise<{ allow: boolean; revision: string; obligations?: unknown[] } | null> {
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
      const envelope = JSON.parse(Buffer.concat(parts).toString('utf8')) as { result?: { allow?: unknown; revision?: unknown; obligations?: unknown } };
      const result = envelope.result;
      if (!result || typeof result !== 'object' || Array.isArray(result) || typeof result.allow !== 'boolean' || result.revision !== this.revision
        || Object.keys(result).some(k => !['allow', 'revision', 'obligations'].includes(k))
        || (Object.hasOwn(result, 'obligations') && !Array.isArray(result.obligations))) return null;
      return { allow: result.allow, revision: result.revision, ...(Array.isArray(result.obligations) ? { obligations: result.obligations } : {}) };
    } catch { return null; }
  }
  /** Structured verdict for the engine. Unavailable or malformed responses throw (POLICY_UNAVAILABLE). */
  async verdict(input: Input): Promise<PolicyVerdict> {
    const result = await this.evaluate(input);
    if (!result) throw new Error('OPA decision unavailable');
    return { allow: result.allow, ...(result.obligations ? { obligations: result.obligations } : {}) };
  }
  /**
   * Boolean view for callers that cannot enforce obligations: an allow that carries
   * any obligation is reported as false (such a caller must treat it as a deny).
   */
  async check(input: Input): Promise<boolean> {
    const result = await this.evaluate(input);
    return result?.allow === true && !result.obligations?.length;
  }
  async ready(): Promise<boolean> {
    return await this.evaluate({ tenant: 'health-probe', action: 'read', purpose: 'health-probe', classification: 'public' }) !== null;
  }
}
