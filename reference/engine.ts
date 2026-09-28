import { createHash, randomUUID } from 'node:crypto';
import { canDelegate, decide, visible } from './policy.ts';
import { LEVELS } from './types.ts';
import type { Action, Audit, Binding, Context, Grant, Knowledge, PolicyHook, Ref, State, Store } from './types.ts';

export type Result<T> = { ok: true; value: T } | { ok: false; code: 'NOT_AUTHORIZED' };
export type Projection = { context: string; expiresAt: number; documents: { id: string; version: number; content: string }[] };
const good = <T>(value: T): Result<T> => ({ ok: true, value });
const bad = <T>(): Result<T> => ({ ok: false, code: 'NOT_AUTHORIZED' });
const same = (a: Binding, b: Binding) => a.tenant === b.tenant && a.subject === b.subject && a.agent === b.agent && a.grant === b.grant;
export const validId = (s: unknown): s is string => typeof s === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(s) && !['constructor', 'prototype', '__proto__'].includes(s);
export function auditHash(entry: Omit<Audit, 'hash'>): string {
  const ordered = Object.fromEntries(Object.entries(entry).sort(([a], [b]) => a.localeCompare(b, 'en')));
  return createHash('sha256').update(JSON.stringify(ordered)).digest('hex');
}
export function verifyAudit(entries: Audit[]): boolean {
  let previous = '0'.repeat(64);
  return entries.every((entry, index) => {
    const { hash, ...body } = entry;
    const valid = entry.sequence === index + 1 && entry.previous === previous && auditHash(body) === hash;
    previous = hash; return valid;
  });
}

export class Engine {
  private store: Store;
  private hook?: PolicyHook;
  private clock: () => number;
  constructor(store: Store, options: { policy?: PolicyHook; clock?: () => number } = {}) {
    this.store = store; this.hook = options.policy; this.clock = options.clock ?? Date.now;
  }
  private audit(s: State, b: Binding, operation: string, allowed: boolean, reason: string) {
    const entry: Omit<Audit, 'hash'> = { sequence: s.audits.length + 1, time: this.clock(), tenant: b.tenant,
      actor: b.subject, operation, decision: allowed ? 'allow' : 'deny', reason,
      policyVersion: s.policyVersion, epoch: s.epoch, previous: s.audits.at(-1)?.hash ?? '0'.repeat(64) };
    s.audits.push({ ...entry, hash: auditHash(entry) });
  }
  private async authorized(s: State, b: Binding, resource: string, action: Action, purpose: string): Promise<boolean> {
    if (!validId(resource) || !Object.values(b).every(validId)) return false;
    if (decide(s, { binding: b, resource, action, purpose, now: this.clock() }).effect !== 'allow') return false;
    if (!this.hook) return true;
    try { return await this.hook.check({ tenant: b.tenant, action, purpose, classification: s.knowledge[resource]!.classification }); }
    catch { return false; }
  }
  /** Capture every read in this credential-bound run. A new run needs a new grant. */
  private async projection(s: State, b: Binding, ids: string[], purpose: string): Promise<Result<Projection>> {
    if (!ids.length || ids.length > 64) return bad();
    const existing = Object.values(s.contexts).filter(c => same(c, b));
    if (existing.some(c => !c.active || c.epoch !== s.epoch || c.policyVersion !== s.policyVersion || c.expiresAt <= this.clock())) return bad();
    const all = new Set(ids);
    for (const c of existing) for (const ref of c.sources) {
      if (s.knowledge[ref.id]?.version !== ref.version) return bad();
      all.add(ref.id);
    }
    if (all.size > 128) return bad();
    for (const id of all) if (!await this.authorized(s, b, id, 'read', purpose)) return bad();
    const grant = s.grants[b.grant]!;
    const id = randomUUID();
    const context: Context = { ...b, id, purpose, sources: [...all].sort().map(key => ({ id: key, version: s.knowledge[key]!.version })),
      expiresAt: Math.min(grant.expiresAt, this.clock() + 300_000, ...existing.map(c => c.expiresAt)),
      epoch: s.epoch, policyVersion: s.policyVersion, active: true };
    // OPA evaluation may have taken time; enforce freshness at the disclosure boundary.
    if (this.clock() >= context.expiresAt) return bad();
    for (const key of all) if (decide(s, { binding: b, resource: key, action: 'read', purpose, now: this.clock() }).effect !== 'allow') return bad();
    s.contexts[id] = context;
    return good({ context: id, expiresAt: context.expiresAt,
      documents: [...new Set(ids)].map(key => { const r = s.knowledge[key]!; return { id: r.id, version: r.version, content: r.content }; }) });
  }
  async openContext(b: Binding, ids: string[], purpose: string): Promise<Result<Projection>> {
    return this.store.transaction(async s => {
      const result = await this.projection(s, b, ids, purpose);
      this.audit(s, b, 'read', result.ok, result.ok ? 'AUTHORIZED' : 'DENIED'); return result;
    });
  }
  async retrieve(b: Binding, query: string, purpose: string, limit = 5): Promise<Result<Projection>> {
    return this.store.transaction(async s => {
      if (!query.trim() || query.length > 4096 || !Number.isInteger(limit) || limit < 1 || limit > 20) return bad();
      const eligible: Knowledge[] = [];
      for (const r of Object.values(s.knowledge)) if (await this.authorized(s, b, r.id, 'read', purpose)) eligible.push(r);
      // No global document statistics. Unauthorized records never enter scoring.
      const terms = [...new Set(query.toLocaleLowerCase('en').split(/\s+/).filter(Boolean))];
      const ids = eligible.map(r => ({ r, score: terms.reduce((n, t) => n + Number(r.content.toLocaleLowerCase('en').includes(t)), 0) }))
        .filter(x => x.score > 0).sort((a, b) => b.score - a.score || a.r.id.localeCompare(b.r.id)).slice(0, limit).map(x => x.r.id);
      // An empty search deliberately does not distinguish no match from no authority.
      const result = await this.projection(s, b, ids, purpose);
      this.audit(s, b, 'retrieve', result.ok, result.ok ? 'AUTHORIZED' : 'DENIED'); return result;
    });
  }
  private async contextSources(s: State, b: Binding, contextId: string, action: Action): Promise<Ref[] | null> {
    if (!validId(contextId)) return null;
    const selected = s.contexts[contextId];
    if (!selected || !same(selected, b)) return null;
    const refs = new Map<string, Ref>();
    for (const c of Object.values(s.contexts).filter(c => same(c, b))) {
      if (!c.active || c.epoch !== s.epoch || c.policyVersion !== s.policyVersion || c.expiresAt <= this.clock() || c.purpose !== selected.purpose) return null;
      for (const ref of c.sources) {
        if (s.knowledge[ref.id]?.version !== ref.version || !await this.authorized(s, b, ref.id, action, selected.purpose)) return null;
        refs.set(ref.id, ref);
      }
    }
    if (!refs.size || selected.expiresAt <= this.clock()) return null;
    for (const ref of refs.values()) if (decide(s, { binding: b, resource: ref.id, action, purpose: selected.purpose, now: this.clock() }).effect !== 'allow') return null;
    return [...refs.values()].sort((a, b) => a.id.localeCompare(b.id));
  }
  async derive(b: Binding, contextId: string, content: string, kind: 'memory' | 'artifact' = 'artifact'): Promise<Result<{ id: string; classification: string }>> {
    return this.store.transaction(async s => {
      if (!content || content.length > 100_000 || !['memory', 'artifact'].includes(kind)) return bad();
      const refs = await this.contextSources(s, b, contextId, 'derive');
      if (!refs || (kind === 'memory' && !await this.contextSources(s, b, contextId, 'write_memory'))) {
        this.audit(s, b, 'derive', false, 'DENIED'); return bad();
      }
      const sources = refs.map(r => s.knowledge[r.id]!);
      const id = randomUUID();
      const classification = LEVELS[Math.max(...sources.map(r => LEVELS.indexOf(r.classification)))]!;
      s.knowledge[id] = { id, tenant: b.tenant, version: 1, kind, content, classification,
        projects: [...new Set(sources.flatMap(r => r.projects))],
        // This local ACL cannot override the transitive source ACL intersection.
        readerRoles: [...new Set(sources.flatMap(r => r.readerRoles))],
        readers: [...new Set(sources.flatMap(r => r.readers))], sources: refs, active: true };
      this.audit(s, b, 'derive', true, 'PROTECTED_DERIVATION'); return good({ id, classification });
    });
  }
  /** Release a generated response to a named recipient. Actual transport is an integration responsibility. */
  async release(b: Binding, contextId: string, recipientId: string, content: string, action: 'share' | 'export' = 'share'): Promise<Result<{ recipient: string; content: string }>> {
    return this.store.transaction(async s => {
      const recipient = validId(recipientId) ? s.actors[recipientId] : undefined;
      const refs = await this.contextSources(s, b, contextId, action);
      if (!content || content.length > 100_000 || !recipient || recipient.tenant !== b.tenant || !refs
        || refs.some(ref => !visible(s, recipient, s.knowledge[ref.id]!))) {
        this.audit(s, b, action, false, 'DENIED'); return bad();
      }
      this.audit(s, b, action, true, 'AUTHORIZED_RECIPIENT'); return good({ recipient: recipientId, content });
    });
  }
  async delegate(b: Binding, child: Grant): Promise<Result<{ id: string }>> {
    return this.store.transaction(async s => {
      const parent = s.grants[b.grant];
      const user = s.actors[b.subject], agent = s.actors[b.agent];
      if (!validId(child.id) || Object.hasOwn(s.grants, child.id) || !parent || parent.subject !== b.subject
        || parent.agent !== b.agent || parent.tenant !== b.tenant || !user?.active || !agent?.active
        || !canDelegate(s, parent, child, this.clock())) {
        this.audit(s, b, 'delegate', false, 'DENIED'); return bad();
      }
      s.grants[child.id] = structuredClone(child);
      this.audit(s, b, 'delegate', true, 'ATTENUATED'); return good({ id: child.id });
    });
  }
  /** Privileged control-plane operation; NOT exposed through the agent API. */
  async revoke(adminId: string, type: 'grant' | 'knowledge' | 'actor', id: string): Promise<Result<{ epoch: number }>> {
    return this.store.transaction(async s => {
      const admin = validId(adminId) ? s.actors[adminId] : undefined;
      const collection = type === 'grant' ? s.grants : type === 'knowledge' ? s.knowledge : s.actors;
      const target = validId(id) ? collection[id] : undefined;
      if (!admin?.active || admin.kind !== 'user' || !admin.roles.includes('security-admin') || !target || target.tenant !== admin.tenant) return bad();
      target.active = false; s.epoch++;
      for (const c of Object.values(s.contexts)) c.active = false;
      this.audit(s, { tenant: admin.tenant, subject: admin.id, agent: 'control-plane', grant: 'control-plane' }, 'revoke', true, 'EPOCH_ADVANCED');
      return good({ epoch: s.epoch });
    });
  }
}
