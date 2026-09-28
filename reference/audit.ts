import { createHash } from 'node:crypto';
import type { Audit, State } from './types.ts';
import { safeNumber } from './validation.ts';

export const GENESIS = '0'.repeat(64);
export function auditHash(entry: Omit<Audit, 'hash'>): string {
  const ordered = Object.fromEntries(Object.entries(entry).sort(([a], [b]) => a.localeCompare(b, 'en')));
  return createHash('sha256').update(JSON.stringify(ordered)).digest('hex');
}
/**
 * Each tenant is an independent stream starting at sequence 1 (or, with
 * `window`, at its first supplied entry). Entries of one tenant must be in order.
 */
export function verifyAudit(entries: Audit[], options: { window?: boolean } = {}): boolean {
  const heads = new Map<string, { sequence: number; hash: string }>();
  return entries.every(entry => {
    const { hash, ...body } = entry;
    const head = heads.get(entry.tenant);
    const sequence = head ? head.sequence + 1 : options.window ? entry.sequence : 1;
    const previous = head ? head.hash : options.window ? entry.previous : GENESIS;
    const valid = safeNumber(entry.sequence) && entry.sequence >= 1 && entry.sequence === sequence
      && entry.previous === previous && auditHash(body) === hash;
    heads.set(entry.tenant, { sequence: entry.sequence, hash }); return valid;
  });
}
/** The 0.1 format: one global chain across all tenants. */
export function verifyLegacyAudit(entries: Audit[]): boolean {
  let previous = GENESIS;
  return entries.every((entry, index) => {
    const { hash, ...body } = entry;
    const valid = entry.sequence === index + 1 && entry.previous === previous && auditHash(body) === hash;
    previous = hash; return valid;
  });
}
/** Appends to the tenant stream. A partial snapshot MUST contain the tenant head (Need.audit). */
export function appendAudit(s: State, fields: Omit<Audit, 'sequence' | 'previous' | 'hash'>): Audit {
  let head: Audit | undefined;
  for (let i = s.audits.length - 1; i >= 0; i--) if (s.audits[i]!.tenant === fields.tenant) { head = s.audits[i]; break; }
  const entry: Omit<Audit, 'hash'> = { ...fields, sequence: (head?.sequence ?? 0) + 1, previous: head?.hash ?? GENESIS };
  const audit = { ...entry, hash: auditHash(entry) };
  s.audits.push(audit); return audit;
}
