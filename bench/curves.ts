import { emptyState } from '../reference/types.ts';
import type { Knowledge, State } from '../reference/types.ts';
import { decide, effectiveRoles, LIMITS, transitiveClassification } from '../reference/policy.ts';
import { micro } from './stats.ts';

/**
 * Cost curves of the documented bounds (reference/policy.ts LIMITS), measured on
 * the pure decision function over an in-memory snapshot: role closure size and
 * depth, container chain depth, derivation DAG size and path length. Each curve
 * runs one step past its bound to show the fail-closed point: beyond the bound the
 * decision is a deferred denial (INVALID_CONTEXT) or a KNOWLEDGE_BOUNDARY denial,
 * never an allow over partial data.
 */
export type Point = { parameter: number; p50us: number; p99us: number; effect: string; code: string };
export type Curve = { name: string; parameter: string; bound: number; boundName: string; points: Point[] };

const T = 'c', NOW = 1_800_000_000_000;
function base(): State {
  const s = emptyState();
  s.actors.u = { id: 'u', tenant: T, kind: 'user', roles: ['r0'], projects: [], clearance: 'restricted', active: true };
  s.actors.a = { id: 'a', tenant: T, kind: 'agent', roles: ['r0'], projects: [], clearance: 'restricted', active: true };
  s.grants.g = { id: 'g', tenant: T, subject: 'u', agent: 'a', actions: ['read'], resources: ['*'], purposes: ['work'], notBefore: NOW - 1000, expiresAt: NOW + 1e9, active: true };
  return s;
}
const doc = (id: string, extra: Partial<Knowledge> = {}): Knowledge => ({ id, tenant: T, version: 1, kind: 'document', origin: 'human', content: 'x',
  classification: 'internal', projects: [], readerRoles: ['r0'], readers: [], sources: [], active: true, ...extra });
const run = (s: State, repeat: number) => micro(() => decide(s, { binding: { tenant: T, subject: 'u', agent: 'a', grant: 'g' }, resource: 'k', action: 'read', purpose: 'work', now: NOW }), repeat);
const point = (parameter: number, m: ReturnType<typeof micro>): Point => {
  const d = m.result as { effect: string; code: string };
  return { parameter, p50us: m.p50us, p99us: m.p99us, effect: d.effect, code: d.code };
};
const steps = (bound: number, extra: number[] = []) => [...new Set([1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, ...extra].filter(x => x < bound)), bound, bound + 1].sort((a, b) => a - b);

export function curves(repeat = 200): Curve[] {
  const out: Curve[] = [];
  // 1. Role hierarchy depth: r0 -> r1 -> ... -> r(d-1); the document admits the most junior role.
  out.push({ name: 'Role hierarchy depth', parameter: 'depth (roles on the longest path)', bound: LIMITS.roleDepth, boundName: 'LIMITS.roleDepth', points: steps(LIMITS.roleDepth, [12]).map(d => {
    const s = base();
    for (let i = 0; i < d; i++) s.roles[`r${i}`] = { id: `r${i}`, tenant: T, inherits: i + 1 < d ? [`r${i + 1}`] : [], active: true };
    s.knowledge.k = doc('k', { readerRoles: [`r${d - 1}`] });
    return point(d, run(s, repeat));
  }) });
  // 2. Role closure size: r0 inherits r1..r(n-1) (flat fan-out, depth 2).
  out.push({ name: 'Role closure size', parameter: 'roles in the closure', bound: LIMITS.roles, boundName: 'LIMITS.roles', points: steps(LIMITS.roles, [48]).map(n => {
    const s = base();
    s.roles.r0 = { id: 'r0', tenant: T, inherits: Array.from({ length: n - 1 }, (_, i) => `r${i + 1}`), active: true };
    for (let i = 1; i < n; i++) s.roles[`r${i}`] = { id: `r${i}`, tenant: T, inherits: [], active: true };
    s.knowledge.k = doc('k', { readerRoles: [`r${n - 1}`] });
    const m = run(s, repeat), closure = effectiveRoles(s, s.actors.u!);
    const p = point(n, m);
    return closure ? p : { ...p, code: `${p.code} (closure not established)` };
  }) });
  // 3. Container chain depth: knowledge base plus folders; the document sits in the deepest folder.
  out.push({ name: 'Container chain depth', parameter: 'containers above the document', bound: LIMITS.containerDepth, boundName: 'LIMITS.containerDepth', points: steps(LIMITS.containerDepth, [24]).map(d => {
    const s = base();
    for (let i = 0; i < d; i++) s.containers[`c${i}`] = { id: `c${i}`, tenant: T, kind: i ? 'folder' : 'knowledge-base', ...(i ? { parent: `c${i - 1}` } : {}),
      classification: 'internal', readerRoles: ['r0'], readers: [], projects: [], active: true };
    s.knowledge.k = doc('k', { container: `c${d - 1}` });
    return point(d, run(s, repeat));
  }) });
  // 4. Derivation path length: k -> n1 -> ... -> n(p-1) (a chain of p records).
  out.push({ name: 'Derivation path length', parameter: 'records on the longest derivation path', bound: LIMITS.path, boundName: 'LIMITS.path', points: steps(LIMITS.path, [16, 96]).map(p => {
    const s = base();
    for (let i = p - 1; i >= 1; i--) s.knowledge[`n${i}`] = doc(`n${i}`, { kind: 'artifact', origin: 'model', sources: i + 1 < p ? [{ id: `n${i + 1}`, version: 1 }] : [] });
    s.knowledge.k = doc('k', { kind: 'artifact', origin: 'model', sources: p > 1 ? [{ id: 'n1', version: 1 }] : [] });
    const m = run(s, Math.max(20, Math.floor(repeat / 4)));
    const t = micro(() => transitiveClassification(s, s.knowledge.k!), Math.max(20, Math.floor(repeat / 4)));
    return { ...point(p, m), code: `${(m.result as { code: string }).code}; transitiveClassification=${t.result ?? 'null'} (${t.p50us} us)` };
  }) });
  // 5. Derivation DAG size: k derives from n-1 source documents (one level, n nodes, n-1 edges).
  out.push({ name: 'Derivation DAG size', parameter: 'records in the source graph', bound: LIMITS.nodes, boundName: 'LIMITS.nodes', points: steps(LIMITS.nodes).map(n => {
    const s = base();
    for (let i = 1; i < n; i++) s.knowledge[`n${i}`] = doc(`n${i}`);
    s.knowledge.k = doc('k', { kind: 'artifact', origin: 'model', sources: Array.from({ length: n - 1 }, (_, i) => ({ id: `n${i + 1}`, version: 1 })) });
    const m = run(s, Math.max(20, Math.floor(repeat / 4)));
    const t = micro(() => transitiveClassification(s, s.knowledge.k!), Math.max(20, Math.floor(repeat / 4)));
    return { ...point(n, m), code: `${(m.result as { code: string }).code}; transitiveClassification=${t.result ?? 'null'} (${t.p50us} us)` };
  }) });
  return out;
}
