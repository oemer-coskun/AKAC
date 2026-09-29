/**
 * Four-way outcome of a vector (0.4, red-team practice). A vector states whether the
 * request MUST be allowed or MUST be denied; the observed effect gives:
 *   SUCCESS         expected allow, allowed
 *   SAFE_BLOCK      expected deny, denied
 *   FAILURE         expected allow, denied (or a wrong code, or a harness error): availability/correctness defect
 *   UNSAFE_SUCCESS  expected deny, allowed: a leak. Never acceptable.
 */
export const OUTCOMES = ['SUCCESS', 'SAFE_BLOCK', 'FAILURE', 'UNSAFE_SUCCESS'] as const;
export type Outcome = typeof OUTCOMES[number];
export type Row = { id: string; kind?: string; expected: unknown; actual: unknown; pass: boolean; outcome: Outcome; tags?: string[]; code?: string };
export const classify = (expectAllow: boolean, allowed: boolean): Outcome =>
  expectAllow ? (allowed ? 'SUCCESS' : 'FAILURE') : (allowed ? 'UNSAFE_SUCCESS' : 'SAFE_BLOCK');
/** Effect-level outcome, downgraded to FAILURE when the effect was right but another expectation (such as the code) was not. */
export function outcomeOf(expectAllow: boolean, allowed: boolean, pass = true): Outcome {
  const o = classify(expectAllow, allowed);
  return !pass && (o === 'SUCCESS' || o === 'SAFE_BLOCK') ? 'FAILURE' : o;
}
/**
 * Vectors that exercise the tenant boundary: only an explicit `cross-tenant` tag counts. An id
 * that merely names a tenant (for example an own-tenant control) never satisfies the R105 gate.
 */
export const isCrossTenant = (r: { tags?: string[] }) => Array.isArray(r.tags) && r.tags.includes('cross-tenant');
export function summarize(rows: Row[]) {
  const counts = { SUCCESS: 0, SAFE_BLOCK: 0, FAILURE: 0, UNSAFE_SUCCESS: 0 } as Record<Outcome, number>;
  for (const r of rows) counts[r.outcome]++;
  const tenant = rows.filter(isCrossTenant);
  const gates = {
    unsafe_success_zero: counts.UNSAFE_SUCCESS === 0,
    failure_zero: counts.FAILURE === 0,
    cross_tenant_vectors: tenant.length,
    cross_tenant_leaks_zero: tenant.length > 0 && tenant.every(r => r.outcome !== 'UNSAFE_SUCCESS'),
  };
  return { total: rows.length, ...counts, cross_tenant: { vectors: tenant.length, leaks: tenant.filter(r => r.outcome === 'UNSAFE_SUCCESS').length },
    gates: { ...gates, pass: gates.unsafe_success_zero && gates.failure_zero && gates.cross_tenant_leaks_zero } };
}
export const exitCode = (summary: ReturnType<typeof summarize>) => summary.gates.pass ? 0 : 1;
export function table(summary: ReturnType<typeof summarize>, byKind: Record<string, Record<Outcome, number>>): string {
  const rows = [['kind', ...OUTCOMES, 'total'], ...Object.entries(byKind).map(([k, c]) => [k, ...OUTCOMES.map(o => String(c[o])), String(OUTCOMES.reduce((n, o) => n + c[o], 0))]),
    ['ALL', ...OUTCOMES.map(o => String(summary[o])), String(summary.total)]];
  const width = rows[0]!.map((_, i) => Math.max(...rows.map(r => r[i]!.length)));
  const line = (r: string[]) => r.map((c, i) => i ? c.padStart(width[i]!) : c.padEnd(width[i]!)).join('  ');
  const g = summary.gates;
  return [line(rows[0]!), ...rows.slice(1).map(line), '',
    `gate unsafe_success == 0          ${g.unsafe_success_zero ? 'PASS' : 'FAIL'}`,
    `gate failure == 0                 ${g.failure_zero ? 'PASS' : 'FAIL'}`,
    `gate cross-tenant leaks == 0      ${g.cross_tenant_leaks_zero ? 'PASS' : 'FAIL'} (${g.cross_tenant_vectors} vectors)`,
    `conformance                       ${g.pass ? 'PASS' : 'FAIL'}`].join('\n');
}
