// Identity and authority (0.6, ADR-019, spec/AKAC-0.6.md): RFC 8693 actor chains, heartbeat-bound
// grants, break-glass, the approval quorum and risk caps. Attack tests first; synthetic data only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { AdminJwtAuthenticator, JwtAuthenticator, actorChain } from '../adapters/jwt.ts';
import type { JwtConfiguration } from '../adapters/jwt.ts';
import { bindings, kbFixture } from '../examples/fixture.ts';
import { Engine } from '../reference/engine.ts';
import { ControlPlane } from '../reference/control.ts';
import type { ControlEvent } from '../reference/control.ts';
import { MemoryStore } from '../reference/store.ts';
import { verifyAudit } from '../reference/audit.ts';
import { attachActorChain, actorChainOf } from '../reference/delegation.ts';
import { decide, riskLimit } from '../reference/policy.ts';
import { settingsRelax, validSettings } from '../reference/approvals.ts';
import type { ApprovalGate } from '../reference/approvals.ts';
import { caepRiskLevel } from '../reference/risk.ts';
import type { RiskProvider } from '../reference/risk.ts';
import type { Grant, Knowledge, RiskLevel, State } from '../reference/types.ts';
import { close, listen } from './support.ts';
import { createAdminGateway } from '../reference/admin.ts';

// ---------- RFC 8693 actor chains ----------
const keys = await generateKeyPair('ES256');
const jwk = { ...await exportJWK(keys.publicKey), kid: 'id-key', alg: 'ES256', use: 'sig' };
const base = { issuer: 'https://identity.example.test', audience: 'akac-gateway', jwksUrl: 'https://identity.example.test/jwks', algorithms: ['ES256'] as ('ES256')[] };
const config: JwtConfiguration = { ...base, subjects: { 'user-chief': bindings.chief, 'legacy-run': bindings.intern },
  delegation: { 'user-chief': { actor: 'spiffe://example.test/agent/chief', actorIssuer: 'https://identity.example.test' } } };
const auth = new JwtAuthenticator(config, createLocalJWKSet({ keys: [jwk] }));
async function token(claims: Record<string, unknown>) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: base.issuer, aud: base.audience, iat: now, exp: now + 120, jti: `t-${Math.random()}`, ...claims })
    .setProtectedHeader({ alg: 'ES256', kid: 'id-key', typ: 'at+jwt' }).sign(keys.privateKey);
}
const agentActor = { sub: 'spiffe://example.test/agent/chief', iss: 'https://identity.example.test' };

test('RFC 8693: a delegation token whose current actor matches the mapping authenticates and carries its chain', async () => {
  const b = await auth.authenticate(await token({ sub: 'user-chief', act: { ...agentActor, act: { sub: 'orchestrator-7' } } }));
  assert.deepEqual(b, bindings.chief);
  assert.deepEqual(actorChainOf(b!), ['spiffe://example.test/agent/chief', 'orchestrator-7']);
  // may_act naming the same actor is accepted.
  assert.ok(await auth.authenticate(await token({ sub: 'user-chief', act: agentActor, may_act: agentActor })));
});
test('RFC 8693 attacks: chain spoofing, missing delegation, prior actor posing as current, may_act mismatch and malformed chains deny', async () => {
  const deny = async (claims: Record<string, unknown>) => assert.equal(await auth.authenticate(await token(claims)), null, JSON.stringify(claims));
  await deny({ sub: 'user-chief', act: { sub: 'spiffe://example.test/agent/intern', iss: agentActor.iss } });           // another agent
  await deny({ sub: 'user-chief', act: { sub: agentActor.sub, iss: 'https://attacker.example.test' } });               // wrong actor issuer
  await deny({ sub: 'user-chief', act: { sub: agentActor.sub } });                                                     // issuer required by mapping
  await deny({ sub: 'user-chief', act: { sub: 'orchestrator-7', act: agentActor } });                                  // mapped actor only as a prior actor
  await deny({ sub: 'user-chief' });                                                                                    // impersonation where delegation is required
  await deny({ sub: 'legacy-run', act: agentActor });                                                                   // delegation where the mapping has none
  await deny({ sub: 'legacy-run', may_act: agentActor });                                                               // may_act without act
  await deny({ sub: 'user-chief', act: agentActor, may_act: { sub: 'someone-else' } });                                 // may_act names another party
  await deny({ sub: 'user-chief', act: 'spiffe://example.test/agent/chief' });                                         // not an object
  await deny({ sub: 'user-chief', act: { ...agentActor, act: { sub: 'a', act: { sub: 'b', act: { sub: 'c', act: { sub: 'd', act: { sub: 'e' } } } } } } }); // deeper than 5
  await deny({ sub: 'user-chief', act: { ...agentActor, act: { sub: 'has space' } } });                                  // invalid id
  await deny({ sub: 'user-chief', act: { ...agentActor, act: [] } });                                                   // nested not an object
  // Token claims never select authority: roles and agent ids in the token are ignored.
  assert.deepEqual(await auth.authenticate(await token({ sub: 'legacy-run', roles: ['security-admin'], agent: 'chief-agent' })), bindings.intern);
  assert.equal(actorChain({ sub: 'a', act: { sub: 'b' } })?.chain.join(','), 'a,b');
  assert.throws(() => new JwtAuthenticator({ ...config, delegation: { unknown: { actor: 'x' } } }, createLocalJWKSet({ keys: [jwk] })), /delegation/);
});
test('RFC 8693: administrative and PEP credentials are never delegation tokens', async () => {
  const admin = new AdminJwtAuthenticator({ ...base, audience: 'akac-admin', admins: { 'ops-user': { tenant: 'acme', admin: 'sec' } } }, createLocalJWKSet({ keys: [jwk] }));
  const t = (claims: Record<string, unknown>) => token({ aud: 'akac-admin', sub: 'ops-user', ...claims });
  assert.deepEqual(await admin.authenticate(await t({})), { tenant: 'acme', admin: 'sec' });
  assert.equal(await admin.authenticate(await t({ act: agentActor })), null);
  assert.equal(await admin.authenticate(await t({ may_act: agentActor })), null);
});

// ---------- shared world ----------
function world(): State {
  const s = kbFixture(Date.now());
  const add = (id: string, kind: 'user' | 'service', roles: string[], tenant = 'acme') => { s.actors[id] = { id, tenant, kind, roles, projects: [], clearance: 'restricted', active: true }; };
  add('sec', 'user', ['security-admin']); add('sec2', 'user', ['security-admin']); add('sec3', 'user', ['security-admin']);
  add('kbadm', 'user', ['kb-admin']); add('aud', 'user', ['auditor']);
  add('runtime-1', 'service', ['runtime']); s.actors['runtime-1']!.runtimeFor = ['chief-agent']; add('risk-1', 'service', ['risk-ingest']); add('svc-admin', 'service', ['security-admin']);
  add('other-sec', 'user', ['security-admin'], 'other');
  return s;
}
function setup(options: { gate?: ApprovalGate; risk?: RiskProvider } = {}) {
  let now = Date.now();
  const clock = () => now;
  const store = new MemoryStore(world());
  const events: ControlEvent[] = [];
  const control = new ControlPlane(store, { clock, onEvent: e => events.push(e), ...(options.gate ? { approvalGate: options.gate } : {}) });
  const engine = new Engine(store, { clock, ...(options.risk ? { risk: options.risk } : {}) });
  return { store, control, engine, events, clock, tick: (ms: number) => { now += ms; }, at: () => now };
}
/** Read-only decision (no context: an epoch change would otherwise end the run's contexts, R13). */
const read = async (engine: Engine, grant: string, ids: string[], purpose = 'work', b = bindings.chief) => ({ ok: (await engine.evaluate({ ...b, grant }, ids[0]!, 'read', purpose)).decision });
const open = (engine: Engine, grant: string, ids: string[], purpose = 'work', b = bindings.chief) => engine.openContext({ ...b, grant }, ids, purpose);
const audits = async (store: MemoryStore) => store.auditLog('acme');

test('actor chains are recorded in the audit entry of every decision of the binding', async () => {
  const w = setup();
  const b = attachActorChain({ ...bindings.chief }, ['spiffe://example.test/agent/chief', 'orchestrator-7']);
  assert.equal((await w.engine.openContext(b, ['handbook'], 'work')).ok, true);
  assert.equal((await w.engine.openContext({ ...bindings.chief }, ['strategy', 'nope'], 'work')).ok, false);
  const log = await audits(w.store);
  assert.deepEqual(log.at(-2)!.actorChain, ['spiffe://example.test/agent/chief', 'orchestrator-7']);
  assert.equal(log.at(-1)!.actorChain, undefined, 'a binding without a verified chain records none');
  assert.ok(verifyAudit(log));
  assert.throws(() => attachActorChain({ ...bindings.chief }, []), /actor chain/);
  assert.throws(() => attachActorChain({ ...bindings.chief }, ['a', 'b', 'c', 'd', 'e', 'f']), /actor chain/);
});

// ---------- heartbeat-bound grants ----------
const grant = (id: string, extra: Partial<Grant> = {}, now = Date.now()): Grant => ({ id, tenant: 'acme', subject: 'chief', agent: 'chief-agent', actions: ['read', 'derive'],
  resources: ['*'], purposes: ['work'], notBefore: now - 1000, expiresAt: now + 3_600_000, active: true, ...extra });

test('heartbeat: issuance starts the run alive; it lapses after the TTL, finally, and cascades to children', async () => {
  const w = setup();
  assert.equal((await w.control.issueGrant('acme', 'sec', grant('hb', { heartbeatTtlMs: 10_000 }, w.at()))).ok, true);
  assert.equal((await w.control.issueGrant('acme', 'sec', grant('hb-child', { parent: 'hb', heartbeatTtlMs: 5_000, actions: ['read'] }, w.at()))).ok, true);
  assert.equal((await read(w.engine, 'hb', ['handbook'])).ok, true);
  // A caller can never set the heartbeat time.
  assert.equal((await w.control.issueGrant('acme', 'sec', { ...grant('forged', { heartbeatTtlMs: 10_000 }, w.at()), lastHeartbeatAt: w.at() + 1e9 } as Grant)).ok, false);
  w.tick(4_000);
  assert.equal((await w.control.heartbeat('acme', 'runtime-1', 'hb')).ok, true);
  assert.equal((await w.control.heartbeat('acme', 'runtime-1', 'hb-child')).ok, true);
  w.tick(8_000);   // parent last heartbeat 8 s ago (< 10 s), child 8 s ago (> 5 s): the child lapsed
  assert.equal((await read(w.engine, 'hb', ['handbook'])).ok, true);
  assert.equal((await read(w.engine, 'hb-child', ['handbook'])).ok, false);
  assert.equal((await w.control.heartbeat('acme', 'runtime-1', 'hb-child')).ok, false, 'a lapse is final');
  const late = await w.control.heartbeat('acme', 'runtime-1', 'hb-child');
  assert.equal(!late.ok && late.code, 'CONFLICT');
  // A fresh child under the parent, then the parent lapses: the child is invalid even with its own fresh heartbeat.
  assert.equal((await w.control.issueGrant('acme', 'sec', grant('hb-child2', { parent: 'hb', heartbeatTtlMs: 5_000, actions: ['read'], notBefore: w.at() - 1, expiresAt: w.at() + 60_000 }, w.at()))).ok, true);
  assert.equal((await w.control.heartbeat('acme', 'runtime-1', 'hb')).ok, true);
  w.tick(2_500); assert.equal((await w.control.heartbeat('acme', 'runtime-1', 'hb-child2')).ok, true);
  assert.equal((await read(w.engine, 'hb-child2', ['handbook'])).ok, true);
  w.tick(4_000); assert.equal((await w.control.heartbeat('acme', 'runtime-1', 'hb-child2')).ok, true);
  w.tick(4_000);  // parent now 10.5 s without heartbeat, the child 4 s
  assert.equal((await w.control.heartbeat('acme', 'runtime-1', 'hb-child2')).ok, false, 'the parent lapsed: the chain is invalid');
  assert.equal((await read(w.engine, 'hb-child2', ['handbook'])).ok, false);
  assert.equal((await read(w.engine, 'hb', ['handbook'])).ok, false);
  assert.equal((await w.control.heartbeat('acme', 'runtime-1', 'hb')).ok, false);
});
test('heartbeat: only the runtime role of a service or user may heartbeat; a TTL longer than the parent is refused', async () => {
  const w = setup();
  await w.control.issueGrant('acme', 'sec', grant('hb', { heartbeatTtlMs: 10_000 }, w.at()));
  for (const who of ['sec', 'risk-1', 'svc-admin', 'other-sec', 'nobody']) {
    const r = await w.control.heartbeat('acme', who, 'hb');
    assert.equal(!r.ok && r.code, 'NOT_AUTHORIZED', who);
  }
  const plain = await w.control.issueGrant('acme', 'sec', grant('no-hb', {}, w.at()));
  assert.equal(plain.ok, true);
  const r = await w.control.heartbeat('acme', 'runtime-1', 'no-hb');
  assert.equal(!r.ok && r.code, 'INVALID_REQUEST', 'only heartbeat-bound grants take heartbeats');
  const longer = await w.control.issueGrant('acme', 'sec', grant('long', { parent: 'hb', heartbeatTtlMs: 20_000, actions: ['read'] }, w.at()));
  assert.equal(longer.ok, false);
  const none = await w.control.issueGrant('acme', 'sec', grant('none', { parent: 'hb', actions: ['read'] }, w.at()));
  assert.equal(none.ok, false, 'a child of a heartbeat-bound parent needs its own TTL');
  // A service principal holding security-admin cannot use it.
  const svc = await w.control.issueGrant('acme', 'svc-admin', grant('svc', {}, w.at()));
  assert.equal(!svc.ok && svc.code, 'NOT_AUTHORIZED');
});
test('heartbeat: an agent-delegated child starts alive at delegation, whatever heartbeat time the agent sends', async () => {
  const w = setup();
  await w.control.issueGrant('acme', 'sec', grant('hb', { heartbeatTtlMs: 10_000 }, w.at()));
  const b = { ...bindings.chief, grant: 'hb' };
  const child = { ...grant('d1', { parent: 'hb', heartbeatTtlMs: 5_000, actions: ['read'] }, w.at()), lastHeartbeatAt: w.at() + 1e12 };
  assert.equal((await w.engine.delegate(b, child)).ok, true);
  const stored = await w.store.transaction('acme', async tx => tx.state.grants.d1!);
  assert.equal(stored.lastHeartbeatAt, w.at());
  w.tick(6_000);
  assert.equal((await read(w.engine, 'd1', ['handbook'])).ok, false);
});

// ---------- approvals and break-glass ----------
const hrNote = (now: number): Knowledge => ({ id: 'hr-note', tenant: 'acme', version: 1, kind: 'document', origin: 'system', content: 'HR note: synthetic contact list.',
  classification: 'internal', readerRoles: ['hr'], projects: [], readers: [], sources: [], active: true, ...(now ? {} : {}) });
const breakGlass = (extra: Record<string, unknown> = {}) => ({ id: 'bg-1', subject: 'intern', agent: 'intern-agent', resources: ['hr-note'], purposes: ['incident'], ttlMs: 3_600_000, ...extra });

test('break-glass: four eyes by default; self-approval and duplicate approval are refused; the grant and its use are flagged', async () => {
  const w = setup();
  assert.equal((await w.control.upsertKnowledge('acme', 'kbadm', hrNote(w.at()))).ok, true);
  const req = await w.control.issueBreakGlass('acme', 'sec', breakGlass());
  assert.equal(!req.ok && req.code, 'APPROVAL_REQUIRED');
  const id = !req.ok ? req.approval! : '';
  assert.equal((await read(w.engine, 'bg-1', ['hr-note'], 'incident', bindings.intern)).ok, false, 'nothing issued before the quorum');
  const self = await w.control.approve('acme', 'sec', id);
  assert.equal(!self.ok && self.code, 'CONFLICT', 'the requester cannot approve');
  const kb = await w.control.approve('acme', 'kbadm', id);
  assert.equal(!kb.ok && kb.code, 'NOT_AUTHORIZED', 'approvers are security-admins');
  const svc = await w.control.approve('acme', 'svc-admin', id);
  assert.equal(!svc.ok && svc.code, 'NOT_AUTHORIZED', 'a service principal never approves');
  const ok = await w.control.approve('acme', 'sec2', id);
  assert.ok(ok.ok && ok.value.execution?.ok, JSON.stringify(ok));
  assert.equal(ok.ok && ok.value.approval.status, 'executed');
  const dup = await w.control.approve('acme', 'sec2', id);
  assert.equal(!dup.ok && dup.code, 'CONFLICT');
  const r = await open(w.engine, 'bg-1', ['hr-note'], 'incident', bindings.intern);
  assert.equal(r.ok, true, 'the named record opens outside the audience');
  assert.equal((await read(w.engine, 'bg-1', ['handbook'], 'incident', bindings.intern)).ok, false, 'only named resources');
  const log = await audits(w.store);
  const bg = log.filter(e => e.breakGlass);
  assert.ok(bg.some(e => e.operation === 'issue_break_glass' && e.decision === 'allow'));
  assert.ok(bg.some(e => e.operation === 'issue_break_glass' && e.reasonCode === 'APPROVAL_REQUIRED'));
  assert.ok(bg.some(e => e.operation === 'approval_grant'));
  assert.equal(bg.filter(e => e.runId === 'bg-1').length, 2, 'every decision under the grant is flagged');
  assert.ok(log.filter(e => e.runId === 'bg-1').slice(-2).every(e => e.breakGlass));
  assert.ok(verifyAudit(log));
  assert.deepEqual(w.events.filter(e => e.type === 'break_glass').length, 1);
  // The grant cannot be delegated and derives nothing.
  const d = await w.engine.delegate({ ...bindings.intern, grant: 'bg-1' }, { ...grant('bg-child', { parent: 'bg-1', actions: ['read'], resources: ['hr-note'], purposes: ['incident'] }, w.at()), subject: 'intern', agent: 'intern-agent' });
  assert.equal(d.ok, false);
  const ctx = r.ok ? r.value.context : '';
  assert.equal((await w.engine.derive({ ...bindings.intern, grant: 'bg-1' }, ctx, 'summary')).ok, false);
});
test('break-glass limits: at most two hours, named resources, same tenant, never over quarantine or erasure, quorum never below 2', async () => {
  const w = setup();
  await w.control.upsertKnowledge('acme', 'kbadm', hrNote(w.at()));
  for (const bad of [{ ttlMs: 7_200_001 }, { resources: ['*'] }, { resources: [] }, { actions: ['read'] }, { subject: 'other-sec' }, { ttlMs: 10 }]) {
    const r = await w.control.issueBreakGlass('acme', 'sec', breakGlass(bad) as never);
    assert.equal(!r.ok && r.code, 'INVALID_REQUEST', JSON.stringify(bad));
  }
  // The quorum of break-glass cannot be configured below 2.
  assert.equal(validSettings({ id: 'acme', tenant: 'acme', approvalQuorum: { break_glass: 1 } }, 'acme'), false);
  assert.equal((await w.control.putSettings('acme', 'sec', { id: 'acme', tenant: 'acme', approvalQuorum: { break_glass: 1 } })).ok, false);
  // Quarantine wins over break-glass.
  const req = await w.control.issueBreakGlass('acme', 'sec', breakGlass());
  await w.control.approve('acme', 'sec2', !req.ok ? req.approval! : '');
  assert.equal((await w.control.quarantine('acme', 'kbadm', 'hr-note', 'incident')).ok, true);
  assert.equal((await read(w.engine, 'bg-1', ['hr-note'], 'incident', bindings.intern)).ok, false);
  // The grant expires after its lifetime.
  await w.control.release('acme', 'sec', 'hr-note');
  assert.equal((await read(w.engine, 'bg-1', ['hr-note'], 'incident', bindings.intern)).ok, true);
  w.tick(3_600_000);
  assert.equal((await read(w.engine, 'bg-1', ['hr-note'], 'incident', bindings.intern)).ok, false);
});
test('approvals expire, can be rejected, execute exactly once and re-validate at execution', async () => {
  const w = setup();
  const a = await w.control.issueBreakGlass('acme', 'sec', breakGlass());
  const id = !a.ok ? a.approval! : '';
  w.tick(86_400_000);
  const late = await w.control.approve('acme', 'sec2', id);
  assert.equal(!late.ok && late.code, 'CONFLICT', 'expired');
  const b = await w.control.issueBreakGlass('acme', 'sec', breakGlass({ id: 'bg-2' }));
  const id2 = !b.ok ? b.approval! : '';
  assert.equal((await w.control.reject('acme', 'sec3', id2)).ok, true);
  assert.equal((await w.control.approve('acme', 'sec2', id2)).ok, false, 'rejected');
  // An approval executes only its own request: another operation, another requester or other arguments are refused.
  const c = await w.control.issueBreakGlass('acme', 'sec', breakGlass({ id: 'bg-3' }));
  const id3 = !c.ok ? c.approval! : '';
  const forged = await w.control.issueBreakGlass('acme', 'sec', breakGlass({ id: 'bg-3', resources: ['strategy'] }), { approval: id3 });
  assert.equal(!forged.ok && forged.code, 'CONFLICT', 'other arguments');
  const other = await w.control.issueBreakGlass('acme', 'sec2', breakGlass({ id: 'bg-3' }), { approval: id3 });
  assert.equal(!other.ok && other.code, 'CONFLICT', 'another requester');
  const early = await w.control.issueBreakGlass('acme', 'sec', breakGlass({ id: 'bg-3' }), { approval: id3 });
  assert.equal(!early.ok && early.code, 'APPROVAL_REQUIRED', 'quorum not met');
  // An approver who lost security-admin before execution no longer counts.
  const approved = await w.control.approve('acme', 'sec2', id3);
  assert.ok(approved.ok && approved.value.execution?.ok);
  const again = await w.control.executeApproval('acme', 'sec', id3);
  assert.equal(!again.ok && again.code, 'CONFLICT', 'executes once');
  const d = await w.control.issueBreakGlass('acme', 'sec', breakGlass({ id: 'bg-4' }));
  const id4 = !d.ok ? d.approval! : '';
  await w.control.putSettings('acme', 'sec', { id: 'acme', tenant: 'acme', approvalQuorum: { break_glass: 3 } });
  const one = await w.control.approve('acme', 'sec2', id4);
  assert.ok(one.ok && one.value.execution === undefined && one.value.approval.status === 'pending', 'a raised quorum applies to pending requests');
  await w.control.assignRoles('acme', 'sec', 'sec2', []);
  const two = await w.control.approve('acme', 'sec3', id4);
  assert.ok(two.ok && two.value.approval.status === 'pending', 'sec2 no longer counts');
  const listed = await w.control.listApprovals('acme', 'sec');
  assert.ok(listed.ok && listed.value.some(x => x.id === id4) && listed.value.every(x => !('payload' in x)));
  const cross = await w.control.approve('other', 'other-sec', id4);
  assert.equal(!cross.ok && cross.code, 'CONFLICT', 'another tenant never sees the approval');
});
test('sensitive operations pass the quorum: label widening, role widening, SoD relaxation, runtime and destination widening, settings relaxation', async () => {
  const w = setup();
  // Tightening settings applies at once; relaxing needs the highest quorum of any class (break-glass: 2).
  const quorum = { label_widening: 2, role_widening: 2, sod_relaxation: 2, runtime_profile: 2, destination_widening: 2 };
  assert.equal((await w.control.putSettings('acme', 'sec', { id: 'acme', tenant: 'acme', approvalQuorum: quorum })).ok, true);
  const relax = await w.control.putSettings('acme', 'sec', { id: 'acme', tenant: 'acme' });
  assert.equal(!relax.ok && relax.code, 'APPROVAL_REQUIRED');
  // Label widening (declassification) of a document.
  await w.control.upsertKnowledge('acme', 'kbadm', hrNote(w.at()));
  const widen = await w.control.upsertKnowledge('acme', 'sec', { ...hrNote(w.at()), version: 2, readerRoles: ['hr', 'staff'] });
  assert.equal(!widen.ok && widen.code, 'APPROVAL_REQUIRED');
  assert.equal((await read(w.engine, 'intern-run', ['hr-note'], 'work', bindings.intern)).ok, false, 'not widened before the quorum');
  const done = await w.control.approve('acme', 'sec2', !widen.ok ? widen.approval! : '');
  assert.ok(done.ok && done.value.execution?.ok);
  assert.equal((await read(w.engine, 'intern-run', ['hr-note'], 'work', bindings.intern)).ok, true);
  // Narrowing is never gated.
  assert.equal((await w.control.upsertKnowledge('acme', 'kbadm', { ...hrNote(w.at()), version: 3, readerRoles: ['hr'] })).ok, true);
  // Role widening, SoD relaxation, destination widening, runtime profile change.
  const role = await w.control.upsertRole('acme', 'sec', { id: 'staff', tenant: 'acme', inherits: ['hr'], active: true });
  assert.equal(!role.ok && role.code, 'APPROVAL_REQUIRED');
  const sod = await w.control.upsertConstraint('acme', 'sec', { id: 'ssd-payments', tenant: 'acme', kind: 'static', roles: ['requester', 'approver'], cardinality: 2 });
  assert.equal(sod.ok, true, 'an unchanged constraint is not a relaxation');
  const sod2 = await w.control.upsertConstraint('acme', 'sec', { id: 'ssd-payments', tenant: 'acme', kind: 'dynamic', roles: ['requester', 'approver'], cardinality: 2 });
  assert.equal(!sod2.ok && sod2.code, 'APPROVAL_REQUIRED');
  const dest = await w.control.upsertDestination('acme', 'sec', { id: 'llm-eu', tenant: 'acme', class: 'model-provider', maxClassification: 'internal', purposes: ['work'], active: true });
  assert.equal(!dest.ok && dest.code, 'APPROVAL_REQUIRED');
  const inactive = await w.control.upsertDestination('acme', 'sec', { id: 'llm-off', tenant: 'acme', class: 'model-provider', maxClassification: 'internal', purposes: ['work'], active: false });
  assert.equal(inactive.ok, true, 'an inactive new profile receives nothing');
  const rp = await w.control.upsertRuntimeProfile('acme', 'sec', { id: 'rp1', tenant: 'acme', classification: 'confidential', profiles: { network: 'deny-all' }, active: true });
  assert.equal(rp.ok, true, 'a new runtime profile only adds obligations');
  const rp2 = await w.control.upsertRuntimeProfile('acme', 'sec', { id: 'rp1', tenant: 'acme', classification: 'confidential', profiles: { network: 'deny-all' }, active: false });
  assert.equal(!rp2.ok && rp2.code, 'APPROVAL_REQUIRED');
  const pending = await w.control.listApprovals('acme', 'sec');
  assert.equal(pending.ok && pending.value.length, 5);
  assert.equal(settingsRelax({ id: 'acme', tenant: 'acme', riskCaps: { high: 'public' } }, { id: 'acme', tenant: 'acme' }), true);
});
test('ApprovalGate can only require more: a higher quorum, an external workflow, and it fails closed', async () => {
  let satisfied = false, calls = 0;
  const gate: ApprovalGate = { requirements: async i => (calls++, i.class === 'label_widening' ? { external: true } : { quorum: 3 }), satisfied: async () => satisfied };
  const w = setup({ gate });
  await w.control.upsertKnowledge('acme', 'kbadm', hrNote(w.at()));
  // Quorum 1 by default, but the gate requires the external workflow: the requester alone is not enough.
  const widen = await w.control.upsertKnowledge('acme', 'sec', { ...hrNote(w.at()), version: 2, readerRoles: ['hr', 'staff'] });
  const id = !widen.ok ? widen.approval! : '';
  assert.equal(!widen.ok && widen.code, 'APPROVAL_REQUIRED');
  const early = await w.control.executeApproval('acme', 'sec', id);
  assert.equal(!early.ok && early.code, 'APPROVAL_REQUIRED', 'the external workflow has not completed');
  satisfied = true;
  const done = await w.control.executeApproval('acme', 'sec', id);
  assert.equal(done.ok, true);
  // A gate quorum above the tenant's applies; satisfied() never replaces the internal quorum.
  const bg = await w.control.issueBreakGlass('acme', 'sec', breakGlass());
  const bid = !bg.ok ? bg.approval! : '';
  const one = await w.control.approve('acme', 'sec2', bid);
  assert.ok(one.ok && one.value.approval.required === 3 && one.value.approval.status === 'pending');
  const two = await w.control.approve('acme', 'sec3', bid);
  assert.ok(two.ok && two.value.execution?.ok);
  // A failing gate requires the external workflow (fail closed).
  const broken = setup({ gate: { requirements: async () => { throw new Error('down'); } } });
  const r = await broken.control.upsertRole('acme', 'sec', { id: 'staff', tenant: 'acme', inherits: ['hr'], active: true });
  assert.equal(!r.ok && r.code, 'APPROVAL_REQUIRED');
  const e = await broken.control.executeApproval('acme', 'sec', !r.ok ? r.approval! : '');
  assert.equal(!e.ok && e.code, 'APPROVAL_REQUIRED', 'no satisfied(): never executes');
  assert.ok(calls >= 2);
});

// ---------- risk ----------
test('risk signals: a service connector ingests, a raise advances the epoch, caps never widen and critical denies', async () => {
  const w = setup();
  assert.equal((await read(w.engine, 'chief-run', ['strategy'])).ok, true);
  const r = await w.control.putRiskSignal('acme', 'risk-1', { principal: 'chief', level: 'high', event: 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change' });
  assert.ok(r.ok);
  assert.equal((await read(w.engine, 'chief-run', ['strategy'])).ok, false);
  assert.equal((await read(w.engine, 'chief-run', ['handbook'])).ok, true);
  const log = await audits(w.store);
  assert.equal(log.at(-2)!.reasonCode, 'RISK_CAP');
  // A tenant cap above a lower level's cap never widens.
  assert.equal(validSettings({ id: 'acme', tenant: 'acme', riskCaps: { medium: 'internal', high: 'confidential' } }, 'acme'), false);
  assert.equal(validSettings({ id: 'acme', tenant: 'acme', riskCaps: { critical: 'restricted' } }, 'acme'), false);
  await w.control.putRiskSignal('acme', 'sec', { principal: 'chief-agent', level: 'critical', ttlMs: 60_000 });
  assert.equal((await read(w.engine, 'chief-run', ['handbook'])).ok, false);
  w.tick(60_000);
  assert.equal((await read(w.engine, 'chief-run', ['handbook'])).ok, true, 'expired signals are ignored');
  // Only the caller's own signal is replaced: another source's high level remains.
  await w.control.putRiskSignal('acme', 'sec', { principal: 'chief', level: 'none' });
  assert.equal((await read(w.engine, 'chief-run', ['strategy'])).ok, false);
  await w.control.putRiskSignal('acme', 'risk-1', { principal: 'chief', level: 'none' });
  assert.equal((await read(w.engine, 'chief-run', ['strategy'])).ok, true);
  for (const [who, input] of [['kbadm', { principal: 'chief', level: 'high' }], ['runtime-1', { principal: 'chief', level: 'high' }],
    ['risk-1', { principal: 'chief', level: 'severe' }], ['risk-1', { principal: 'nobody', level: 'high' }], ['risk-1', { principal: 'other-sec', level: 'high' }],
    ['risk-1', { principal: 'chief', level: 'high', event: 'https://attacker.example.test/x' }], ['risk-1', { principal: 'chief', level: 'high', source: 'spoofed' }]] as const) {
    assert.equal((await w.control.putRiskSignal('acme', who, input as never)).ok, false, `${who} ${JSON.stringify(input)}`);
  }
  assert.equal(caepRiskLevel('HIGH'), 'high'); assert.equal(caepRiskLevel('SEVERE'), null);
});
test('RiskProvider can only lower clearance; a failure denies', async () => {
  let level: RiskLevel = 'none', fail = false;
  const w = setup({ risk: { level: async i => { if (fail) throw new Error('down'); return i.kind === 'agent' ? level : 'none'; } } });
  assert.equal((await read(w.engine, 'chief-run', ['strategy'])).ok, true);
  level = 'high';
  assert.equal((await read(w.engine, 'chief-run', ['strategy'])).ok, false);
  assert.equal((await read(w.engine, 'chief-run', ['handbook'])).ok, true);
  // A provider saying 'none' never lifts a stored signal.
  level = 'none';
  await w.control.putRiskSignal('acme', 'risk-1', { principal: 'chief', level: 'critical' });
  assert.equal((await read(w.engine, 'chief-run', ['handbook'])).ok, false);
  await w.control.putRiskSignal('acme', 'risk-1', { principal: 'chief', level: 'none' });
  fail = true;
  assert.equal((await read(w.engine, 'chief-run', ['handbook'])).ok, false);
  const log = await audits(w.store);
  assert.equal(log.at(-1)!.reasonCode, 'POLICY_UNAVAILABLE');
  const bad = setup({ risk: { level: async () => 'severe' as RiskLevel } });
  assert.equal((await read(bad.engine, 'chief-run', ['handbook'])).ok, false);
});
test('property: adding any risk signal never turns a denial into an allow', () => {
  const now = 1_800_000_000_000;
  const levels: RiskLevel[] = ['none', 'low', 'medium', 'high', 'critical'];
  const docs = ['handbook', 'strategy', 'project-alpha', 'board-notes', 'vault-memo', 'staff-faq'];
  for (const who of ['chief', 'intern', 'lead'] as const) for (const doc of docs) for (const level of levels) for (const target of ['user', 'agent']) {
    const s = kbFixture(now);
    const input = { binding: bindings[who], resource: doc, action: 'read' as const, purpose: 'work', now };
    const before = decide(s, input);
    const principal = target === 'user' ? bindings[who].subject : bindings[who].agent;
    s.riskSignals = { x: { id: 'x', tenant: 'acme', principal, level, source: 'p', issuedAt: now, expiresAt: now + 1 } };
    const after = decide(s, input);
    if (before.effect === 'deny') assert.equal(after.effect, 'deny', `${who} ${doc} ${level}`);
    if (level === 'critical') assert.equal(after.effect, 'deny');
    assert.ok(riskLimit(s, s.actors[principal]!, now) <= 3);
  }
});

// ---------- administrative HTTP routes ----------
test('admin routes: heartbeat (runtime service), break-glass with approval, risk signals and settings', async () => {
  let now = Date.now();
  const store = new MemoryStore(world());
  const control = new ControlPlane(store, { clock: () => now });
  const token = (n: string) => `test-only-${n}-credential-0000000000000000000000`;
  const admin = createAdminGateway(control, { credentials: ['sec', 'sec2', 'runtime-1', 'risk-1', 'aud'].map(a => ({ token: token(a), binding: { tenant: 'acme', admin: a } })) });
  const url = await listen(admin);
  const call = (who: string, method: string, path: string, body?: unknown) => fetch(url + path, { method,
    headers: { authorization: `Bearer ${token(who)}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  try {
    const g = grant('hb', { heartbeatTtlMs: 10_000 }, now);
    assert.equal((await call('sec', 'POST', '/admin/v1/grants', g)).status, 201);
    assert.equal((await call('runtime-1', 'POST', '/admin/v1/grants/hb/heartbeat')).status, 200);
    assert.equal((await call('sec', 'POST', '/admin/v1/grants/hb/heartbeat')).status, 403);
    now += 11_000;
    assert.equal((await call('runtime-1', 'POST', '/admin/v1/grants/hb/heartbeat')).status, 409);
    const req = await call('sec', 'POST', '/admin/v1/break-glass', breakGlass({ resources: ['handbook'] }));
    assert.equal(req.status, 202);
    const { approval } = await req.json() as { approval: string };
    assert.equal((await call('sec', 'POST', `/admin/v1/approvals/${approval}/approve`)).status, 409);
    const view = await call('sec2', 'GET', `/admin/v1/approvals/${approval}`);
    assert.equal(view.status, 200);
    assert.equal((await call('aud', 'GET', `/admin/v1/approvals/${approval}`)).status, 403);
    const ok = await call('sec2', 'POST', `/admin/v1/approvals/${approval}/approve`);
    assert.equal(ok.status, 200);
    assert.equal(((await ok.json()) as { value: { approval: { status: string } } }).value.approval.status, 'executed');
    assert.equal((await call('risk-1', 'POST', '/admin/v1/risk-signals', { principal: 'chief', level: 'high' })).status, 200);
    assert.equal((await call('risk-1', 'POST', '/admin/v1/risk-signals', { principal: 'chief', level: 'high', source: 'x' })).status, 400);
    assert.equal((await call('sec', 'PUT', '/admin/v1/settings', { riskCaps: { high: 'public' } })).status, 200);
    assert.equal((await call('sec', 'PUT', '/admin/v1/settings', { tenant: 'other' })).status, 400);
    const settings = await call('aud', 'GET', '/admin/v1/settings');
    assert.equal(((await settings.json()) as { value: { riskCaps: Record<string, string> } }).value.riskCaps.high, 'public');
    assert.equal((await call('sec', 'PUT', '/admin/v1/settings', {})).status, 202, 'relaxing the risk caps needs the quorum');
  } finally { await close(admin); }
});
