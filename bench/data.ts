import { emptyState, LEVELS } from '../reference/types.ts';
import type { Actor, Binding, Container, Grant, Knowledge, Level, Role, State } from '../reference/types.ts';
import { decide, effectiveLabel } from '../reference/policy.ts';
import { defaultChunker } from '../reference/chunking.ts';
import type { Embedder } from '../reference/embedding.ts';
import type { IndexedChunk } from '../reference/vector.ts';
import { RETRIEVAL } from '../reference/engine.ts';
import { prng } from './stats.ts';
import type { Rng } from './stats.ts';

/**
 * Synthetic multi-tenant data set. Everything is derived from the seed; no real
 * names, documents or personal data. Per tenant: `roles` roles in chains of
 * `roleDepth` (a role inherits the next one of its chain; chain k is the common
 * chain of knowledge base k, which half of its documents admit), knowledge bases with
 * folder chains of `containerDepth`, documents in them, users with an agent and one
 * grant each, a few groups, one static separation-of-duty constraint, and chains of
 * model-derived artifacts `dagDepth` long (each node derives from the previous one
 * and from one document). Tenant `tlex` holds exactly the lexical corpus bound
 * (RETRIEVAL.corpus documents) for the bounded lexical retrieval workload.
 */
export type Scale = {
  name: string; tenants: number; docsPerTenant: number; usersPerTenant: number; roles: number; roleDepth: number;
  knowledgeBases: number; branches: number; containerDepth: number; dagDepth: number; dagChains: number; groups: number;
  lexicalDocs: number; iterations: number;
};
export const SCALES: Record<string, Scale> = {
  // Test/smoke only.
  tiny: { name: 'tiny', tenants: 2, docsPerTenant: 60, usersPerTenant: 20, roles: 40, roleDepth: 8, knowledgeBases: 2, branches: 2, containerDepth: 8, dagDepth: 16, dagChains: 1, groups: 2, lexicalDocs: 60, iterations: 30 },
  // 10 tenants, 1k documents, 1k grants.
  small: { name: 'small', tenants: 10, docsPerTenant: 100, usersPerTenant: 100, roles: 200, roleDepth: 8, knowledgeBases: 5, branches: 4, containerDepth: 8, dagDepth: 16, dagChains: 2, groups: 10, lexicalDocs: RETRIEVAL.corpus, iterations: 300 },
  // 10 tenants, 10k documents, 10k grants.
  medium: { name: 'medium', tenants: 10, docsPerTenant: 1000, usersPerTenant: 1000, roles: 200, roleDepth: 8, knowledgeBases: 5, branches: 4, containerDepth: 8, dagDepth: 16, dagChains: 10, groups: 10, lexicalDocs: RETRIEVAL.corpus, iterations: 1000 },
  // 10 tenants, 100k documents, 10k grants.
  large: { name: 'large', tenants: 10, docsPerTenant: 10000, usersPerTenant: 1000, roles: 200, roleDepth: 8, knowledgeBases: 5, branches: 4, containerDepth: 8, dagDepth: 16, dagChains: 20, groups: 10, lexicalDocs: RETRIEVAL.corpus, iterations: 1000 }
};

export type TenantSet = { tenant: string; bindings: Binding[]; docs: string[]; derived: string[][];
  /** Filled by authorize(): documents each sampled binding may read, and (binding, chain) pairs whose whole derivation chain is readable. */
  authorized?: { binding: Binding; docs: string[] }[]; readableChains?: { binding: Binding; chain: string[] }[] };
export type DataSet = { scale: Scale; now: number; /** One snapshot per tenant (record keys are ids; ids repeat across tenants). */ states: Map<string, State>; tenants: TenantSet[]; lexical: TenantSet; vocabulary: string[]; counts: Record<string, number> };

const SYLLABLES = ['ka', 'lo', 'mi', 'ne', 'ru', 'ta', 'vo', 'shi', 'pe', 'da', 'gu', 'zo', 'fi', 'be', 'no', 'xa'];
function vocabulary(rng: Rng, n: number): string[] {
  const words = new Set<string>();
  while (words.size < n) words.add(Array.from({ length: 2 + rng.int(2) }, () => rng.pick(SYLLABLES)).join(''));
  return [...words];
}
const LEVEL_WEIGHTS: [Level, number][] = [['public', 0.2], ['internal', 0.5], ['confidential', 0.2], ['restricted', 0.1]];
function weighted(rng: Rng, table: [Level, number][]): Level {
  let x = rng.next();
  for (const [v, w] of table) { if ((x -= w) < 0) return v; }
  return table.at(-1)![0];
}
const higher = (a: Level, b: Level): Level => LEVELS.indexOf(a) >= LEVELS.indexOf(b) ? a : b;

export function generate(scale: Scale, seed = 1, now = Date.now()): DataSet {
  const rng = prng(seed), states = new Map<string, State>();
  const vocab = vocabulary(rng, 2000), topics = Array.from({ length: 50 }, (_, t) => vocab.slice(t * 40, t * 40 + 40));
  const text = (topic: number, words: number) => Array.from({ length: words }, () => rng.chance(0.7) ? rng.pick(topics[topic]!) : rng.pick(vocab)).join(' ') + '.';
  const counts: Record<string, number> = { tenants: 0, roles: 0, containers: 0, documents: 0, derived: 0, actors: 0, grants: 0, groups: 0 };
  const build = (tenant: string, docCount: number, users: number, dagChains: number): TenantSet => {
    counts.tenants!++;
    const s = emptyState(); states.set(tenant, s);
    const chains = Math.max(2, Math.floor(scale.roles / scale.roleDepth));
    const role = (c: number, d: number) => `r${c}-${d}`;
    for (let c = 0; c < chains; c++) for (let d = 0; d < scale.roleDepth; d++) {
      const r: Role = { id: role(c, d), tenant, inherits: d + 1 < scale.roleDepth ? [role(c, d + 1)] : [], active: true };
      s.roles[r.id] = r; counts.roles!++;
    }
    const bottom = (c: number) => role(c, scale.roleDepth - 1), mid = (c: number) => role(c, Math.min(3, scale.roleDepth - 1));
    const kbChains = (k: number) => Array.from({ length: chains }, (_, c) => c).filter(c => c % scale.knowledgeBases === k);
    // Containers: knowledge base (depth 1), then `branches` folder chains down to containerDepth.
    const leaves: { id: string; kb: number; level: number }[] = [];
    for (let k = 0; k < scale.knowledgeBases; k++) {
      const kb: Container = { id: `kb${k}`, tenant, kind: 'knowledge-base', classification: 'internal', readerRoles: kbChains(k).map(bottom), readers: [], projects: [], active: true };
      s.containers[kb.id] = kb; counts.containers!++; leaves.push({ id: kb.id, kb: k, level: 1 });
      for (let b = 0; b < scale.branches; b++) {
        let parent = kb.id;
        for (let l = 2; l <= scale.containerDepth; l++) {
          const classification: Level = b === scale.branches - 1 && l >= 5 ? 'confidential' : b === 2 && l >= 7 ? 'restricted' : 'internal';
          // Branch 1 narrows the audience below level 4 to holders of a mid-level role of one chain.
          const readerRoles = b === 1 && l >= 4 ? [mid(kbChains(k)[l % kbChains(k).length]!)] : kbChains(k).map(bottom);
          const f: Container = { id: `f${k}-${b}-${l}`, tenant, kind: 'folder', parent, classification, readerRoles, readers: [], projects: [], active: true };
          s.containers[f.id] = f; counts.containers!++; leaves.push({ id: f.id, kb: k, level: l }); parent = f.id;
        }
      }
    }
    const docs: string[] = [];
    for (let i = 0; i < docCount; i++) {
      const where = rng.pick(leaves), topic = rng.int(topics.length), chain = rng.pick(kbChains(where.kb));
      const k: Knowledge = { id: `d${i}`, tenant, version: 1, kind: 'document', origin: 'human', content: text(topic, 40 + rng.int(40)),
        classification: weighted(rng, LEVEL_WEIGHTS), projects: rng.chance(0.1) ? [`p${rng.int(10)}`] : [],
        readerRoles: rng.chance(0.5) ? [bottom(where.kb)] : rng.chance(0.2) ? [mid(chain)] : [bottom(chain)], readers: [], sources: [], active: true, container: where.id };
      s.knowledge[k.id] = k; docs.push(k.id); counts.documents!++;
    }
    // Derivation chains: node j derives from node j-1 and from one public or internal document.
    const derived: string[][] = [];
    const plain = docs.filter(id => ['public', 'internal'].includes(s.knowledge[id]!.classification) && s.knowledge[id]!.projects.length === 0);
    for (let c = 0; c < dagChains && plain.length; c++) {
      const chain: string[] = [];
      // Every source of one chain shares the first source's container and audience, so a caller that may read the tip may read the whole graph.
      const first = s.knowledge[rng.pick(plain)]!;
      const pool = plain.filter(id => s.knowledge[id]!.container === first.container && s.knowledge[id]!.readerRoles[0] === first.readerRoles[0]);
      for (let j = 0; j < scale.dagDepth; j++) {
        const base = j ? s.knowledge[rng.pick(pool)]! : first;
        const sources = [{ id: base.id, version: 1 }, ...(j ? [{ id: chain[j - 1]!, version: 1 }] : [])];
        const classification = j ? higher(base.classification, s.knowledge[chain[j - 1]!]!.classification) : base.classification;
        const k: Knowledge = { id: `x${c}-${j}`, tenant, version: 1, kind: 'artifact', origin: 'model', content: text(rng.int(topics.length), 30),
          classification, projects: [], readerRoles: base.readerRoles, readers: [], sources, active: true, ...(base.container ? { container: base.container } : {}) };
        s.knowledge[k.id] = k; chain.push(k.id); counts.derived!++;
      }
      derived.push(chain);
    }
    const bindings: Binding[] = [];
    for (let i = 0; i < users; i++) {
      // A home knowledge base (chain h is the kb's common chain) plus one other chain.
      const home = rng.int(scale.knowledgeBases);
      const held = [role(home, rng.int(Math.min(4, scale.roleDepth))), role(rng.int(chains), rng.int(Math.min(4, scale.roleDepth)))];
      const projects = rng.chance(0.3) ? [`p${rng.int(10)}`] : [];
      const user: Actor = { id: `u${i}`, tenant, kind: 'user', roles: [...new Set(held)], projects, clearance: weighted(rng, [['internal', 0.3], ['confidential', 0.5], ['restricted', 0.2]]), active: true };
      const agent: Actor = { id: `a${i}`, tenant, kind: 'agent', roles: [...new Set(held)], projects, clearance: rng.chance(0.7) ? 'confidential' : 'restricted', active: true };
      const grant: Grant = { id: `g${i}`, tenant, subject: user.id, agent: agent.id, actions: ['read', 'derive', 'share', 'export'], resources: ['*'], purposes: ['work'],
        notBefore: now - 60_000, expiresAt: now + 30 * 86_400_000, active: true };
      s.actors[user.id] = user; s.actors[agent.id] = agent; s.grants[grant.id] = grant;
      counts.actors! += 2; counts.grants!++;
      bindings.push({ tenant, subject: user.id, agent: agent.id, grant: grant.id });
    }
    for (let g = 0; g < scale.groups; g++) {
      // A user's agent is a member with it, so agent and user carry the same roles (as the retrieval pre-filter assumes).
      const members = Array.from({ length: Math.max(1, Math.floor(users / 20)) }, () => rng.int(users)).flatMap(i => [`u${i}`, `a${i}`]);
      s.groups[`grp${g}`] = { id: `grp${g}`, tenant, members: [...new Set(members)], roles: [role(rng.int(chains), Math.min(5, scale.roleDepth - 1))], active: true };
      counts.groups!++;
    }
    // Holding the top roles of chains 0 and 1 together is a static SoD violation (a realistic share of denials).
    s.constraints['sod0'] = { id: 'sod0', tenant, kind: 'static', roles: [role(0, 0), role(1, 0)], cardinality: 2 };
    return { tenant, bindings, docs, derived };
  };
  const tenants = Array.from({ length: scale.tenants }, (_, t) => build(`t${t}`, scale.docsPerTenant, scale.usersPerTenant, scale.dagChains));
  const lexical = build('tlex', scale.lexicalDocs, Math.min(100, scale.usersPerTenant), 0);
  return { scale, now, states, tenants, lexical, vocabulary: vocab, counts };
}
/** Chunks with the label metadata the Ingestor would compute (documents only), embedded with `embedder`. */
export async function chunks(data: DataSet, embedder: Embedder, onBatch?: (batch: IndexedChunk[]) => Promise<void>): Promise<IndexedChunk[]> {
  const out: IndexedChunk[] = [], tokens = (a: { readers: string[]; readerRoles: string[] }) => [...a.readers.map(x => `user:${x}`), ...a.readerRoles.map(x => `role:${x}`)];
  let pending: { k: Knowledge; text: string; chunkId: string; ordinal: number; label: NonNullable<ReturnType<typeof effectiveLabel>> }[] = [];
  const flush = async () => {
    const vectors = await embedder.embed(pending.map(p => p.text));
    const batch = pending.map((p, i): IndexedChunk => {
      const [own, ...ancestors] = p.label.audiences;
      return { tenant: p.k.tenant, docId: p.k.id, docVersion: p.k.version, chunkId: p.chunkId, ordinal: p.ordinal, compartment: p.label.classification,
        readTokens: own ? tokens(own) : [], requiredProjects: p.label.projects, containerTokens: ancestors.map(tokens), model: embedder.model, vector: vectors[i]! };
    });
    pending = [];
    if (onBatch) await onBatch(batch); else out.push(...batch);
  };
  for (const state of data.states.values()) {
    for (const k of Object.values(state.knowledge)) {
      if (k.kind !== 'document') continue;
      const label = effectiveLabel(state, k);
      if (!label) throw new Error(`Unlabelled synthetic document ${k.tenant}/${k.id}`);
      for (const c of defaultChunker(k.id, k.version, k.content)) {
        pending.push({ k, text: c.text, chunkId: c.id, ordinal: c.ordinal, label });
        if (pending.length >= 256) await flush();
      }
    }
  }
  if (pending.length) await flush();
  return out;
}
export function query(data: DataSet, i: number): string {
  const rng = prng(1_000_003 + i), topic = rng.int(50);
  return Array.from({ length: 3 }, () => data.vocabulary[topic * 40 + rng.int(40)]!).join(' ');
}

/**
 * Samples bindings per tenant and records, with the pure decide(), which documents
 * each may read (up to `docSample` documents examined) and which derivation chains
 * it may read in full. The authorized workloads draw from these lists, so their
 * calls are allows; the mixed workloads draw at random and are mostly denials.
 */
export function authorize(data: DataSet, bindingSample = 20, docSample = 2000): void {
  for (const t of [...data.tenants, data.lexical]) {
    const state = data.states.get(t.tenant)!, rng = prng(4242);
    const bindings = Array.from({ length: Math.min(bindingSample, t.bindings.length) }, () => rng.pick(t.bindings));
    const docs = t.docs.length > docSample ? Array.from({ length: docSample }, () => rng.pick(t.docs)) : t.docs;
    const may = (binding: Binding, resource: string) => decide(state, { binding, resource, action: 'read', purpose: 'work', now: data.now }).effect === 'allow';
    t.authorized = bindings.map(binding => ({ binding, docs: [...new Set(docs.filter(d => may(binding, d)))] })).filter(x => x.docs.length > 0);
    t.readableChains = t.bindings.slice(0, 200).flatMap(binding => t.derived.filter(chain => may(binding, chain.at(-1)!)).map(chain => ({ binding, chain })));
  }
}
