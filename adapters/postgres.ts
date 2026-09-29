import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import pg from 'pg';
import type { Audit, HolderQuery, KnowledgeMeta, Need, State, Store, Tx } from '../reference/types.ts';
import { emptyState, upgradeState } from '../reference/types.ts';
import { auditLeaf, verifyAudit } from '../reference/audit.ts';
import { Frontier, keyOf, rootKeys } from '../reference/merkle.ts';
import type { NodeKey } from '../reference/merkle.ts';
import { validId } from '../reference/validation.ts';
import { BudgetExceeded } from '../reference/hydrate.ts';
import { LIFECYCLE } from '../reference/lifecycle.ts';
import { LIMITS } from '../reference/policy.ts';
import { RUNTIME_PROFILE_LIMIT } from '../reference/types.ts';

type Kind = 'text' | 'int' | 'bool' | 'list' | 'json';
type Column = [column: string, field: string, kind: Kind, optional?: true];
type Collection = 'actors' | 'roles' | 'groups' | 'constraints' | 'containers' | 'knowledge' | 'grants' | 'contexts' | 'destinations' | 'runtimeProfiles';
const common: Column[] = [['id', 'id', 'text'], ['tenant', 'tenant', 'text']];
/** Real columns for identifiers, tenant, lifecycle, versions, parents, labels and expiry. JSONB only for source references. */
const TABLES: Record<Collection, { table: string; columns: Column[] }> = {
  actors: { table: 'akac_actors', columns: [...common, ['kind', 'kind', 'text'], ['roles', 'roles', 'list'], ['projects', 'projects', 'list'],
    ['clearance', 'clearance', 'text'], ['active', 'active', 'bool'],
    // Destination profile reference (migration 006, ADR-008).
    ['destination', 'destination', 'text', true]] },
  roles: { table: 'akac_roles', columns: [...common, ['inherits', 'inherits', 'list'], ['active', 'active', 'bool']] },
  groups: { table: 'akac_groups', columns: [...common, ['members', 'members', 'list'], ['roles', 'roles', 'list'], ['active', 'active', 'bool']] },
  constraints: { table: 'akac_constraints', columns: [...common, ['kind', 'kind', 'text'], ['roles', 'roles', 'list'], ['cardinality', 'cardinality', 'int']] },
  containers: { table: 'akac_containers', columns: [...common, ['kind', 'kind', 'text'], ['parent', 'parent', 'text', true],
    ['classification', 'classification', 'text'], ['reader_roles', 'readerRoles', 'list'], ['readers', 'readers', 'list'],
    ['projects', 'projects', 'list'], ['active', 'active', 'bool']] },
  knowledge: { table: 'akac_knowledge', columns: [...common, ['version', 'version', 'int'], ['kind', 'kind', 'text'], ['origin', 'origin', 'text'],
    ['content', 'content', 'text'], ['classification', 'classification', 'text'], ['projects', 'projects', 'list'],
    ['reader_roles', 'readerRoles', 'list'], ['readers', 'readers', 'list'], ['sources', 'sources', 'json'], ['active', 'active', 'bool'],
    ['access_expires_at', 'accessExpiresAt', 'int', true], ['container', 'container', 'text', true],
    // Lifecycle (migration 005, ADR-007).
    ['lifecycle', 'lifecycle', 'text', true], ['lifecycle_at', 'lifecycleAt', 'int', true], ['quarantine_reason', 'quarantineReason', 'text', true],
    ['retain_until', 'retainUntil', 'int', true], ['legal_holds', 'legalHolds', 'list', true], ['revoked_at', 'revokedAt', 'int', true]] },
  grants: { table: 'akac_grants', columns: [...common, ['subject', 'subject', 'text'], ['agent', 'agent', 'text'], ['actions', 'actions', 'list'],
    ['resources', 'resources', 'list'], ['purposes', 'purposes', 'list'], ['not_before', 'notBefore', 'int'], ['expires_at', 'expiresAt', 'int'],
    ['active', 'active', 'bool'], ['parent', 'parent', 'text', true], ['active_roles', 'activeRoles', 'list', true],
    // Run destinations and result limit (migration 006, ADR-008).
    ['destinations', 'destinations', 'list', true], ['max_results', 'maxResults', 'int', true]] },
  contexts: { table: 'akac_contexts', columns: [...common, ['subject', 'subject', 'text'], ['agent', 'agent', 'text'], ['grant_id', 'grant', 'text'],
    ['purpose', 'purpose', 'text'], ['sources', 'sources', 'json'], ['expires_at', 'expiresAt', 'int'], ['policy_version', 'policyVersion', 'text'],
    ['epoch', 'epoch', 'int'], ['active', 'active', 'bool']] },
  // Destination profiles (migration 006, ADR-008).
  destinations: { table: 'akac_destinations', columns: [...common, ['class', 'class', 'text'], ['max_classification', 'maxClassification', 'text'],
    ['purposes', 'purposes', 'list'], ['active', 'active', 'bool']] },
  // Runtime profile policies (migration 008, ADR-012). One real column per domain; `profiles.x` maps to record.profiles.x.
  runtimeProfiles: { table: 'akac_runtime_profiles', columns: [...common, ['classification', 'classification', 'text'],
    ['destination_class', 'destinationClass', 'text', true], ['profile_network', 'profiles.network', 'text', true],
    ['profile_filesystem', 'profiles.filesystem', 'text', true], ['profile_tool', 'profiles.tool', 'text', true],
    ['profile_credential', 'profiles.credential', 'text', true], ['active', 'active', 'bool']] }
};
const AUDIT: (keyof Audit)[] = ['tenant', 'sequence', 'time', 'actor', 'operation', 'decision', 'reason', 'policyVersion', 'epoch', 'previous', 'hash',
  'formatVersion', 'decisionId', 'reasonCode', 'policyDigest', 'obligations', 'runId', 'traceId',
  // Evidence correlation (migration 008, ADR-012).
  'executionId', 'runtimeRevision'];
const AUDIT_COLUMNS = AUDIT.map(f => f.replace(/[A-Z]/g, c => `_${c.toLowerCase()}`));
/** Format 2 evidence columns (migration 004); NULL for format 1 entries, which then omit the field. */
const OPTIONAL_AUDIT = new Set<keyof Audit>(['formatVersion', 'decisionId', 'reasonCode', 'policyDigest', 'obligations', 'runId', 'traceId', 'executionId', 'runtimeRevision']);
/**
 * Per-load bounds. A load never truncates: when a request or its closure exceeds
 * the bound, the load throws BudgetExceeded and the caller denies (deferred).
 * Grant and container ancestry are additionally depth-bounded (33); a deeper
 * chain stays incomplete, which the decision treats as a missing record (deny).
 */
export const BOUNDS = { contexts: 512, memberships: 256, constraints: 1024, roles: 512, grants: 64, knowledge: 1100, containers: 256,
  principals: 2048, groups: 1024, runtimeProfiles: RUNTIME_PROFILE_LIMIT } as const;

/** `a.b` addresses member b of the object member a (created, possibly empty, for every loaded row). */
const nested = (field: string) => { const dot = field.indexOf('.'); return dot < 0 ? null : [field.slice(0, dot), field.slice(dot + 1)] as const; };
function fromRow(columns: Column[], row: Record<string, unknown>): Record<string, unknown> {
  const record: Record<string, unknown> = {};
  for (const [column, field, kind] of columns) {
    const value = row[column], path = nested(field);
    const target = path ? (record[path[0]] ??= {}) as Record<string, unknown> : record;
    if (value === null || value === undefined) continue;
    target[path ? path[1] : field] = kind === 'int' ? Number(value) : value;
  }
  return record;
}
function toParams(columns: Column[], record: Record<string, unknown>): unknown[] {
  return columns.map(([, field, kind, optional]) => {
    const path = nested(field), parent = path ? record[path[0]] : undefined;
    const value = path ? (parent && typeof parent === 'object' ? (parent as Record<string, unknown>)[path[1]] : undefined) : record[field];
    if (value === undefined && optional) return null;
    if (value === undefined) throw new Error(`Missing ${field}`);
    return kind === 'json' ? JSON.stringify(value) : value;
  });
}
function upsertSql(table: string, columns: Column[]): string {
  const names = columns.map(c => c[0]);
  // Keys are (tenant, id) (migration 003): the same id in another tenant is another row,
  // and an update can never move a row to another tenant.
  return `INSERT INTO ${table} (${names.join(',')}) VALUES (${names.map((_, i) => `$${i + 1}`).join(',')}) ON CONFLICT (tenant, id) DO UPDATE SET `
    + names.filter(n => n !== 'id' && n !== 'tenant').map(n => `${n}=EXCLUDED.${n}`).join(',');
}
const fromAudit = (row: Record<string, unknown>): Audit => Object.fromEntries(AUDIT.flatMap((f, i) => {
  const value = row[AUDIT_COLUMNS[i]!];
  if (OPTIONAL_AUDIT.has(f) && (value === null || value === undefined)) return [];
  return [[f, ['sequence', 'time', 'epoch', 'formatVersion'].includes(f) ? Number(value) : value]];
})) as Audit;

async function upsert(client: pg.PoolClient | pg.Client, collection: Collection, record: Record<string, unknown>) {
  const { table, columns } = TABLES[collection];
  await client.query(upsertSql(table, columns), toParams(columns, record));
}
/**
 * Appends entries and the Merkle nodes they complete (leaf plus O(log n) parents
 * each, from the loaded frontier). Entries must continue the tree without gaps.
 */
async function appendAudits(client: pg.PoolClient | pg.Client, tenant: string, entries: Audit[], frontier: Frontier) {
  if (!entries.length) return;
  const nodes: (NodeKey & { hash: string })[] = [];
  for (const entry of entries) {
    if (entry.tenant !== tenant) throw new Error('Cross-tenant audit write');
    if (entry.sequence !== frontier.size + 1) throw new Error('Audit tree out of step with the stream');
    await client.query(`INSERT INTO akac_audit (${AUDIT_COLUMNS.join(',')}) VALUES (${AUDIT.map((_, i) => `$${i + 1}`).join(',')})`,
      AUDIT.map(f => f === 'obligations' ? (entry.obligations === undefined ? null : JSON.stringify(entry.obligations)) : entry[f] ?? null));
    nodes.push(...frontier.append(auditLeaf(entry)));
  }
  await client.query('INSERT INTO akac_audit_node (tenant, level, idx, hash) SELECT $1, * FROM unnest($2::smallint[], $3::bigint[], $4::text[])',
    [tenant, nodes.map(n => n.level), nodes.map(n => n.index), nodes.map(n => n.hash)]);
  const last = entries.at(-1)!;
  await client.query('INSERT INTO akac_audit_head (tenant, sequence, hash) VALUES ($1,$2,$3) ON CONFLICT (tenant) DO UPDATE SET sequence=EXCLUDED.sequence, hash=EXCLUDED.hash',
    [tenant, last.sequence, last.hash]);
}
/** Perfect-subtree hashes by key, in one query; throws when any is missing. */
async function readNodes(client: pg.PoolClient | pg.Client, tenant: string, keys: NodeKey[]): Promise<string[]> {
  if (!keys.length) return [];
  const rows = (await client.query('SELECT level, idx, hash FROM akac_audit_node WHERE tenant=$1 AND (level, idx) IN (SELECT * FROM unnest($2::smallint[], $3::bigint[]))',
    [tenant, keys.map(k => k.level), keys.map(k => k.index)])).rows;
  const found = new Map(rows.map(r => [`${r.level}:${r.idx}`, r.hash as string]));
  return keys.map(k => { const h = found.get(keyOf(k)); if (!h) throw new Error('Audit tree node missing'); return h; });
}

/**
 * Partial per-tenant snapshot. Keeps the serialized form of every loaded row and
 * flushes only new or changed rows at commit. Records are never deleted.
 */
class PgTx implements Tx {
  readonly state: State;
  readonly complete = false;
  private client: pg.PoolClient;
  private tenant: string;
  private loaded = new Map<Collection, Map<string, string>>();
  private flags = new Set<string>();
  private epoch?: number;
  private head = 0;
  private frontier?: Frontier;
  /** Every group of the tenant is loaded (principals); membership queries are then redundant. */
  private allGroups = false;
  constructor(client: pg.PoolClient, tenant: string, policyVersion: string) {
    this.client = client; this.tenant = tenant;
    this.state = { ...emptyState(), policyVersion };
    for (const collection of Object.keys(TABLES) as Collection[]) this.loaded.set(collection, new Map());
  }
  /** Rows beyond `bound` abort. A row with a NULL id is a closure name without a record (LEFT JOIN) and counts toward the bound. */
  private async rows(collection: Collection, sql: string, params: unknown[], bound?: number) {
    const result = await this.client.query(sql, [this.tenant, ...params]);
    if (bound !== undefined && result.rows.length > bound) throw new BudgetExceeded(`${collection} load`);
    const target = (this.state[collection] ??= {}) as Record<string, unknown>, seen = this.loaded.get(collection)!;
    for (const row of result.rows) {
      if (row.id === null || row.id === undefined) continue;
      const record = fromRow(TABLES[collection].columns, row);
      const id = record.id as string;
      // Never overwrite a record this transaction already holds (it may be modified).
      if (Object.hasOwn(target, id)) continue;
      target[id] = record; seen.set(id, JSON.stringify(record));
    }
  }
  private once(flag: string) { if (this.flags.has(flag)) return false; this.flags.add(flag); return true; }
  async load(need: Need): Promise<void> {
    const ids = (x?: string[]) => [...new Set((x ?? []).filter(validId))];
    /** Requested ids beyond the bound abort before any query. */
    const bounded = (x: string[] | undefined, bound: number, what: string) => {
      const list = ids(x); if (list.length > bound) throw new BudgetExceeded(`${what} load`); return list;
    };
    if (need.epoch && this.once('epoch')) {
      const row = (await this.client.query('SELECT epoch FROM akac_epochs WHERE tenant=$1', [this.tenant])).rows[0];
      if (row) { this.epoch = Number(row.epoch); this.state.epochs[this.tenant] = this.epoch; }
    }
    if (need.audit && this.once('audit')) {
      const row = (await this.client.query('SELECT a.* FROM akac_audit_head h JOIN akac_audit a ON a.tenant=h.tenant AND a.sequence=h.sequence WHERE h.tenant=$1', [this.tenant])).rows[0];
      if (row) { const head = fromAudit(row); this.head = head.sequence; this.state.audits.push(head); }
      // The Merkle frontier of the stream (at most one node per level) continues the tree at commit.
      const keys = rootKeys(this.head), hashes = await readNodes(this.client, this.tenant, keys);
      this.frontier = new Frontier(this.head, new Map(keys.map((k, i) => [k.level, hashes[i]!])));
    }
    if (need.constraints && this.once('constraints')) {
      await this.rows('constraints', 'SELECT * FROM akac_constraints WHERE tenant=$1 ORDER BY id LIMIT $2', [BOUNDS.constraints + 1], BOUNDS.constraints);
    }
    if (need.principals && this.once('principals')) {
      await this.rows('actors', 'SELECT * FROM akac_actors WHERE tenant=$1 AND active ORDER BY id LIMIT $2', [BOUNDS.principals + 1], BOUNDS.principals);
      await this.rows('groups', 'SELECT * FROM akac_groups WHERE tenant=$1 ORDER BY id LIMIT $2', [BOUNDS.groups + 1], BOUNDS.groups);
      this.allGroups = true;
    }
    if (need.actors?.length) await this.rows('actors', 'SELECT * FROM akac_actors WHERE tenant=$1 AND id = ANY($2::text[])', [ids(need.actors)]);
    if (need.memberships?.length && !this.allGroups) {
      await this.rows('groups', 'SELECT * FROM akac_groups WHERE tenant=$1 AND members && $2::text[] ORDER BY id LIMIT $3',
        [ids(need.memberships), BOUNDS.memberships + 1], BOUNDS.memberships);
    }
    if (need.groups?.length) await this.rows('groups', 'SELECT * FROM akac_groups WHERE tenant=$1 AND id = ANY($2::text[])', [ids(need.groups)]);
    // Closures return one row per NAME (LEFT JOIN), so a name without a record counts
    // toward the bound: a truncated role closure could otherwise leave an inactive
    // role unloaded, and an unloaded role name reads as a flat, active role (R22).
    if (need.roles?.length) {
      // Inactive roles are loaded (so they are not mistaken for flat roles) but not expanded.
      await this.rows('roles', `WITH RECURSIVE r(id) AS (SELECT unnest($2::text[]) UNION SELECT unnest(x.inherits) FROM r JOIN akac_roles x ON x.id=r.id AND x.tenant=$1 AND x.active),
        n AS (SELECT id FROM r LIMIT $3)
        SELECT n.id AS akac_name, x.* FROM n LEFT JOIN akac_roles x ON x.tenant=$1 AND x.id=n.id`, [bounded(need.roles, BOUNDS.roles, 'roles'), BOUNDS.roles + 1], BOUNDS.roles);
    }
    if (need.grants?.length) {
      await this.rows('grants', `WITH RECURSIVE g(id, depth) AS (SELECT unnest($2::text[]), 0 UNION SELECT x.parent, g.depth + 1 FROM g JOIN akac_grants x ON x.id=g.id AND x.tenant=$1 WHERE x.parent IS NOT NULL AND g.depth < 33),
        n AS (SELECT DISTINCT id FROM g LIMIT $3)
        SELECT n.id AS akac_name, x.* FROM n LEFT JOIN akac_grants x ON x.tenant=$1 AND x.id=n.id`, [bounded(need.grants, BOUNDS.grants, 'grants'), BOUNDS.grants + 1], BOUNDS.grants);
    }
    if (need.knowledge?.length) {
      await this.rows('knowledge', `WITH RECURSIVE k(id) AS (SELECT unnest($2::text[]) UNION SELECT s->>'id' FROM k JOIN akac_knowledge x ON x.id=k.id AND x.tenant=$1 CROSS JOIN LATERAL jsonb_array_elements(x.sources) s),
        n AS (SELECT id FROM k WHERE id IS NOT NULL LIMIT $3)
        SELECT n.id AS akac_name, x.* FROM n LEFT JOIN akac_knowledge x ON x.tenant=$1 AND x.id=n.id`, [bounded(need.knowledge, BOUNDS.knowledge, 'knowledge'), BOUNDS.knowledge + 1], BOUNDS.knowledge);
    }
    if (need.containers?.length) {
      await this.rows('containers', `WITH RECURSIVE c(id, depth) AS (SELECT unnest($2::text[]), 0 UNION SELECT x.parent, c.depth + 1 FROM c JOIN akac_containers x ON x.id=c.id AND x.tenant=$1 WHERE x.parent IS NOT NULL AND c.depth < 33),
        n AS (SELECT DISTINCT id FROM c LIMIT $3)
        SELECT n.id AS akac_name, x.* FROM n LEFT JOIN akac_containers x ON x.tenant=$1 AND x.id=n.id`, [bounded(need.containers, BOUNDS.containers, 'containers'), BOUNDS.containers + 1], BOUNDS.containers);
    }
    if (need.runtimeProfiles && this.once('runtimeProfiles')) {
      await this.rows('runtimeProfiles', 'SELECT * FROM akac_runtime_profiles WHERE tenant=$1 ORDER BY id LIMIT $2', [BOUNDS.runtimeProfiles + 1], BOUNDS.runtimeProfiles);
    }
    if (need.destinations?.length) await this.rows('destinations', 'SELECT * FROM akac_destinations WHERE tenant=$1 AND id = ANY($2::text[])', [ids(need.destinations)]);
    if (need.contexts?.length) await this.rows('contexts', 'SELECT * FROM akac_contexts WHERE tenant=$1 AND id = ANY($2::text[])', [ids(need.contexts)]);
    const bindings = (need.bindings ?? []).filter(b => b.tenant === this.tenant);
    if (bindings.length) {
      // A run manifest MUST be complete; overflow aborts rather than omitting prior reads.
      await this.rows('contexts', `SELECT c.* FROM akac_contexts c JOIN unnest($2::text[], $3::text[], $4::text[]) AS b(subject, agent, grant_id)
        ON c.subject=b.subject AND c.agent=b.agent AND c.grant_id=b.grant_id WHERE c.tenant=$1 LIMIT $5`,
        [bindings.map(b => b.subject), bindings.map(b => b.agent), bindings.map(b => b.grant), BOUNDS.contexts + 1], BOUNDS.contexts);
    }
    if (need.corpus) {
      // Measure before transferring: an over-budget corpus is never loaded.
      if (need.corpusBytes !== undefined) {
        const bytes = (await this.client.query('SELECT COALESCE(sum(octet_length(content)), 0)::bigint AS n FROM (SELECT content FROM akac_knowledge WHERE tenant=$1 ORDER BY id LIMIT $2) c',
          [this.tenant, need.corpus])).rows[0].n;
        if (Number(bytes) > need.corpusBytes) throw new BudgetExceeded('retrieval content');
      }
      await this.rows('knowledge', 'SELECT * FROM akac_knowledge WHERE tenant=$1 ORDER BY id LIMIT $2', [need.corpus]);
    }
  }
  /**
   * Reverse provenance traversal in SQL: a recursive CTE over `sources @> [{"id": x}]`
   * (GIN jsonb_path_ops index, migration 005), depth-bounded by LIMITS.path and
   * row-bounded by LIFECYCLE.rows. No content is read.
   */
  async descendants(roots: string[], limit: number): Promise<{ records: KnowledgeMeta[]; truncated: boolean }> {
    const columns = TABLES.knowledge.columns.filter(c => c[0] !== 'content');
    const rows = (await this.client.query(`WITH RECURSIVE d(id, depth) AS (
        SELECT unnest($2::text[]), 0
        UNION
        SELECT x.id, d.depth + 1 FROM d JOIN akac_knowledge x ON x.tenant=$1 AND x.sources @> jsonb_build_array(jsonb_build_object('id', d.id))
        WHERE d.depth < $3
      ),
      v AS (SELECT id, depth FROM d LIMIT $4),
      n AS (SELECT DISTINCT id FROM v WHERE NOT (id = ANY($2::text[])))
      SELECT (SELECT count(*) FROM v)::int AS visited, (SELECT max(depth) FROM v)::int AS deepest, ${columns.map(c => `x.${c[0]}`).join(',')}
      FROM n JOIN akac_knowledge x ON x.tenant=$1 AND x.id=n.id ORDER BY x.id LIMIT $5`,
      [this.tenant, roots, LIMITS.path, LIFECYCLE.rows + 1, limit + 1])).rows;
    const visited = rows.length ? Number(rows[0].visited) : 0, deepest = rows.length ? Number(rows[0].deepest) : 0;
    return { records: rows.slice(0, limit).map(row => fromRow(columns, row) as KnowledgeMeta),
      truncated: rows.length > limit || visited > LIFECYCLE.rows || deepest >= LIMITS.path };
  }
  async retentionDue(now: number, after: string, limit: number): Promise<string[]> {
    return (await this.client.query(`SELECT id FROM akac_knowledge WHERE tenant=$1 AND retain_until IS NOT NULL AND retain_until <= $2
      AND lifecycle IS DISTINCT FROM 'erased' AND COALESCE(cardinality(legal_holds), 0) = 0 AND id > $3 ORDER BY id LIMIT $4`,
      [this.tenant, now, after, limit])).rows.map(r => r.id as string);
  }
  async catalog(limit: number): Promise<KnowledgeMeta[]> {
    const columns = TABLES.knowledge.columns.filter(c => c[0] !== 'content');
    const result = await this.client.query(`SELECT ${columns.map(c => c[0]).join(',')} FROM akac_knowledge WHERE tenant=$1 AND kind='document' ORDER BY id LIMIT $2`, [this.tenant, limit]);
    return result.rows.map(row => fromRow(columns, row) as KnowledgeMeta);
  }
  /**
   * Holder count in SQL (recursive closure over the role hierarchy and active
   * groups; semantics of policy `effectiveRoles`: inactive role records and inactive
   * groups contribute nothing, a name without a record is a flat role). A closure
   * path beyond 16 roles (which includes a cycle) or more than 64 roles for one
   * principal cannot be established: 'unknown'.
   */
  async countSodHolders(query: HolderQuery): Promise<number | 'unknown'> {
    const constraints = query.constraints.map(c => ({ roles: [...c.roles], cardinality: c.cardinality }));
    if (!constraints.length) return 0;
    const row = (await this.client.query(`WITH RECURSIVE
      rl AS (
        SELECT id, inherits, active FROM akac_roles WHERE tenant=$1 AND ($2::jsonb IS NULL OR id <> $2->>'id')
        UNION ALL
        SELECT $2->>'id', ARRAY(SELECT jsonb_array_elements_text($2->'inherits')), ($2->>'active')::boolean WHERE $2::jsonb IS NOT NULL
      ),
      who AS (SELECT id, roles FROM akac_actors WHERE tenant=$1 AND active),
      seed AS (
        SELECT w.id AS actor, r AS role FROM who w CROSS JOIN LATERAL unnest(w.roles) r
        UNION
        SELECT w.id, r FROM who w JOIN akac_groups g ON g.tenant=$1 AND g.active AND w.id = ANY(g.members) CROSS JOIN LATERAL unnest(g.roles) r
      ),
      c(actor, role, depth) AS (
        SELECT s.actor, s.role, 1 FROM seed s LEFT JOIN rl ON rl.id=s.role WHERE rl.id IS NULL OR rl.active
        UNION
        SELECT c.actor, j.role, c.depth + 1 FROM c JOIN rl ON rl.id=c.role
          CROSS JOIN LATERAL unnest(rl.inherits) AS j(role) LEFT JOIN rl jr ON jr.id=j.role
          WHERE c.depth <= 16 AND (jr.id IS NULL OR jr.active)
      ),
      held AS (SELECT DISTINCT actor, role FROM c WHERE depth <= 16),
      k AS (SELECT t.ord, ARRAY(SELECT jsonb_array_elements_text(t.e->'roles')) AS roles, (t.e->>'cardinality')::int AS cardinality
        FROM jsonb_array_elements($3::jsonb) WITH ORDINALITY AS t(e, ord)),
      viol AS (SELECT h.actor FROM held h JOIN k ON h.role = ANY(k.roles) GROUP BY h.actor, k.ord, k.cardinality HAVING count(*) >= k.cardinality)
      SELECT (SELECT count(DISTINCT actor) FROM viol)::int AS holders,
        (EXISTS (SELECT 1 FROM c WHERE depth > 16) OR EXISTS (SELECT 1 FROM held GROUP BY actor HAVING count(*) > 64)) AS unknown`,
      [this.tenant, query.role ? JSON.stringify(query.role) : null, JSON.stringify(constraints)])).rows[0];
    return row.unknown ? 'unknown' : Number(row.holders);
  }
  async flush(): Promise<void> {
    if (this.state.schema !== 'akac-state/0.3') throw new Error('Unsupported state schema');
    for (const collection of Object.keys(TABLES) as Collection[]) {
      const seen = this.loaded.get(collection)!;
      for (const [id, record] of Object.entries((this.state[collection] ?? {}) as Record<string, Record<string, unknown>>)) {
        if (seen.get(id) === JSON.stringify(record)) continue;
        if (record.tenant !== this.tenant || record.id !== id) throw new Error('Cross-tenant write');
        await upsert(this.client, collection, record);
      }
    }
    for (const [tenant, epoch] of Object.entries(this.state.epochs)) {
      if (tenant !== this.tenant) throw new Error('Cross-tenant epoch write');
      if (epoch !== this.epoch) {
        await this.client.query('INSERT INTO akac_epochs (tenant, epoch) VALUES ($1,$2) ON CONFLICT (tenant) DO UPDATE SET epoch=EXCLUDED.epoch', [tenant, epoch]);
      }
    }
    if (this.state.audits.some(a => a.tenant !== this.tenant)) throw new Error('Cross-tenant audit write');
    const appended = this.state.audits.filter(a => a.sequence > this.head);
    if (appended.length && !this.frontier) throw new Error('Audit head not loaded');
    if (appended.length) await appendAudits(this.client, this.tenant, appended, this.frontier!);
  }
}

export const MIGRATIONS = fileURLToPath(new URL('../migrations/', import.meta.url));
const MIGRATION_LOCK = [1095450947, 3] as const;
const checksum = (sql: string) => createHash('sha256').update(sql.replace(/\r\n/g, '\n')).digest('hex');
function migrationFiles(directory: string) {
  return readdirSync(directory).filter(f => /^\d{3}_[a-z0-9_]+\.sql$/.test(f)).sort()
    .map(file => { const sql = readFileSync(join(directory, file), 'utf8'); return { version: file.slice(0, -4), sql, checksum: checksum(sql) }; });
}
export type PostgresOptions = { schema?: string };
/** Tables that hold no tenant records and therefore carry no row-level security policy. */
const UNPROTECTED = new Set(['akac_schema_migrations', 'akac_settings', 'akac_state_legacy']);
/**
 * Runtime-role posture: not a superuser, no BYPASSRLS, neither owner nor member of
 * the owner role of any akac_* table (owners are exempt from plain RLS), and every
 * tenant table has RLS enabled AND forced.
 */
async function rlsPosture(db: { query: (sql: string) => Promise<{ rows: Record<string, unknown>[] }> }): Promise<boolean> {
  const role = (await db.query('SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user')).rows[0];
  if (!role || role.rolsuper || role.rolbypassrls) return false;
  const tables = (await db.query(`SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, pg_has_role(current_user, c.relowner, 'MEMBER') AS owns
    FROM pg_class c WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind IN ('r', 'p') AND c.relname LIKE 'akac\\_%'`)).rows;
  return tables.length > 0 && tables.every(t => !t.owns && (UNPROTECTED.has(t.relname as string) || (t.relrowsecurity === true && t.relforcerowsecurity === true)));
}
function config(connectionString: string, options: PostgresOptions): pg.PoolConfig {
  if (options.schema !== undefined && !/^[a-z_][a-z0-9_]{0,62}$/.test(options.schema)) throw new Error('Invalid schema name');
  return { connectionString, connectionTimeoutMillis: 5000, statement_timeout: 10000, idle_in_transaction_session_timeout: 15000,
    ...(options.schema ? { options: `-c search_path=${options.schema}` } : {}) };
}

/**
 * Applies pending migrations in order inside one advisory-locked transaction.
 * Applied migrations are verified by checksum; an edited, missing or unknown
 * migration refuses to start. A 0.2 single-row `akac_state` is imported once and
 * renamed `akac_state_legacy` (its global audit chain stays there, unmodified).
 * Run with the schema owner, never with the runtime role.
 */
export async function migrate(connectionString: string, options: PostgresOptions & { directory?: string } = {}): Promise<string[]> {
  const files = migrationFiles(options.directory ?? MIGRATIONS);
  const client = new pg.Client(config(connectionString, options));
  await client.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1, $2)', [...MIGRATION_LOCK]);
    await client.query('CREATE TABLE IF NOT EXISTS akac_schema_migrations (version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())');
    const applied = new Map((await client.query('SELECT version, checksum FROM akac_schema_migrations')).rows.map(r => [r.version as string, r.checksum as string]));
    for (const [version, sum] of applied) {
      const file = files.find(f => f.version === version);
      if (!file) throw new Error(`Unknown applied migration ${version}`);
      if (file.checksum !== sum) throw new Error(`Migration checksum mismatch for ${version}`);
    }
    const pending = files.filter(f => !applied.has(f.version));
    for (const file of pending) {
      await client.query(file.sql);
      await client.query('INSERT INTO akac_schema_migrations (version, checksum) VALUES ($1, $2)', [file.version, file.checksum]);
    }
    if ((await client.query("SELECT to_regclass('akac_state') AS t")).rows[0].t) await importLegacy(client);
    await client.query('COMMIT');
    return pending.map(f => f.version);
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { await client.end(); }
}
async function importLegacy(client: pg.Client) {
  const row = (await client.query('SELECT body FROM akac_state WHERE id=1')).rows[0];
  if (row) {
    const state = upgradeState(row.body);
    await client.query("UPDATE akac_settings SET value=$1 WHERE key='policyVersion'", [state.policyVersion]);
    const tenants = new Set(Object.keys(state.epochs));
    for (const collection of Object.keys(TABLES) as Collection[]) for (const r of Object.values(state[collection] ?? {})) tenants.add(r.tenant);
    for (const tenant of [...tenants].sort()) {
      if (!validId(tenant)) throw new Error('Invalid legacy tenant');
      await client.query("SELECT set_config('akac.tenant', $1, true)", [tenant]);
      for (const collection of Object.keys(TABLES) as Collection[]) {
        for (const record of Object.values((state[collection] ?? {}) as Record<string, Record<string, unknown>>)) if (record.tenant === tenant) await upsert(client, collection, record);
      }
      await client.query('INSERT INTO akac_epochs (tenant, epoch) VALUES ($1,$2) ON CONFLICT (tenant) DO UPDATE SET epoch=EXCLUDED.epoch', [tenant, state.epochs[tenant] ?? 0]);
    }
    await client.query("SELECT set_config('akac.tenant', '', true)");
  }
  await client.query('ALTER TABLE akac_state RENAME TO akac_state_legacy');
}

/**
 * Normalized, tenant-partitioned store. Each transaction sets `akac.tenant`
 * (SET LOCAL semantics) for row-level security and takes a per-tenant advisory
 * lock, so one tenant's decisions are linearized while tenants run in parallel.
 */
export class PostgresStore implements Store {
  private pool: pg.Pool;
  private init: Promise<void>;
  /** Migration, then (with requireRls) the runtime-role posture check. Transactions wait for both. */
  private guard: Promise<void>;
  private requireRls: boolean;
  private expected: { version: string; checksum: string }[];
  constructor(connectionString: string, options: PostgresOptions & {
    /** true: migrate with this connection (development). A URL: migrate as that owner. false: verify only. */
    migrate?: boolean | string; requireRls?: boolean; max?: number;
  } = {}) {
    this.pool = new pg.Pool({ ...config(connectionString, options), max: options.max ?? 10 });
    this.requireRls = options.requireRls ?? false;
    this.expected = migrationFiles(MIGRATIONS).map(({ version, checksum }) => ({ version, checksum }));
    const migration = options.migrate ?? true;
    this.init = migration === false ? Promise.resolve()
      : migrate(migration === true ? connectionString : migration, { schema: options.schema }).then(() => {});
    this.guard = this.init.then(() => this.requireRls ? this.checkRuntimeRole() : undefined);
    // Observe early rejection without hiding it from transaction()/close().
    void this.init.catch(() => {}); void this.guard.catch(() => {});
  }
  private async checkRuntimeRole(): Promise<void> {
    if (!await rlsPosture(this.pool)) throw new Error('The PostgreSQL runtime role is a superuser, bypasses row-level security, owns the tables, or a table lacks forced row-level security');
  }
  /** Resolves when migrations are verified and, with requireRls, the runtime role is subject to RLS; rejects otherwise (start-up gate). */
  async verify(): Promise<void> { await this.guard; }
  async transaction<T>(tenant: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    if (!validId(tenant)) throw new Error('Invalid tenant');
    await this.guard;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const setup = await client.query(`SELECT set_config('akac.tenant', $1, true), pg_advisory_xact_lock(hashtextextended($1, 0)),
        (SELECT value FROM akac_settings WHERE key='policyVersion') AS policy`, [tenant]);
      const tx = new PgTx(client, tenant, setup.rows[0].policy);
      const value = await fn(tx);
      await tx.flush();
      await client.query('COMMIT'); return value;
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
    finally { client.release(); }
  }
  /** Schema version and checksums, RLS posture and a bounded audit tail (256 entries) against the head row. */
  async ready(tenant?: string): Promise<boolean> {
    try {
      await this.guard;
      const client = await this.pool.connect();
      try {
        await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
        const applied = (await client.query('SELECT version, checksum FROM akac_schema_migrations ORDER BY version')).rows;
        if (applied.length !== this.expected.length || applied.some((r, i) => r.version !== this.expected[i]!.version || r.checksum !== this.expected[i]!.checksum)) return false;
        if (this.requireRls) {
          if (!await rlsPosture(client)) return false;
        }
        if (tenant === undefined) return true;
        if (!validId(tenant)) return false;
        await client.query("SELECT set_config('akac.tenant', $1, true)", [tenant]);
        const head = (await client.query('SELECT sequence, hash FROM akac_audit_head WHERE tenant=$1', [tenant])).rows[0];
        const tail = (await client.query('SELECT * FROM akac_audit WHERE tenant=$1 ORDER BY sequence DESC LIMIT 256', [tenant])).rows.map(fromAudit).reverse();
        if (!head) return tail.length === 0;
        if (!(tail.length > 0 && verifyAudit(tail, { window: true }) && tail.at(-1)!.sequence === Number(head.sequence)
          && tail.at(-1)!.hash === head.hash && (tail[0]!.sequence > 1 || tail[0]!.previous === '0'.repeat(64)))) return false;
        // The Merkle leaves of the verified tail must match the stored nodes, and the frontier must be complete.
        const leaves = await readNodes(client, tenant, tail.map(e => ({ level: 0, index: e.sequence - 1 })));
        await readNodes(client, tenant, rootKeys(Number(head.sequence)));
        return tail.every((e, i) => auditLeaf(e) === leaves[i]);
      } finally { await client.query('ROLLBACK').catch(() => {}); client.release(); }
    } catch { return false; }
  }
  async auditLog(tenant: string, after = 0, limit = 100_000): Promise<Audit[]> {
    if (!validId(tenant)) throw new Error('Invalid tenant');
    await this.guard;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      await client.query("SELECT set_config('akac.tenant', $1, true)", [tenant]);
      return (await client.query('SELECT * FROM akac_audit WHERE tenant=$1 AND sequence > $2 ORDER BY sequence LIMIT $3', [tenant, after, limit])).rows.map(fromAudit);
    } finally { await client.query('ROLLBACK').catch(() => {}); client.release(); }
  }
  /**
   * Tree size (audit head) and stored perfect-subtree hashes in one read-only
   * snapshot. A key outside the tree or a missing node throws. Cost: one indexed
   * query for any number of keys (a proof needs O(log^2 n)).
   */
  async auditTree(tenant: string, keys: NodeKey[]): Promise<{ size: number; hashes: string[] }> {
    if (!validId(tenant)) throw new Error('Invalid tenant');
    await this.guard;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      await client.query("SELECT set_config('akac.tenant', $1, true)", [tenant]);
      const head = (await client.query('SELECT sequence FROM akac_audit_head WHERE tenant=$1', [tenant])).rows[0];
      const size = head ? Number(head.sequence) : 0;
      if (keys.some(k => !Number.isSafeInteger(k.level) || k.level < 0 || k.level > 62 || !Number.isSafeInteger(k.index) || k.index < 0
        || (k.index + 1) * 2 ** k.level > size)) throw new RangeError('Audit tree node outside the stream');
      return { size, hashes: await readNodes(client, tenant, keys) };
    } finally { await client.query('ROLLBACK').catch(() => {}); client.release(); }
  }
  async close() { try { await this.init; } finally { await this.pool.end(); } }
}
