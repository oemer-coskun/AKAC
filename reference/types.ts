export const ACTIONS = ['read', 'derive', 'write_memory', 'share', 'export', 'declassify'] as const;
export type Action = typeof ACTIONS[number];
export const LEVELS = ['public', 'internal', 'confidential', 'restricted'] as const;
export type Level = typeof LEVELS[number];
export type Ref = { id: string; version: number };
export type Actor = {
  id: string; tenant: string; kind: 'user' | 'agent' | 'service';
  roles: string[]; projects: string[]; clearance: Level; active: boolean;
};
export type Grant = {
  id: string; tenant: string; subject: string; agent: string;
  actions: Action[]; resources: string[]; purposes: string[];
  notBefore: number; expiresAt: number; active: boolean; parent?: string;
};
export type Knowledge = {
  id: string; tenant: string; version: number;
  kind: 'document' | 'memory' | 'artifact'; content: string;
  classification: Level; projects: string[]; readerRoles: string[];
  readers: string[]; sources: Ref[]; active: boolean;
  accessExpiresAt?: number;
};
export type Binding = { tenant: string; subject: string; agent: string; grant: string };
export type Context = Binding & {
  id: string; purpose: string; sources: Ref[]; expiresAt: number;
  policyVersion: string; epoch: number; active: boolean;
};
export type Audit = {
  sequence: number; time: number; tenant: string; actor: string;
  operation: string; decision: 'allow' | 'deny'; reason: string;
  policyVersion: string; epoch: number; previous: string; hash: string;
};
export type State = {
  schema: 'akac-state/0.1'; policyVersion: string; epoch: number;
  actors: Record<string, Actor>; grants: Record<string, Grant>;
  knowledge: Record<string, Knowledge>; contexts: Record<string, Context>;
  audits: Audit[];
};
export type Decision = { effect: 'allow' | 'deny'; code: string };
export type PolicyInput = {
  binding: Binding; action: Action; resource: string; purpose: string; now: number;
};
export interface Store {
  transaction<T>(fn: (state: State) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}
export interface PolicyHook {
  readonly revision: string;
  ready?(): Promise<boolean>;
  check(input: { action: Action; tenant: string; classification: Level; purpose: string }): Promise<boolean>;
}
export function emptyState(): State {
  return { schema: 'akac-state/0.1', policyVersion: 'akac-reference/0.2.0', epoch: 0,
    actors: {}, grants: {}, knowledge: {}, contexts: {}, audits: [] };
}
