import type { Binding } from './types.ts';
import { validActorChain } from './audit.ts';

/**
 * Delegation evidence (0.6, R143..R146). A trusted authenticator (adapters/jwt.ts)
 * that verified an RFC 8693 actor chain attaches it to the binding object it
 * returns; the engine records it with every audited decision of that binding.
 * Only in-process code can attach a chain: nothing a caller sends over HTTP
 * reaches this registry. The chain is evidence, never authority: the binding and
 * its grant decide.
 */
const chains = new WeakMap<object, readonly string[]>();
/** Attaches a verified chain (current actor first). A malformed chain is refused (throws). */
export function attachActorChain<T extends Binding>(binding: T, chain: readonly string[]): T {
  if (!validActorChain(chain)) throw new Error('Invalid actor chain');
  chains.set(binding, Object.freeze([...chain]));
  return binding;
}
/** The chain attached to this binding object, if any (a copy). */
export function actorChainOf(binding: Binding): string[] | undefined {
  const chain = binding && typeof binding === 'object' ? chains.get(binding) : undefined;
  return chain ? [...chain] : undefined;
}
