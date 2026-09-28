export const validId = (s: unknown): s is string => typeof s === 'string'
  && /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(s)
  && !['constructor', 'prototype', '__proto__'].includes(s);
export function exactKeys(value: unknown, required: string[], optional: string[] = []): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
    && required.every(k => Object.hasOwn(value, k))
    && Object.keys(value).every(k => [...required, ...optional].includes(k));
}
export const safeText = (s: unknown, max: number): s is string => typeof s === 'string' && s.length > 0 && s.length <= max;
export const safeNumber = (n: unknown): n is number => Number.isSafeInteger(n) && Number(n) >= 0;
