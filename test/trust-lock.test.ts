import { describe, expect, it } from 'vitest';
import { MemoryTrustStorage, TrustError, getTrustHook, lockTrustHook, passThroughTrustHook, resetTrustEnvironment, setTrustEnvironment, setTrustHook } from '../src/core';

// Own file: vitest isolates modules per test file, so the lock does not leak.
describe('lockTrustHook', () => {
  it('prevents replacing the installed policy after start-up', () => {
    const strict = { name: 'strict', verify: async () => ({ ok: false as const, code: 'untrusted' as const, reason: 'x' }) };
    setTrustHook(strict);
    lockTrustHook();
    expect(() => setTrustHook(passThroughTrustHook)).toThrow(TrustError);
    expect(getTrustHook()).toBe(strict);
    // the trust environment (anchor storage, store identity, clock) is frozen too
    expect(() => setTrustEnvironment({ storage: new MemoryTrustStorage() })).toThrow(TrustError);
    expect(() => setTrustEnvironment({ now: () => new Date(0) })).toThrow(TrustError);
    expect(() => resetTrustEnvironment()).toThrow(TrustError);
  });
});
