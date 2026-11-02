import { describe, expect, it } from 'vitest';
import { TrustError, getTrustHook, lockTrustHook, passThroughTrustHook, setTrustHook } from '../src/core';

// Own file: vitest isolates modules per test file, so the lock does not leak.
describe('lockTrustHook', () => {
  it('prevents replacing the installed policy after start-up', () => {
    const strict = { name: 'strict', verify: async () => ({ ok: false as const, code: 'untrusted' as const, reason: 'x' }) };
    setTrustHook(strict);
    lockTrustHook();
    expect(() => setTrustHook(passThroughTrustHook)).toThrow(TrustError);
    expect(getTrustHook()).toBe(strict);
  });
});
