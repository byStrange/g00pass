import { readProtectedPrivateKey } from '../core';

/**
 * Per-device private key storage. Only passphrase-PROTECTED armored keys are
 * stored (readProtectedPrivateKey refuses unprotected keys); the passphrase
 * and the unlocked key never touch storage.
 */
const KEY = 'g00pass.device-key.v1';

export interface StoredKeyInfo {
  fingerprint: string;
  userIds: string[];
}

export async function saveDeviceKey(armored: string): Promise<StoredKeyInfo> {
  const key = await readProtectedPrivateKey(armored);
  localStorage.setItem(KEY, key.armor());
  return { fingerprint: key.getFingerprint().toUpperCase(), userIds: key.getUserIDs() };
}

export function loadDeviceKeyArmored(): string | null {
  return localStorage.getItem(KEY);
}

export async function deviceKeyInfo(): Promise<StoredKeyInfo | null> {
  const a = loadDeviceKeyArmored();
  if (!a) return null;
  const key = await readProtectedPrivateKey(a);
  return { fingerprint: key.getFingerprint().toUpperCase(), userIds: key.getUserIDs() };
}

export function forgetDeviceKey(): void {
  localStorage.removeItem(KEY);
}
