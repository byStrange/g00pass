/** Public core API. Feature code should import from here. */
export * from './errors';
export * from './paths';
export * from './gpgid';
export * from './store';
export * from './keys';
export * from './trust';
export { encryptToVerified } from './crypto/encrypt';
export { decryptEntry, unlockPrivateKey, readProtectedPrivateKey, KeyUnlockError, wipe } from './crypto/decrypt';
export * from './entries';
export * from './reencrypt';
export * from './token';
export * from './github/client';
export { GitHubSnapshot, getBranchHead, base64ToBytes, bytesToBase64 } from './github/snapshot';
export { commitChanges, GitHubWriter, withConflictRetry, type CommitOptions } from './github/commit';
