/** Public core API. Feature code should import from here. */
export * from './errors';
export * from './paths';
export * from './gpgid';
export * from './store';
export * from './keys';
export * from './trust';
export { encryptToVerified, installEncryptGuard, isEncryptGuardInstalled } from './crypto/encrypt';
export { decryptEntry, unlockPrivateKey, readProtectedPrivateKey, KeyUnlockError, wipe } from './crypto/decrypt';
export * from './entries';
export * from './reencrypt';
export * from './token';
export * from './github/client';
export { GitHubSnapshot, getBranchHead, base64ToBytes, bytesToBase64 } from './github/snapshot';
export { commitChanges, GitHubWriter, withConflictRetry, type CommitOptions } from './github/commit';
// Phase 1 trust (Agent C): pinned anchors, .gpg-id signatures, folder admins.
export * from './canonical';
export * from './signatures';
export * from './trust-env';
export * from './anchors';
export * from './admins';
export * from './trust-policy';
export * from './boundaries';
export { GitHubFileHistory, type FileHistory, type FileVersion } from './github/history';
export * from './requests/keygen';
export {
  buildAccessRequest,
  groupFingerprint,
  REQUEST_LABEL,
  REQUEST_ROLES,
  RequestBuildError,
  type AccessRequestInput,
  type BuiltAccessRequest,
  type RequestRole,
} from './requests/build';
export * from './requests/submit';
export * from './github/issues';
export * from './requests/parse';
export { idMatchesFingerprint, isFolderRecipient, readRecipientLines } from './access/folders';
export * from './access/recipients';
export * from './access/approve';
export * from './access/inbox';
