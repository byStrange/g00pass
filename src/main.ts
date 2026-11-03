import './ui/styles.css';
import { getTrustHook, installEncryptGuard, isTrustHookLocked, lockTrustHook, setTrustHook, signatureTrustHook } from './core';
import { mountApp } from './ui/app';

// Trust policy: .gpg-id signatures + pinned anchors + folder admins
// (docs/specs/gpg-id-signatures.md). Locking also freezes the trust
// environment (storage, store identity, history, clock).
setTrustHook(signatureTrustHook);
lockTrustHook();
installEncryptGuard();
// Fail closed if the trust policy is not the locked signature hook. The
// message is also the marker scripts/check-dist.mjs looks for in the bundle.
if (!isTrustHookLocked() || getTrustHook() !== signatureTrustHook) throw new Error('g00pass: trust policy is not locked');

mountApp(document.getElementById('app') as HTMLElement);

if ('serviceWorker' in navigator && import.meta.env.PROD) {
  void navigator.serviceWorker.register('./sw.js', { scope: './' });
}
